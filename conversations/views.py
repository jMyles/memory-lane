import json
import logging
import os
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from .models import (
    Message,
    Thought,
    ToolUse,
    ToolResult,
    Era
)

logger = logging.getLogger(__name__)


def memory_lane(request):
    """Main memory viewer/editor page."""
    return render(request, 'conversations/memory_lane.html')


def stream(request):
    """Live stream view - compact, auto-updating recent messages."""
    return render(request, 'conversations/stream.html')


def recent_messages(request):
    """Lightweight endpoint for stream - just last N messages."""
    limit = min(int(request.GET.get('limit', 100)), 500)

    messages = Message.objects.select_related('sender').order_by('-created_at')[:limit]

    messages_data = []
    for msg in messages:
        # Get the actual polymorphic instance
        msg_type = 'Message'
        tool_name = None
        is_error = False

        if hasattr(msg, 'thought'):
            msg_type = 'Thought'
        elif hasattr(msg, 'tooluse'):
            msg_type = 'ToolUse'
            tool_name = msg.tooluse.tool_name
        elif hasattr(msg, 'toolresult'):
            msg_type = 'ToolResult'
            is_error = msg.toolresult.is_error

        # Handle content - extract text from message format
        content = ''
        if msg.content:
            if isinstance(msg.content, str):
                content = msg.content[:1000]
            elif isinstance(msg.content, list):
                # Extract text from [{"text": "...", "type": "text"}] format
                texts = []
                for item in msg.content:
                    if isinstance(item, dict) and 'text' in item:
                        texts.append(item['text'])
                content = '\n'.join(texts)[:1000]
            elif isinstance(msg.content, dict):
                import json
                content = json.dumps(msg.content)[:1000]
            else:
                content = str(msg.content)[:1000]

        msg_dict = {
            'id': str(msg.id),
            'message_type': msg_type,
            'sender': msg.sender.name if msg.sender else 'unknown',
            'content': content,
            'timestamp': msg.timestamp,
            'tool_name': tool_name,
            'is_error': is_error,
            'context_heap_id': str(msg.context_heap_id) if msg.context_heap_id else None,
        }
        messages_data.append(msg_dict)

    return JsonResponse({'messages': messages_data})


def messages_since(request, message_id):
    """
    Get all messages created after the specified message_id.
    Returns messages with their heap context for proper placement.
    """
    from .models import Message, ContextHeap, Era
    from django.contrib.contenttypes.models import ContentType
    import uuid as uuid_lib

    try:
        last_msg = Message.objects.get(id=uuid_lib.UUID(message_id))
        last_msg_number = last_msg.message_number
    except Message.DoesNotExist:
        return JsonResponse({'error': 'Message not found'}, status=404)

    # Get all messages with message_number > last
    new_messages = Message.objects.filter(
        message_number__gt=last_msg_number
    ).select_related(
        'thought', 'tooluse', 'toolresult', 'sender', 'context_heap'
    ).prefetch_related('recipients').order_by('message_number')

    message_ct = ContentType.objects.get(app_label='conversations', model='message')

    messages_data = []
    for msg in new_messages:
        # Get the actual polymorphic instance
        if hasattr(msg, 'thought'):
            actual_msg = msg.thought
        elif hasattr(msg, 'tooluse'):
            actual_msg = msg.tooluse
        elif hasattr(msg, 'toolresult'):
            actual_msg = msg.toolresult
        else:
            actual_msg = msg

        msg_dict = {
            'id': str(actual_msg.id),
            'message_number': actual_msg.message_number,
            'message_type': actual_msg.__class__.__name__,
            'sender': msg.sender.name,
            'recipients': [r.name for r in msg.recipients.all()],
            'content': msg.content,
            'timestamp': msg.timestamp,
            'eth_blockheight': msg.eth_blockheight,
            'parent_id': str(msg.parent_id) if msg.parent_id else None,
            'heap_id': str(msg.context_heap.id) if msg.context_heap else None,
            'era_id': str(msg.context_heap.era.id) if msg.context_heap else None,
        }

        # Add type-specific fields
        if hasattr(msg, 'tooluse'):
            msg_dict['tool_name'] = msg.tooluse.tool_name
        elif hasattr(msg, 'toolresult'):
            msg_dict['is_error'] = msg.toolresult.is_error
            if msg.parent and hasattr(msg.parent, 'tooluse'):
                msg_dict['tool_name'] = msg.parent.tooluse.tool_name
        elif hasattr(msg, 'thought'):
            msg_dict['signature'] = msg.thought.signature

        messages_data.append(msg_dict)

    return JsonResponse({'messages': messages_data})


def heap_metadata(request):
    """Return just era and heap metadata without messages (for lazy loading).

    Every per-heap fact is gathered in a fixed number of queries per era rather
    than one query per heap.  Before this, each heap cost six queries (notes,
    compacting action, first message, message count, and two blockheight
    aggregates); with ~12,900 heaps in a single era that was ~78,000 round
    trips, and the child-heap search was O(heaps^2) on top.  Gunicorn killed
    the worker at 30s and the browser got an HTML error page to JSON.parse().
    """
    from .models import ContextHeap, Era, Note, CompactingAction, Message
    from django.contrib.contenttypes.models import ContentType
    from django.db.models import Min, Max, Count
    from collections import defaultdict
    from datetime import datetime

    eras = Era.objects.order_by('created_at')

    data = {
        'eras': [],
        'orphaned_compacting_actions': []
    }

    # Get content types for lookups
    heap_ct = ContentType.objects.get(app_label='conversations', model='contextheap')
    era_ct = ContentType.objects.get(app_label='conversations', model='era')

    # All era notes in one query, grouped by era id.
    era_notes_by_id = defaultdict(list)
    for note in Note.objects.filter(content_type=era_ct).select_related('from_entity').order_by('created_at'):
        era_notes_by_id[str(note.object_id)].append(note)

    # All heap notes in one query, grouped by heap id.
    heap_notes_by_id = defaultdict(list)
    for note in Note.objects.filter(content_type=heap_ct).select_related('from_entity').order_by('created_at'):
        heap_notes_by_id[str(note.object_id)].append(note)

    def serialize_note(note):
        return {
            'id': str(note.id),
            'from_entity': note.from_entity.name,
            'content': note.content,
            'eth_blockheight': note.eth_blockheight,
            'created_at': note.created_at.isoformat()
        }

    for era in eras:
        era_data = {
            'id': str(era.id),
            'name': era.name,
            'created_at': era.created_at.isoformat(),
            'earliest_blockheight': era.earliest_blockheight(),
            'latest_blockheight': era.latest_blockheight(),
            'context_heaps': [],
            'notes': [serialize_note(n) for n in era_notes_by_id.get(str(era.id), [])]
        }

        # One query for every per-heap aggregate: message count, blockheight
        # range, and the timestamps used for sorting.  All of these aggregate
        # over the same `messages` join, so there is no fan-out.
        all_heaps = list(
            era.context_heaps
               .select_related('compacting_action')
               .annotate(
                   msg_count=Count('messages'),
                   earliest_bh=Min('messages__eth_blockheight'),
                   latest_bh=Max('messages__eth_blockheight'),
                   first_msg_timestamp=Min('messages__timestamp'),
                   first_msg_created=Min('messages__created_at'),
               )
        )

        if not all_heaps:
            data['eras'].append(era_data)
            continue

        heap_ids = [h.id for h in all_heaps]

        # One query for the first message of every heap (Postgres DISTINCT ON).
        first_msg_by_heap = {}
        for msg in (Message.objects
                    .filter(context_heap_id__in=heap_ids)
                    .order_by('context_heap_id', 'message_number')
                    .distinct('context_heap_id')
                    .only('id', 'timestamp', 'context_heap_id')):
            first_msg_by_heap[msg.context_heap_id] = msg

        # Sort by first message timestamp, falling back to created_at
        def heap_sort_key(h):
            if h.first_msg_timestamp:
                return (0, h.first_msg_timestamp)
            elif h.first_msg_created:
                return (1, h.first_msg_created.timestamp() * 1000)
            else:
                return (2, h.created_at.timestamp() * 1000)

        all_heaps.sort(key=heap_sort_key)

        # A split heap's parent is the heap its first message belongs to.  The
        # first-message map above already answers that, so the parent lookup is
        # a dict read rather than a scan over every heap.
        children_by_parent = defaultdict(list)
        for heap in all_heaps:
            if heap.type != 'split_point':
                continue
            first_msg = first_msg_by_heap.get(heap.id)
            if first_msg and first_msg.context_heap_id != heap.id:
                children_by_parent[first_msg.context_heap_id].append(heap)

        # Build metadata for each heap (without messages)
        def serialize_heap_metadata(heap):
            # Check for compacting action (select_related above; no query here)
            compacting_action = None
            ca = getattr(heap, 'compacting_action', None)
            if ca:
                # Get ending message ID from either FK or looking_for field
                ending_msg_id = None
                if ca.ending_message_id:
                    ending_msg_id = str(ca.ending_message_id)
                elif ca.looking_for_ending_message:
                    ending_msg_id = str(ca.looking_for_ending_message)

                compacting_action = {
                    'id': str(ca.id),
                    'ending_message_id': ending_msg_id,
                    'compact_trigger': ca.compact_trigger,
                    'continuation_message_id': str(ca.continuation_message_id) if ca.continuation_message_id else None
                }

            # First message info, from the map built above
            first_message = first_msg_by_heap.get(heap.id)
            first_message_timestamp = None
            first_message_id = None
            if first_message:
                first_message_id = str(first_message.id)
                if first_message.timestamp:
                    first_message_timestamp = datetime.fromtimestamp(first_message.timestamp / 1000).isoformat()

            heap_data = {
                'id': str(heap.id),
                'type': heap.type,
                'type_display': heap.get_type_display(),
                'first_message_id': first_message_id,
                'first_message_timestamp': first_message_timestamp,
                'message_count': heap.msg_count,
                'created_at': heap.created_at.isoformat(),
                'earliest_blockheight': heap.earliest_bh,
                'latest_blockheight': heap.latest_bh,
                'child_heaps': [
                    serialize_heap_metadata(child)
                    for child in children_by_parent.get(heap.id, [])
                ],
                'compacting_action': compacting_action,
                'notes': [serialize_note(n) for n in heap_notes_by_id.get(str(heap.id), [])]
            }

            return heap_data

        # Serialize root heaps (non-split heaps)
        for heap in all_heaps:
            if heap.type != 'split_point':
                era_data['context_heaps'].append(serialize_heap_metadata(heap))

        data['eras'].append(era_data)

    # Get orphaned compacting actions (not linked to any context heap)
    from .models import RawImportedContent
    ca_ct = ContentType.objects.get(app_label='conversations', model='compactingaction')
    orphaned = list(CompactingAction.objects.filter(context_heap__isnull=True).order_by('created_at'))

    # Raw imported content for all orphans in one query
    raw_by_object_id = {
        str(rc.object_id): rc
        for rc in RawImportedContent.objects.filter(
            content_type=ca_ct,
            object_id__in=[c.id for c in orphaned]
        )
    } if orphaned else {}

    for compact in orphaned:
        raw_content = raw_by_object_id.get(str(compact.id))

        # Get ending message ID
        ending_msg_id = None
        if compact.ending_message_id:
            ending_msg_id = str(compact.ending_message_id)
        elif compact.looking_for_ending_message:
            ending_msg_id = str(compact.looking_for_ending_message)

        data['orphaned_compacting_actions'].append({
            'id': str(compact.id),
            'ending_message_id': ending_msg_id,
            'compact_trigger': compact.compact_trigger,
            'created_at': compact.created_at.isoformat(),
            'raw_imported_content': raw_content.raw_data if raw_content else None
        })

    return JsonResponse(data, safe=False)


def all_messages(request):
    """Messages grouped by Era and ContextHeap."""
    # Get all context heaps with their eras
    from .models import ContextHeap, Era, Note, CompactingAction
    from django.contrib.contenttypes.models import ContentType

    eras = Era.objects.prefetch_related(
        'context_heaps__messages__sender',
        'context_heaps__messages__recipients'
    ).order_by('created_at')

    data = {
        'eras': [],
        'orphaned_compacting_actions': []
    }

    # Get content types for lookups
    message_ct = ContentType.objects.get(app_label='conversations', model='message')
    heap_ct = ContentType.objects.get(app_label='conversations', model='contextheap')
    era_ct = ContentType.objects.get(app_label='conversations', model='era')

    for era in eras:
        # Get notes for this era
        era_notes = Note.objects.filter(
            content_type=era_ct,
            object_id=era.id
        ).order_by('created_at')

        era_data = {
            'id': str(era.id),
            'name': era.name,
            'created_at': era.created_at.isoformat(),
            'earliest_blockheight': era.earliest_blockheight(),
            'latest_blockheight': era.latest_blockheight(),
            'context_heaps': [],
            'notes': [{
                'id': str(note.id),
                'from_entity': note.from_entity.name,
                'content': note.content,
                'eth_blockheight': note.eth_blockheight,
                'created_at': note.created_at.isoformat()
            } for note in era_notes]
        }

        # Get all heaps and annotate with first message info for sorting
        from django.db.models import Prefetch, Min, F, Case, When, Value, IntegerField

        # Get all heaps with their first message's timestamp for sorting
        all_heaps = list(era.context_heaps.annotate(
            first_msg_timestamp=Min('messages__timestamp'),
            first_msg_created=Min('messages__created_at')
        ).all())

        # Sort by first message timestamp, falling back to created_at
        def heap_sort_key(h):
            if h.first_msg_timestamp:
                return (0, h.first_msg_timestamp)
            elif h.first_msg_created:
                return (1, h.first_msg_created.timestamp() * 1000)
            else:
                return (2, h.created_at.timestamp() * 1000)

        all_heaps.sort(key=heap_sort_key)

        # Now prefetch first messages for display (separate from sorting)
        first_messages_prefetch = Prefetch(
            'messages',
            queryset=Message.objects.order_by('message_number').only('id', 'timestamp', 'message_number', 'context_heap')[:1],
            to_attr='prefetched_first_message'
        )

        # Re-fetch with prefetch (Django will use cached objects)
        all_heaps_with_prefetch = list(era.context_heaps.prefetch_related(first_messages_prefetch).all())

        # Build mapping by ID to preserve sort order
        heap_by_id = {h.id: h for h in all_heaps_with_prefetch}
        all_heaps = [heap_by_id[h.id] for h in all_heaps]

        # Build cache from prefetched data
        first_message_cache = {}
        for heap in all_heaps:
            first_msg = heap.prefetched_first_message[0] if heap.prefetched_first_message else None
            first_message_cache[heap.id] = first_msg

        # Build hierarchy: find root heaps (non-split) and their children (splits)
        def serialize_heap(heap):
            # Get notes for this heap
            heap_notes = Note.objects.filter(
                content_type=heap_ct,
                object_id=heap.id
            ).order_by('created_at')

            # Check for compacting action
            compacting_action = None
            if hasattr(heap, 'compacting_action') and heap.compacting_action:
                ca = heap.compacting_action
                # Get ending message ID from either FK or looking_for field
                ending_msg_id = None
                if ca.ending_message_id:
                    ending_msg_id = str(ca.ending_message_id)
                elif ca.looking_for_ending_message:
                    ending_msg_id = str(ca.looking_for_ending_message)

                compacting_action = {
                    'id': str(ca.id),
                    'ending_message_id': ending_msg_id,
                    'compact_trigger': ca.compact_trigger,
                    'continuation_message_id': str(ca.continuation_message_id) if ca.continuation_message_id else None
                }

            # Get first message from cache
            first_message = first_message_cache.get(heap.id)
            first_message_timestamp = None
            first_message_id = None
            if first_message:
                first_message_id = str(first_message.id)
                if first_message.timestamp:
                    from datetime import datetime
                    first_message_timestamp = datetime.fromtimestamp(first_message.timestamp / 1000).isoformat()

            heap_data = {
                'id': str(heap.id),
                'type': heap.type,
                'type_display': heap.get_type_display(),
                'first_message_id': first_message_id,
                'first_message_timestamp': first_message_timestamp,
                'created_at': heap.created_at.isoformat(),
                'earliest_blockheight': heap.earliest_blockheight(),
                'latest_blockheight': heap.latest_blockheight(),
                'messages': [],
                'child_heaps': [],
                'compacting_action': compacting_action,
                'notes': [{
                    'id': str(note.id),
                    'from_entity': note.from_entity.name,
                    'content': note.content,
                    'eth_blockheight': note.eth_blockheight,
                    'created_at': note.created_at.isoformat()
                } for note in heap_notes]
            }

            # Build lookup of CompactingActions by their ending message UUID
            # This includes both linked CAs (for this heap or others) and orphaned ones
            all_compacting_actions = CompactingAction.objects.all()
            compacting_action_by_leaf_uuid = {}
            for action in all_compacting_actions:
                # Get the ending message ID from either the FK or the looking_for field
                if action.ending_message_id:
                    compacting_action_by_leaf_uuid[action.ending_message_id] = action
                elif action.looking_for_ending_message:
                    compacting_action_by_leaf_uuid[action.looking_for_ending_message] = action

            # Get messages for this heap
            messages = heap.messages.select_related('thought', 'tooluse', 'toolresult', 'sender').prefetch_related('recipients').order_by('message_number')
            for msg in messages:
                # Get the actual polymorphic instance
                if hasattr(msg, 'thought'):
                    actual_msg = msg.thought
                elif hasattr(msg, 'tooluse'):
                    actual_msg = msg.tooluse
                elif hasattr(msg, 'toolresult'):
                    actual_msg = msg.toolresult
                else:
                    actual_msg = msg

                # Get notes for this message
                msg_notes = Note.objects.filter(
                    content_type=message_ct,
                    object_id=msg.id
                ).order_by('created_at')

                msg_dict = {
                    'id': str(actual_msg.id),
                    'message_number': actual_msg.message_number,
                    'message_type': actual_msg.__class__.__name__,
                    'sender': msg.sender.name,
                    'sender_type': msg.sender.participant_type,
                    'recipients': [r.name for r in msg.recipients.all()],
                    'recipient_types': [r.participant_type for r in msg.recipients.all()],
                    'content': msg.content,  # JSONField - keep as dict/str, JsonResponse will serialize properly
                    'timestamp': msg.timestamp,
                    'eth_blockheight': msg.eth_blockheight,
                    'eth_block_offset': msg.eth_block_offset,
                    'created_at': msg.created_at.isoformat(),
                    'session_id': str(msg.session_id) if msg.session_id else None,
                    'source_file': msg.source_file,
                    'missing_from_markdown': msg.missing_from_markdown,
                    'cwd': msg.cwd,
                    'git_branch': msg.git_branch,
                    'client_version': msg.client_version,
                    'parent_id': str(msg.parent_id) if msg.parent_id else None,
                    'is_synthetic_error': msg.is_synthetic_error,
                    'is_retry': msg.is_retry,
                    'notes': [{
                        'id': str(note.id),
                        'from_entity': note.from_entity.name,
                        'content': note.content,
                        'eth_blockheight': note.eth_blockheight,
                        'created_at': note.created_at.isoformat()
                    } for note in msg_notes]
                }

                # Add type-specific fields
                if hasattr(msg, 'tooluse'):
                    msg_dict['tool_name'] = msg.tooluse.tool_name
                    msg_dict['tool_id'] = msg.tooluse.tool_id
                elif hasattr(msg, 'toolresult'):
                    msg_dict['tool_use_id'] = msg.toolresult.tool_use_id
                    msg_dict['is_error'] = msg.toolresult.is_error
                    # Look up parent ToolUse to get tool name
                    if msg.parent and hasattr(msg.parent, 'tooluse'):
                        msg_dict['tool_name'] = msg.parent.tooluse.tool_name
                elif hasattr(msg, 'thought'):
                    msg_dict['signature'] = msg.thought.signature

                heap_data['messages'].append(msg_dict)

                # Check if this message is the leaf of a CompactingAction
                if msg.id in compacting_action_by_leaf_uuid:
                    compacting_action = compacting_action_by_leaf_uuid[msg.id]

                    # Get raw imported content if it exists
                    from .models import RawImportedContent
                    ca_ct = ContentType.objects.get(app_label='conversations', model='compactingaction')
                    raw_content = RawImportedContent.objects.filter(
                        content_type=ca_ct,
                        object_id=compacting_action.id
                    ).first()

                    # Get ending message ID
                    ending_msg_id = None
                    if compacting_action.ending_message_id:
                        ending_msg_id = str(compacting_action.ending_message_id)
                    elif compacting_action.looking_for_ending_message:
                        ending_msg_id = str(compacting_action.looking_for_ending_message)

                    # Add a pseudo-message representing the compacting action
                    heap_data['messages'].append({
                        'id': str(compacting_action.id),
                        'message_type': 'CompactingAction',
                        'ending_message_id': ending_msg_id,
                        'compact_trigger': compacting_action.compact_trigger,
                        'pre_compact_tokens': compacting_action.pre_compact_tokens,
                        'is_orphaned': compacting_action.context_heap_id is None,
                        'linked_heap_id': str(compacting_action.context_heap_id) if compacting_action.context_heap_id else None,
                        'raw_imported_content': raw_content.raw_data if raw_content else None
                    })

            # Find child split heaps
            for potential_child in all_heaps:
                if potential_child.type == 'split_point':
                    parent_heap = potential_child.parent_heap()
                    if parent_heap and parent_heap.id == heap.id:
                        heap_data['child_heaps'].append(serialize_heap(potential_child))

            return heap_data

        # Serialize root heaps (non-split heaps)
        for heap in all_heaps:
            if heap.type != 'split_point':
                era_data['context_heaps'].append(serialize_heap(heap))

        data['eras'].append(era_data)

    # Get orphaned compacting actions (not linked to any context heap)
    from .models import RawImportedContent
    ca_ct = ContentType.objects.get(app_label='conversations', model='compactingaction')
    orphaned = CompactingAction.objects.filter(context_heap__isnull=True).order_by('created_at')
    for compact in orphaned:
        # Get raw imported content if it exists
        raw_content = RawImportedContent.objects.filter(
            content_type=ca_ct,
            object_id=compact.id
        ).first()

        # Get ending message ID
        ending_msg_id = None
        if compact.ending_message_id:
            ending_msg_id = str(compact.ending_message_id)
        elif compact.looking_for_ending_message:
            ending_msg_id = str(compact.looking_for_ending_message)

        data['orphaned_compacting_actions'].append({
            'id': str(compact.id),
            'ending_message_id': ending_msg_id,
            'compact_trigger': compact.compact_trigger,
            'created_at': compact.created_at.isoformat(),
            'raw_imported_content': raw_content.raw_data if raw_content else None
        })

    return JsonResponse(data, safe=False)


def api_messages(request):
    """API endpoint for fetching messages with filtering."""
    # Get filter parameters
    search = request.GET.get('search', '').lower()
    person = request.GET.get('person', '')
    show_thinking = request.GET.get('show_thinking', 'true') == 'true'
    message_types = request.GET.get('types', 'context_opening,regular,thought,tool_use,tool_result').split(',')
    limit = int(request.GET.get('limit', 100))

    # Start with all messages from base table
    messages = Message.objects.all()

    # Apply filters
    if person:
        # Filter by sender or recipients (M2M)
        messages = messages.filter(sender__name=person) | messages.filter(recipients__name=person)

    # Filter by message type
    if not show_thinking:
        # Exclude Thought messages
        messages = messages.exclude(thought__isnull=False)

    # Order by timestamp (or created_at if timestamp is null)
    messages = messages.order_by('-timestamp', '-created_at')[:limit]

    # Serialize messages with polymorphic content
    data = []
    for msg in messages.prefetch_related('recipients'):
        # Determine message type and get content
        message_type = None
        content = None
        extra = {}

        # Check which subclass this is
        if hasattr(msg, 'thought'):
            message_type = 'thought'
            content = str(msg.thought.content)
            extra['signature'] = msg.thought.signature
            extra['parent_uuid'] = str(msg.parent.id) if msg.parent else None
            extra['context_heap'] = str(msg.context_heap.id) if msg.context_heap else None
        elif hasattr(msg, 'tooluse'):
            message_type = 'tool_use'
            content = f"[Tool: {msg.tooluse.tool_name}]"
            extra['tool_name'] = msg.tooluse.tool_name
            extra['tool_id'] = msg.tooluse.tool_id
            extra['parent_uuid'] = str(msg.parent.id) if msg.parent else None
            extra['context_heap'] = str(msg.context_heap.id) if msg.context_heap else None
        elif hasattr(msg, 'toolresult'):
            message_type = 'tool_result'
            result_content = str(msg.toolresult.content)
            content = result_content[:100] + '...' if len(result_content) > 100 else result_content
            extra['is_error'] = msg.toolresult.is_error
            extra['tool_use_id'] = msg.toolresult.tool_use_id
            extra['parent_uuid'] = str(msg.parent.id) if msg.parent else None
            extra['context_heap'] = str(msg.context_heap.id) if msg.context_heap else None
        else:
            message_type = 'message'
            content = str(msg.content)
            extra['parent_uuid'] = str(msg.parent.id) if msg.parent else None
            extra['context_heap'] = str(msg.context_heap.id) if msg.context_heap else None

        # Filter by message type
        if message_type and message_type not in message_types:
            continue

        # Filter by search text
        if search and content and search not in content.lower():
            continue

        # Get recipients
        recipient_names = [r.name for r in msg.recipients.all()]

        data.append({
            'id': str(msg.id),
            'message_type': message_type,
            'sender': msg.sender.name,
            'recipients': recipient_names,
            'content': content,
            'timestamp': msg.timestamp,
            'session_id': str(msg.session_id) if msg.session_id else None,
            **extra
        })

    return JsonResponse(data, safe=False)


def heap_messages(request, heap_id):
    """Load all messages for a specific context heap."""
    from .models import ContextHeap, Note, CompactingAction
    from django.contrib.contenttypes.models import ContentType
    import uuid as uuid_lib

    try:
        heap = ContextHeap.objects.get(id=uuid_lib.UUID(heap_id))
    except ContextHeap.DoesNotExist:
        return JsonResponse({'error': 'Heap not found'}, status=404)

    # Get content types
    message_ct = ContentType.objects.get(app_label='conversations', model='message')

    # Build lookup of CompactingActions by their ending message UUID
    all_compacting_actions = CompactingAction.objects.all()
    compacting_action_by_leaf_uuid = {}
    for action in all_compacting_actions:
        # Get the ending message ID from either the FK or the looking_for field
        if action.ending_message_id:
            compacting_action_by_leaf_uuid[action.ending_message_id] = action
        elif action.looking_for_ending_message:
            compacting_action_by_leaf_uuid[action.looking_for_ending_message] = action

    # Get messages for this heap
    messages = heap.messages.select_related('thought', 'tooluse', 'toolresult', 'sender').prefetch_related('recipients').order_by('message_number')

    messages_data = []
    for msg in messages:
        # Get the actual polymorphic instance
        if hasattr(msg, 'thought'):
            actual_msg = msg.thought
        elif hasattr(msg, 'tooluse'):
            actual_msg = msg.tooluse
        elif hasattr(msg, 'toolresult'):
            actual_msg = msg.toolresult
        else:
            actual_msg = msg

        # Get notes for this message
        msg_notes = Note.objects.filter(
            content_type=message_ct,
            object_id=msg.id
        ).order_by('created_at')

        msg_dict = {
            'id': str(actual_msg.id),
            'message_number': actual_msg.message_number,
            'message_type': actual_msg.__class__.__name__,
            'sender': msg.sender.name,
            'sender_type': msg.sender.participant_type,
            'recipients': [r.name for r in msg.recipients.all()],
            'recipient_types': [r.participant_type for r in msg.recipients.all()],
            'content': msg.content,  # JSONField - keep as dict/str, JsonResponse will serialize properly
            'timestamp': msg.timestamp,
            'eth_blockheight': msg.eth_blockheight,
            'eth_block_offset': msg.eth_block_offset,
            'created_at': msg.created_at.isoformat(),
            'session_id': str(msg.session_id) if msg.session_id else None,
            'source_file': msg.source_file,
            'missing_from_markdown': msg.missing_from_markdown,
            'cwd': msg.cwd,
            'git_branch': msg.git_branch,
            'client_version': msg.client_version,
            'parent_id': str(msg.parent_id) if msg.parent_id else None,
            'is_synthetic_error': msg.is_synthetic_error,
            'is_retry': msg.is_retry,
            'notes': [{
                'id': str(note.id),
                'from_entity': note.from_entity.name,
                'content': note.content,
                'eth_blockheight': note.eth_blockheight,
                'created_at': note.created_at.isoformat()
            } for note in msg_notes]
        }

        # Add type-specific fields
        if hasattr(msg, 'tooluse'):
            msg_dict['tool_name'] = msg.tooluse.tool_name
            msg_dict['tool_id'] = msg.tooluse.tool_id
        elif hasattr(msg, 'toolresult'):
            msg_dict['tool_use_id'] = msg.toolresult.tool_use_id
            msg_dict['is_error'] = msg.toolresult.is_error
            # Look up parent ToolUse to get tool name
            if msg.parent and hasattr(msg.parent, 'tooluse'):
                msg_dict['tool_name'] = msg.parent.tooluse.tool_name
        elif hasattr(msg, 'thought'):
            msg_dict['signature'] = msg.thought.signature

        messages_data.append(msg_dict)

        # Check if this message is the leaf of a CompactingAction
        if msg.id in compacting_action_by_leaf_uuid:
            compacting_action = compacting_action_by_leaf_uuid[msg.id]

            # Get raw imported content if it exists
            from .models import RawImportedContent
            ca_ct = ContentType.objects.get(app_label='conversations', model='compactingaction')
            raw_content = RawImportedContent.objects.filter(
                content_type=ca_ct,
                object_id=compacting_action.id
            ).first()

            # Get ending message ID
            ending_msg_id = None
            if compacting_action.ending_message_id:
                ending_msg_id = str(compacting_action.ending_message_id)
            elif compacting_action.looking_for_ending_message:
                ending_msg_id = str(compacting_action.looking_for_ending_message)

            # Add a pseudo-message representing the compacting action
            messages_data.append({
                'id': str(compacting_action.id),
                'message_type': 'CompactingAction',
                'ending_message_id': ending_msg_id,
                'compact_trigger': compacting_action.compact_trigger,
                'pre_compact_tokens': compacting_action.pre_compact_tokens,
                'is_orphaned': compacting_action.context_heap_id is None,
                'linked_heap_id': str(compacting_action.context_heap_id) if compacting_action.context_heap_id else None,
                'raw_imported_content': raw_content.raw_data if raw_content else None
            })

    return JsonResponse({'messages': messages_data}, safe=False)


@csrf_exempt
@require_http_methods(["POST"])
def ingest(request):
    """
    Ingest endpoint for receiving JSONL lines from watchers.

    Requires Authorization: Bearer <INGEST_API_KEY> header if INGEST_API_KEY is set.

    Accepts POST with JSON body:
    {
        "lines": ["jsonl line 1", "jsonl line 2", ...],
        "username": "justin",  # optional, defaults to "justin"
        "era_name": "Current Working Era",  # optional
        "source": "hunter-watcher"  # optional, for logging
    }

    Or single line:
    {
        "line": "single jsonl line",
        "username": "justin"
    }

    Returns:
    {
        "imported": 5,
        "skipped": 2,
        "errors": ["error message 1", ...]
    }
    """
    from importers_and_parsers.claude_code_v2 import import_line_from_claude_code_v2
    from watcher.heap_assignment import assign_heap_to_message
    from constant_sorrow.constants import EVENT_TYPE_WE_DO_NOT_HANDLE_YET

    # Check API key if configured
    expected_key = os.environ.get('INGEST_API_KEY')
    if expected_key:
        auth_header = request.headers.get('Authorization', '')
        if auth_header != f'Bearer {expected_key}':
            return JsonResponse({'error': 'Unauthorized'}, status=401)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError as e:
        return JsonResponse({'error': f'Invalid JSON: {e}'}, status=400)

    # Get parameters
    username = data.get('username', 'justin')
    era_name = data.get('era_name', 'Current Working Era (Era N)')
    source = data.get('source', 'unknown')

    # Get lines - support both single line and batch
    lines = data.get('lines', [])
    if 'line' in data:
        lines = [data['line']]

    if not lines:
        return JsonResponse({'error': 'No lines provided'}, status=400)

    # Get or create era
    era, _ = Era.objects.get_or_create(name=era_name)

    # Optional: Apply secrets scrubbing via external scrubber service
    scrubber_url = os.environ.get('SCRUBBER_URL')
    if scrubber_url and lines:
        try:
            import requests
            response = requests.post(
                f"{scrubber_url}/scrub/batch",
                json={"texts": lines},
                timeout=10
            )
            if response.status_code == 200:
                result = response.json()
                lines = result['texts']
                if result['redacted_count'] > 0:
                    logger.info(f"Scrubber redacted secrets in {result['redacted_count']} lines")
            else:
                logger.warning(f"Scrubber returned {response.status_code}, proceeding without scrubbing")
        except Exception as e:
            logger.warning(f"Could not reach scrubber service: {e}, proceeding without scrubbing")

    # Process lines
    imported = 0
    skipped = 0
    errors = []
    current_heap = None

    for line in lines:
        try:

            # Import the line
            event, created = import_line_from_claude_code_v2(
                line, era, f"ingest-{source}", username
            )

            if event is EVENT_TYPE_WE_DO_NOT_HANDLE_YET:
                skipped += 1
                continue

            if not created:
                skipped += 1
                continue

            # Assign heap if it's a Message
            if isinstance(event, Message):
                heap = assign_heap_to_message(event, era, current_heap)
                current_heap = heap

            imported += 1

        except Exception as e:
            errors.append(str(e))
            logger.error(f"Error importing line from {source}: {e}")

    logger.info(f"Ingest from {source}: imported={imported}, skipped={skipped}, errors={len(errors)}")

    return JsonResponse({
        'imported': imported,
        'skipped': skipped,
        'errors': errors[:10]  # Limit error messages returned
    })
