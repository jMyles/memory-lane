"""
Memory service - handles querying conversation history.

All methods are synchronous Django ORM queries.
Called via sync_to_async from MCP tools.
"""

from conversations.models import Message, Era, ContextHeap
from django.db.models import Count, Max, Min, Q
import json
import random


# Opening prompts that say nothing about what a thread is *about*. Skipped
# when picking a title hint, so a background session started with
# `claude --bg 'reawaken magent'` is titled by its first real request.
_NON_TOPICAL_OPENERS = ('reawaken magent', 'reawaken')


def _text_of(content):
    """Best-effort plain text from a Message.content value.

    Content arrives in several shapes depending on importer and era: a plain
    string, a JSON-encoded string of blocks, a list of blocks, or a dict.
    Only human-readable text blocks are kept; tool calls and results are not.
    """
    if isinstance(content, str):
        stripped = content.strip()
        if stripped[:1] in ('[', '{'):
            try:
                return _text_of(json.loads(stripped))
            except ValueError:
                pass
        return content
    if isinstance(content, dict):
        return content.get('text', '') if content.get('type', 'text') == 'text' else ''
    if isinstance(content, list):
        return ' '.join(t for t in (_text_of(block) for block in content) if t)
    return ''


class MemoryService:
    """Service for querying conversation memory"""

    @staticmethod
    def get_latest_continuation():
        """Get the most recent continuation message"""
        return Message.objects.filter(
            is_continuation_message=True
        ).order_by('-created_at').first()

    @staticmethod
    def get_message_by_id(message_id):
        """Get a specific message by its UUID"""
        try:
            return Message.objects.get(id=message_id)
        except Message.DoesNotExist:
            return None

    @staticmethod
    def get_messages_before(reference_id=None, reference_timestamp=None, limit=300):
        """Get N messages before a reference point"""
        if reference_id:
            ref_msg = Message.objects.get(id=reference_id)
            messages = Message.objects.filter(
                created_at__lt=ref_msg.created_at
            ).order_by('-created_at')[:limit]
        elif reference_timestamp:
            messages = Message.objects.filter(
                created_at__lt=reference_timestamp
            ).order_by('-created_at')[:limit]
        else:
            messages = Message.objects.order_by('-created_at')[:limit]

        return list(messages)

    @staticmethod
    def get_era_summary(era_name="Compacting Meta-Conversation (Era 1)"):
        """Get messages from a specific era"""
        try:
            era = Era.objects.get(name=era_name)
            heaps = ContextHeap.objects.filter(era=era)
            messages = Message.objects.filter(
                context_heap__in=heaps
            ).order_by('message_number')[:100]
            return {
                'era': era,
                'messages': list(messages)
            }
        except Era.DoesNotExist:
            return None

    @staticmethod
    def get_context_heap(heap_id):
        """Get all messages from a specific context heap"""
        try:
            heap = ContextHeap.objects.get(id=heap_id)
            messages = Message.objects.filter(
                context_heap=heap
            ).order_by('message_number')
            return {
                'heap': heap,
                'messages': list(messages)
            }
        except ContextHeap.DoesNotExist:
            return None

    @staticmethod
    def search_messages(query, limit=50):
        """Full-text search for messages"""
        # PostgreSQL full-text search
        from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector

        search_vector = SearchVector('content')
        search_query = SearchQuery(query)

        messages = Message.objects.annotate(
            rank=SearchRank(search_vector, search_query)
        ).filter(
            rank__gt=0
        ).order_by('-rank', '-created_at')[:limit]

        return list(messages)

    @staticmethod
    def get_recent_work(limit=50, session_id=None):
        """Get most recent messages, optionally scoped to one thread"""
        messages = Message.objects.all()
        if session_id:
            messages = messages.filter(session_id=session_id)
        return list(messages.order_by('-created_at')[:limit])

    @staticmethod
    def list_threads(limit=20, since=None):
        """Distinct threads, most recently active first.

        Without this, recall is a flat chronological column: concurrent
        threads interleave and read as one confused stream.

        A thread here is a session_id. That is a runtime instance, not a
        conversation -- one long session spans several context heaps, and a
        resumed conversation gets a new session_id -- so this is the unit
        available today, not the right one. The intended key is a motion ID
        (see magenta#41). Keep callers keyed on the returned `thread_id` so
        the grouping can change underneath them.
        """
        messages = Message.objects.exclude(session_id__isnull=True)
        if since:
            messages = messages.filter(created_at__gte=since)

        rows = (
            messages.values('session_id')
            .annotate(
                message_count=Count('id'),
                first_at=Min('created_at'),
                last_at=Max('created_at'),
            )
            .order_by('-last_at')[:limit]
        )

        threads = []
        for row in rows:
            in_thread = Message.objects.filter(session_id=row['session_id'])

            # cwd and branch can change mid-session; report where it is now.
            latest = in_thread.exclude(cwd__isnull=True).order_by('-created_at').first()

            # Thinking entities only: tools and system components also send
            # messages, but "who was in this thread" means humans and agents.
            participants = sorted(set(
                in_thread.filter(sender__thinkingentity__isnull=False)
                .values_list('sender_id', flat=True)
            ))

            title_hint = ''
            human_messages = in_thread.filter(
                sender__thinkingentity__is_biological_human=True
            ).order_by('created_at')
            for msg in human_messages[:25]:
                text = ' '.join(_text_of(msg.content).split())
                if not text or text.startswith('<'):
                    continue
                if text.lower().rstrip('.!') in _NON_TOPICAL_OPENERS:
                    continue
                title_hint = text
                break

            threads.append({
                'thread_id': str(row['session_id']),
                'message_count': row['message_count'],
                'first_at': row['first_at'],
                'last_at': row['last_at'],
                'cwd': latest.cwd if latest else None,
                'git_branch': latest.git_branch if latest else None,
                'participants': participants,
                'title_hint': title_hint,
            })

        return threads

    @staticmethod
    def get_random_messages_with_context(count=4, context_messages=4):
        """Get random messages with following context"""
        total = Message.objects.count()
        if total == 0:
            return []

        # Get random message IDs
        all_ids = list(Message.objects.values_list('id', flat=True))
        random_ids = random.sample(all_ids, min(count, len(all_ids)))

        results = []
        for msg_id in random_ids:
            random_msg = Message.objects.get(id=msg_id)

            # Get this message plus N following messages
            following = list(Message.objects.filter(
                created_at__gte=random_msg.created_at
            ).order_by('created_at')[:(context_messages + 1)])

            results.append({
                'starting_message': random_msg,
                'context': following
            })

        return results

    @staticmethod
    def get_recent_messages_by_chars(max_chars=10000):
        """Get recent messages up to a character limit"""
        messages = []
        total_chars = 0

        for msg in Message.objects.order_by('-created_at'):
            content_str = str(msg.content)
            if total_chars + len(content_str) > max_chars:
                break
            messages.append(msg)
            total_chars += len(content_str)

        return messages, total_chars

    @staticmethod
    def get_awakening_reflection():
        """Get most recent 'reawaken and breathe' message"""
        # TODO: Query by topic once topic tagging is working
        # For now, search for messages from magent containing "reawaken" or "breathe"
        return Message.objects.filter(
            Q(sender_id='magent') &
            (Q(content__icontains='reawaken') | Q(content__icontains='breathe'))
        ).order_by('-created_at').first()
