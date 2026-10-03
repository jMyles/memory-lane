"""Read-only public view of Motions.

Served by memory-lane because memory-lane is where the record lives. This
is a projection: nothing here writes, and nothing a reader does can change
the conversation.
"""

from django.conf import settings
from django.db.models import Max
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import ensure_csrf_cookie
from django.core.exceptions import ValidationError
from django.views.decorators.http import require_GET, require_POST

from .models import Message, Motion, ThinkingEntity
from .services import motion_auth
from .services.motion_view import (
    MACHINERY_SENDERS, how_payload, activity, background_tasks, is_wrapper, known_names, mentions_in, motion_payload,
    prose, render_html, step_detail, step_images, step_payload, timeline, turn_payload, turns, wiki_title, wikilinks_in,
)


@ensure_csrf_cookie
@require_GET
def motions_page(request, slug=None):
    if slug is not None and not Motion.objects.filter(slug=slug).exists():
        raise Http404
    device = motion_auth.device_for(request)
    return render(request, 'conversations/motions.html', {
        'initial_slug': slug or '',
        # A preview can pretend to be someone, to show the composer; its
        # database is read-only, so nothing it sends is kept.
        'viewer': device.entity_id if device else getattr(settings, 'PREVIEW_VIEWER', ''),
        'preview_label': getattr(settings, 'PREVIEW_LABEL', ''),
        # [[ in the composer suggests PickiPedia titles, asked of the wiki itself.
        'pickipedia_url': getattr(settings, 'PICKIPEDIA_URL', 'https://pickipedia.xyz').rstrip('/'),
    })


@require_GET
def api_motions(request):
    """Every Motion, most recently active first."""
    payloads = [motion_payload(m) for m in Motion.objects.all()]
    payloads.sort(key=lambda p: p['last_at'] or '', reverse=True)
    people = ThinkingEntity.objects.order_by('name')
    return JsonResponse({'motions': payloads, 'people': [
        {'name': p.name, 'is_human': p.is_biological_human} for p in people]})


@require_GET
def api_motion_turns(request, slug):
    """The readable conversation in one Motion.

    Pass ?after=<message id> to get only what arrived since -- the polling
    contract. An unknown `after` is treated as "everything", so a client
    that has fallen out of sync recovers rather than stalls.
    """
    motion = get_object_or_404(Motion, slug=slug)

    after = before = None
    if request.GET.get('after'):
        after = _message_or_none(request.GET['after'])
    if request.GET.get('before'):
        before = _message_or_none(request.GET['before'])
    # ?from=<id>: that message and everything since -- what a runner reads
    # when a post links a message to read from.
    start = _message_or_none(request.GET['from']) if request.GET.get('from') else None
    # A first load, or a page back, is the newest PAGE items; a poll is
    # everything since.
    limit = None if after is not None or start is not None else PAGE
    if request.GET.get('limit', '').isdigit():  # e.g. the runner wanting recent context only
        limit = max(1, min(int(request.GET['limit']), PAGE))

    names = known_names()
    turns_out, step_msgs, quiet_out, thoughts_out, compactions_out, events_out = [], [], [], [], [], []
    for kind, msg, text in timeline(motion, after=after, before=before, limit=limit, start=start):
        if kind == 'turn':
            turns_out.append(turn_payload(msg, text, names))
        elif kind == 'thought':
            thoughts_out.append({**how_payload(msg), 'id': str(msg.id), 'sender': msg.sender_id,
                                 'created_at': msg.created_at.isoformat(), 'text': text})
        elif kind == 'event':
            events_out.append({'id': str(msg.id), 'created_at': msg.created_at.isoformat(),
                               **{k: text.get(k) for k in ('type', 'server', 'state', 'commit', 'by', 'note', 'took')}})
        elif kind == 'compaction':
            compactions_out.append({'id': str(msg.id), 'session_id': str(msg.session_id or ''),
                                    'created_at': msg.created_at.isoformat(), 'html': render_html(text)})
        elif kind == 'quiet':
            quiet_out.append({'id': str(msg.id), 'sender': msg.sender_id,
                              'created_at': msg.created_at.isoformat(), **text})
        else:
            step_msgs.append(msg)
    images = step_images(step_msgs)
    steps_out = [{**step_payload(m), 'images': images.get(str(m.id), [])} for m in step_msgs]
    first = min([i['created_at'] for i in turns_out + steps_out + quiet_out + thoughts_out + compactions_out
                 + events_out], default=None)
    agents = agents_in(motion)
    return JsonResponse({
        'motion': motion_payload(motion),
        # Prose only: the poller reads an agent turn here as an answer, so a
        # tool call must never appear in this list.
        'turns': turns_out,
        'steps': steps_out,
        # Choices not to speak, shown as dots. Not turns: they answer nothing.
        'quiet': quiet_out,
        # What the agent thought along the way, where the harness kept it.
        'thoughts': thoughts_out,
        # Where a session's context was compacted, and the summary it went on from.
        'compactions': compactions_out,
        # Things that happened around the conversation: a server redeployed.
        'events': events_out,
        'has_earlier': bool(limit) and first is not None and motion.messages.filter(
            is_sidechain=False, created_at__lt=first).exists(),
        'activity': activity(motion),
        # What an agent started in the background here and is still running.
        'tasks': background_tasks(motion),
        # Whether each agent is listening here (the hush menu in the head).
        'listening': {name: a['listening'] for name, a in agents.items()},
        # Each agent here: listening, model, effort, and how full its context is.
        'agents': agents,
        'scram': settings_scram(),
        'typing': typing_in(motion.slug),
    })


PAGE = 400


def agents_in(motion):
    """name -> {listening, model, effort, context} for each agent, in this Motion."""
    from .services import settings as knobs
    from .services.motion_view import context_in
    agents = ThinkingEntity.objects.filter(is_biological_human=False).values_list('name', flat=True)
    out = {}
    for name in agents:
        resolved = knobs.resolve(motion.slug, name)
        out[name] = {'listening': resolved['listening'], 'model': resolved['model'],
                     'effort': resolved['mention_effort'], 'ultracode': bool(resolved['ultracode']),
                     'reads': resolved['catch_up_tokens'],
                     'context': context_in(motion, name)}
    return out


def settings_scram():
    from .services import settings as knobs
    return knobs.scram()


def _message_or_none(raw):
    try:
        return Message.objects.filter(id=raw).first()
    except (ValueError, ValidationError):
        return None


@require_GET
def media_file(request, sha256, ext):
    """A stored image. Immutable by construction: the name is its hash."""
    from django.http import HttpResponse
    from .models import Media

    item = Media.objects.filter(sha256=sha256).first()
    if item is None or Media.EXTENSIONS.get(item.mime) != ext:
        raise Http404('no such image')
    response = HttpResponse(bytes(item.data), content_type=item.mime)
    response['Cache-Control'] = 'public, max-age=31536000, immutable'
    response['X-Content-Type-Options'] = 'nosniff'
    response['Content-Security-Policy'] = "default-src 'none'; sandbox"
    return response


@require_GET
def api_pulse(request):
    """Every Motion at a glance, for a runner looking every few seconds.

    Per Motion: its newest message, newest web post and newest word from a
    person; who is typing; what an agent is doing. All of it is readable
    elsewhere already -- this only saves asking Motion by Motion.
    """
    from django.utils import timezone

    def brief(message):
        return message and {'id': str(message['id']), 'created_at': message['created_at'].isoformat(),
                            'sender': message['sender_id']}

    from .models import Setting
    from .services import settings as knobs

    humans = set(ThinkingEntity.objects.filter(is_biological_human=True).values_list('name', flat=True))
    agent = request.GET.get('agent', 'magent')
    rows = list(Setting.objects.exclude(key__in=knobs.MODERATION_KEYS))
    motions = []
    for motion in Motion.objects.all():
        said = motion.messages.filter(is_sidechain=False).exclude(sender_id__in=MACHINERY_SENDERS)
        fields = ('id', 'created_at', 'sender_id')
        motions.append({
            'slug': motion.slug,
            'newest': brief(said.order_by('-created_at').values(*fields).first()),
            'last_web_post': brief(said.filter(source_file='motion-web').order_by('-created_at').values(*fields).first()),
            'last_human': brief(said.filter(sender_id__in=humans).order_by('-created_at').values(*fields).first()),
            'typing': typing_in(motion.slug),
            'activity': activity(motion),
            # How this agent is to carry itself here (services/settings.py).
            'settings': knobs.resolve(motion.slug, agent, rows=rows),
        })
    return JsonResponse({
        'now': timezone.now().isoformat(),
        'agent': agent,
        # An admin's emergency stop: while set, a runner wakes nothing.
        'scram': knobs.scram(),
        'budget': {k: knobs.global_value(k) for k in knobs.GLOBAL_KNOBS},
        'motions': motions,
    })


@require_GET
def api_motion_step(request, slug, step_id):
    """One tool call in full, for a step someone opened."""
    msg = _message_or_none(step_id)
    if msg is None or msg.motion_id != slug or not hasattr(msg, 'tooluse'):
        raise Http404('no such step in this Motion')
    return JsonResponse(step_detail(msg))


# --- who is typing ---------------------------------------------------------
# Ephemeral, so not in the record: a shared cache entry per Motion holding
# name -> when they last typed. Every gunicorn worker shares the cache.
TYPING_FOR = 8  # seconds a keystroke counts as "typing"


def _typing_key(slug):
    return f'typing:{slug}'


def typing_in(slug):
    from django.core.cache import cache
    import time
    now = time.time()
    return sorted(name for name, at in (cache.get(_typing_key(slug)) or {}).items() if now - at < TYPING_FOR)


@require_POST
def api_typing(request, slug):
    """Say this device's person is (or stopped) typing in a Motion."""
    from django.core.cache import cache
    import json
    import time
    from .views_admin import locked_response
    if locked_response():
        return locked_response()
    device = motion_auth.device_for(request)
    if device is None:
        return JsonResponse({'error': 'sign in to write'}, status=401)
    get_object_or_404(Motion, slug=slug)
    try:
        typing = bool(json.loads(request.body or b'{}').get('typing', True))
    except (ValueError, AttributeError):
        return JsonResponse({'error': 'expected {"typing": true|false}'}, status=400)
    now = time.time()
    state = {n: at for n, at in (cache.get(_typing_key(slug)) or {}).items() if now - at < TYPING_FOR}
    if typing:
        state[device.entity_id] = now
    else:
        state.pop(device.entity_id, None)
    cache.set(_typing_key(slug), state, TYPING_FOR * 2)
    return JsonResponse({'typing': sorted(state)})


@require_GET
def api_motion_sessions(request, slug):
    """Runtime sessions in a Motion, most recently active first.

    ?sender=<name> keeps only sessions in which that entity wrote. This is
    how the poller finds a session to resume when it wakes an agent: the
    Motion is durable, and whichever process last spoke for the agent is
    the one to continue. A session id is a local handle, not a credential.
    """
    motion = get_object_or_404(Motion, slug=slug)
    messages = Message.objects.filter(motion=motion, session_id__isnull=False)
    sender = request.GET.get('sender')
    if sender:
        messages = messages.filter(sender_id=sender.lower())
    sessions = (messages.values('session_id')
                .annotate(last_at=Max('created_at'))
                .order_by('-last_at'))
    return JsonResponse({'motion': motion.slug, 'sessions': [
        {'session_id': str(s['session_id']), 'last_at': s['last_at'].isoformat()} for s in sessions
    ]})


@require_GET
def api_wikilinks(request):
    """Turns in Motions that link to PickiPedia pages with [[...]], oldest first.

    This is what PickiPedia reads to reach Motions without storing them.
    ?page=<title> keeps one page's backlinks. ?since=<iso> starts after a
    moment; pass back `next_since` to page forward. A message's links are
    never split across pages. The cursor is ingest time (created_at), so a
    consumer should overlap its cursor by a few minutes and dedupe on
    (turn, page), and resync fully now and then: motion_assign attaches
    old messages to a Motion without changing their created_at.
    Titles are normalised as MediaWiki does.
    """
    page = request.GET.get('page')
    page = wiki_title(page) if page else None
    since_raw = request.GET.get('since')
    since = parse_datetime(since_raw) if since_raw else None
    if since_raw and since is None:
        return JsonResponse({'error': f'unparseable since: {since_raw!r} (URL-encode the +)'}, status=400)
    try:
        limit = min(max(int(request.GET.get('limit', 200)), 1), 1000)
    except ValueError:
        limit = 200

    names = known_names()
    messages = (
        Message.objects.filter(motion__isnull=False, is_sidechain=False)
        .exclude(sender_id__in=MACHINERY_SENDERS)
        .order_by('created_at')
    )
    if since:
        messages = messages.filter(created_at__gt=since)

    links, next_since = [], None
    for msg in messages.iterator():
        if len(links) >= limit:
            break
        next_since = msg.created_at.isoformat()
        if msg.sender_id not in names:
            continue
        text = prose(msg.content)
        if not text or is_wrapper(text):
            continue
        for title in wikilinks_in(text):
            if page and title != page:
                continue
            links.append({'page': title, 'motion': msg.motion_id, 'turn': str(msg.id),
                          'sender': msg.sender_id, 'created_at': msg.created_at.isoformat(),
                          'eth_blockheight': msg.eth_blockheight})
    else:
        next_since = None  # read to the end

    return JsonResponse({'links': links, 'next_since': next_since})


SEARCH_MAX = 40
SEARCH_SCAN = 300  # candidates read, newest first, before keeping only what people and agents said


def snippet(text, q, width=160):
    """`text` around the first place `q` occurs, with its ends marked if cut."""
    at = text.lower().find(q.lower())
    if at < 0:
        return text[:width]
    start = max(0, at - width // 3)
    end = min(len(text), start + width)
    return ('…' if start else '') + text[start:end] + ('…' if end < len(text) else '')


@require_GET
def api_search(request):
    """What was said, in one Motion (?motion=<slug>) or all of them, that contains ?q=.

    Newest first, at most SEARCH_MAX. Only what people and agents said --
    not tool calls, their results or the harness's wrappers. A plain
    case-insensitive match on the stored text: about 0.15 s in one Motion,
    1.2 s across all of them, at 25k messages.
    """
    from django.db.models import TextField
    from django.db.models.functions import Cast

    q = (request.GET.get('q') or '').strip()
    if len(q) < 2:
        return JsonResponse({'error': 'two characters at least'}, status=400)
    q = q[:200]
    names = known_names()
    rows = (Message.objects.filter(motion__isnull=False, is_sidechain=False)
            .exclude(sender_id__in=MACHINERY_SENDERS)
            .annotate(text=Cast('content', TextField())).filter(text__icontains=q))
    motion = request.GET.get('motion')
    if motion:
        rows = rows.filter(motion_id=motion)
    titles = dict(Motion.objects.values_list('slug', 'title'))
    hits = []
    for msg in rows.select_related('sender').order_by('-created_at')[:SEARCH_SCAN]:
        if msg.sender_id not in names:
            continue
        text = prose(msg.content)
        if not text or is_wrapper(text) or q.lower() not in text.lower():
            continue
        hits.append({'id': str(msg.id), 'motion': msg.motion_id, 'title': titles.get(msg.motion_id, msg.motion_id),
                     'sender': msg.sender_id, 'created_at': msg.created_at.isoformat(), 'text': snippet(text, q)})
        if len(hits) >= SEARCH_MAX:
            break
    return JsonResponse({'q': q, 'motion': motion, 'hits': hits})


RECENT_MAX = 30
RECENT_SCAN = 800  # rows read for what was said, newest first


@require_GET
def api_recent(request):
    """What's been happening across every Motion, newest first: what people said,
    agents' finished answers, renames, settings changed, Motions opened.

    ?since=<iso> (default: a day ago), ?limit= (at most RECENT_MAX). Read
    from the record; agents' progress lines between tool calls are left
    out, or they would be all there is.
    """
    from datetime import timedelta
    from django.utils import timezone
    from .models import Setting
    from .services.motion_view import quiet_reason

    since = parse_datetime(request.GET.get('since') or '') or timezone.now() - timedelta(days=1)
    try:
        limit = min(max(int(request.GET.get('limit', RECENT_MAX)), 1), RECENT_MAX)
    except ValueError:
        limit = RECENT_MAX
    names = known_names()
    agents = set(ThinkingEntity.objects.filter(is_biological_human=False).values_list('name', flat=True))
    titles = dict(Motion.objects.values_list('slug', 'title'))
    events = []

    said = (Message.objects.filter(motion__isnull=False, is_sidechain=False, created_at__gt=since)
            .exclude(sender_id__in=MACHINERY_SENDERS).order_by('-created_at')[:RECENT_SCAN])
    for msg in said:
        if msg.sender_id not in names:
            continue
        text = prose(msg.content)
        if not text or is_wrapper(text) or quiet_reason(text) is not None:
            continue
        if msg.sender_id in agents and msg.stop_reason != 'end_turn':
            continue
        events.append({'kind': 'answered' if msg.sender_id in agents else 'said', 'at': msg.created_at.isoformat(),
                       'motion': msg.motion_id, 'who': msg.sender_id, 'id': str(msg.id), 'text': text[:140]})
        if len(events) >= limit:
            break

    for msg in (Message.objects.filter(source_file='motion-rename', created_at__gt=since)
                .order_by('-created_at')[:limit]):
        content = msg.content if isinstance(msg.content, dict) else {}
        events.append({'kind': 'renamed', 'at': msg.created_at.isoformat(), 'motion': msg.motion_id,
                       'who': content.get('by', ''), 'text': f"{(content.get('from') or {}).get('title', '')} → "
                                                             f"{(content.get('to') or {}).get('title', '')}"})

    for row in Setting.objects.filter(created_at__gt=since).order_by('-created_at')[:limit]:
        value = row.value if not isinstance(row.value, dict) else (row.value.get('mode') or row.value)
        events.append({'kind': 'set', 'at': row.created_at.isoformat(), 'motion': row.motion_id,
                       'who': row.set_by_id or '', 'text': f"{row.key} for {row.agent_id or 'every agent'}: {value}"[:140]})

    told = set()  # a redeploy is announced in several Moods; list it once
    for row in (Message.objects.filter(source_file='deploy', created_at__gt=since).order_by('-created_at')
                .values('content', 'created_at')[:limit * 10]):
        c = row['content'] if isinstance(row['content'], dict) else {}
        key = (c.get('server'), c.get('state'), row['created_at'].replace(microsecond=0).isoformat()[:18])
        if key in told:
            continue
        told.add(key)
        verb = {'started': 'redeploy started', 'finished': 'redeployed', 'failed': 'redeploy failed'}.get(c.get('state'), '')
        events.append({'kind': 'deploy', 'at': row['created_at'].isoformat(), 'motion': None, 'who': c.get('by', ''),
                       'text': f"{c.get('server')} {verb}" + (f" · {c['commit'][:8]}" if c.get('commit') else '')})

    for motion in Motion.objects.filter(created_at__gt=since).order_by('-created_at')[:limit]:
        events.append({'kind': 'opened', 'at': motion.created_at.isoformat(), 'motion': motion.slug, 'who': '',
                       'text': motion.title or motion.slug})

    events.sort(key=lambda e: e['at'], reverse=True)
    for e in events:
        e['title'] = titles.get(e['motion'], e['motion'] or 'every Motion')
    return JsonResponse({'events': events[:limit]})


NOTICES_MAX = 100


def answered_by(msg, humans):
    """Who an agent's finished turn was answering: the person whose words were
    the last a person said in that Motion before it, or None."""
    earlier = (Message.objects.filter(motion_id=msg.motion_id, is_sidechain=False, created_at__lt=msg.created_at,
                                      sender_id__in=humans)
               .order_by('-created_at').only('content', 'sender_id')[:5])
    for m in earlier:  # the latest that is someone's words, not a harness wrapper
        text = prose(m.content)
        if text and not is_wrapper(text):
            return m.sender_id
    return None


@require_GET
def api_notices(request, name):
    """What `name` would want to hear about, across every Motion, since a moment.

    Two kinds, newest first: a 'mention' of them by someone else, and an
    'answer' -- an agent's turn that ended (end_turn) in a Motion where they
    were the last person to speak before it. That second kind is how someone
    who asked something and went elsewhere learns the agent is done, without
    the agent having to @mention them back.

    ?since=<iso> (default: an hour ago). At most NOTICES_MAX.
    """
    from datetime import timedelta
    from django.utils import timezone
    from .services.motion_view import quiet_reason

    name = name.lower()
    if not ThinkingEntity.objects.filter(name=name).exists():
        raise Http404
    since = parse_datetime(request.GET.get('since') or '') or timezone.now() - timedelta(hours=1)
    names = known_names()
    agents = set(ThinkingEntity.objects.filter(is_biological_human=False).values_list('name', flat=True))
    humans = set(ThinkingEntity.objects.filter(is_biological_human=True).values_list('name', flat=True))
    messages = (Message.objects.filter(motion__isnull=False, is_sidechain=False, created_at__gt=since)
                .exclude(sender_id__in=MACHINERY_SENDERS).select_related('sender').order_by('-created_at'))
    found = []
    for msg in messages.iterator():
        if msg.sender_id not in names or msg.sender_id == name:
            continue
        text = prose(msg.content)
        if not text or is_wrapper(text):
            continue
        if name in mentions_in(text, names):
            found.append({'kind': 'mention', 'motion': msg.motion_id, 'turn': turn_payload(msg, text, names)})
        elif (msg.sender_id in agents and msg.stop_reason == 'end_turn' and quiet_reason(text) is None
              and answered_by(msg, humans) == name):
            found.append({'kind': 'answer', 'motion': msg.motion_id, 'turn': turn_payload(msg, text, names)})
        if len(found) >= NOTICES_MAX:
            break
    return JsonResponse({'name': name, 'notices': found})


@require_GET
def api_mentions(request, name):
    """Recent turns, across all Motions, that mention one thinking entity.

    Newest first. ?since=<iso> narrows to what arrived after a moment;
    ?limit= caps the result (default 50, max 200). Mentions are derived
    from message text at read time -- there is no mention table -- so this
    scans, bounded by `since` and `limit`. Fine at today's volume.

    This is what a notification badge reads, and what a poller reads to
    learn that an agent has been addressed by name.
    """
    name = name.lower()
    if not ThinkingEntity.objects.filter(name=name).exists():
        raise Http404

    since = parse_datetime(request.GET.get('since') or '')
    try:
        limit = min(max(int(request.GET.get('limit', 50)), 1), 200)
    except ValueError:
        limit = 50

    names = known_names()
    messages = (
        Message.objects.filter(motion__isnull=False, is_sidechain=False)
        .exclude(sender_id__in=MACHINERY_SENDERS)
        .select_related('sender')
        .order_by('-created_at')
    )
    if since:
        messages = messages.filter(created_at__gt=since)

    found = []
    for msg in messages.iterator():
        if msg.sender_id not in names:
            continue
        text = prose(msg.content)
        if not text or is_wrapper(text):
            continue
        if name in mentions_in(text, names):
            found.append({'motion': msg.motion_id, 'turn': turn_payload(msg, text, names)})
            if len(found) >= limit:
                break

    return JsonResponse({'name': name, 'mentions': found})


# --- installing it as an app (a web app manifest, an icon, a service worker) --
# Chrome and Edge (Ubuntu, Windows, macOS) offer "Install" for a page with a
# manifest, and Chrome on Android "Install app": it then opens in its own
# window, from the launcher, with no browser around it.

@require_GET
def app_manifest(request):
    return JsonResponse({
        'name': 'pickipedia chat',
        'short_name': 'pickipedia chat',
        'description': 'Moods: where cryptograss talks, people and agents together.',
        'id': '/motions/',
        'start_url': '/motions/',
        'scope': '/motions/',
        'display': 'standalone',
        'background_color': '#fbfaf7',
        'theme_color': '#b8106b',
        'icons': [{'src': f'/motions/icon-{size}.png', 'sizes': f'{size}x{size}', 'type': 'image/png',
                   'purpose': 'any maskable'} for size in (192, 512)],
    }, content_type='application/manifest+json')


@require_GET
def app_icon(request, size):
    from django.http import HttpResponse
    from .services import app_icon as icon
    if size not in (180, 192, 512):
        raise Http404('no icon that size')
    response = HttpResponse(icon.png(size), content_type='image/png')
    response['Cache-Control'] = 'public, max-age=86400'
    return response


SERVICE_WORKER = """// pickipedia chat: here so the page can be installed as an app. It keeps
// nothing: every request goes to the network, as if it weren't here.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {
  if (e.request.mode === 'navigate') e.respondWith(fetch(e.request));
});
// A notification (a mention, an answer) opens its Mood at that message: in a
// window already open on pickipedia chat if there is one, else a new one.
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const { slug, id } = e.notification.data || {};
  const url = '/motions/' + encodeURIComponent(slug || '') + '/' + (id ? '#m-' + id : '');
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    const open = list.find(c => new URL(c.url).pathname.startsWith('/motions/'));
    if (open) { open.postMessage({ open: slug, id }); return open.focus(); }
    return self.clients.openWindow(url);
  }));
});
"""


@require_GET
def app_service_worker(request):
    from django.http import HttpResponse
    response = HttpResponse(SERVICE_WORKER, content_type='text/javascript')
    response['Service-Worker-Allowed'] = '/motions/'
    response['Cache-Control'] = 'no-cache'
    return response


@require_GET
def api_work(request):
    """Open pull requests and new issues across our repositories, with the people
    and Moods each involves (services/work.py)."""
    from django.core.cache import cache
    from .services import work
    items = cache.get('work:open')
    if items is None:
        try:
            items = work.open_work()
        except Exception as e:  # the forge unreachable, or rate-limited: say so, don't fail the page
            return JsonResponse({'items': [], 'error': f'could not ask the forge: {type(e).__name__}'})
        cache.set('work:open', items, 120)
    return JsonResponse({'items': items})
