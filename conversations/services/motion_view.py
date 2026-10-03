"""Turn a Motion into something a person can read.

A Motion is mostly machinery. Of the first 42 messages in the first Motion,
30 were tool calls, their results, system notices and thinking blocks. A
conversation view keeps the prose from thinking entities and drops the rest.
What it drops is a product decision, made here in one place.

The record holds whatever the agent wrote -- usually markdown, because the
agent composes for a terminal. Each view translates for itself; this one
produces HTML, escaped first so nothing in a message can inject markup, with
[[wikilinks]] resolving to PickiPedia.
"""

import html
import re

from django.conf import settings

MACHINERY_SENDERS = {'tool-result', 'system'}

# Command scaffolding, system reminders and interruption markers are text,
# but they are not conversation.
# The summary Claude Code starts a session with after compacting it. Not
# anyone's words -- the harness writes it, as a prompt -- so never a turn or
# a mention; the Motion shows it folded, as the moment a context was compacted.
COMPACTION_PREFIX = 'This session is being continued from a previous conversation'
INTERRUPT_SOURCE = 'interrupt'
# System rows shown as a line in the thread.
NEW_MOOD_SOURCE = 'motion-new'
EVENT_SOURCES = ('deploy', INTERRUPT_SOURCE, NEW_MOOD_SOURCE)
# Words posted into a Motion directly, not typed into a session: from the
# composer, or attested with a key (magenta.sh attest).
POSTED = ('motion-web', 'motion-attest')
_WRAPPER_PREFIXES = ('<', '[Request interrupted', COMPACTION_PREFIX)


def pickipedia_url():
    return getattr(settings, 'PICKIPEDIA_URL', 'https://pickipedia.xyz').rstrip('/')


def prose(content):
    """Human-readable text from a message's content, or '' if it is machinery."""
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, dict):
        if content.get('type') == 'attestation':
            return str(content.get('text', '')).strip()  # a statement signed with someone's key
        return ''  # a tool call
    if isinstance(content, list):
        parts = []
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get('type') == 'text' or ('text' in block and 'type' not in block):
                parts.append(block.get('text', ''))
        return '\n'.join(p for p in parts if p).strip()
    return ''


# An agent's choice not to speak: <silent/>, or <silent>why</silent>.
# by="screen": the runner's quick screen let it pass, not the agent itself.
_QUIET = re.compile(r'^<silent\s*/>$|^<silent(?:\s+by="(\w+)")?>(.*)</silent>$', re.S)


def quiet_reason(text):
    """{'reason', 'by'} for a silent reply ('by' is '' when the agent itself
    chose), or None if the text isn't one."""
    match = _QUIET.match(text)
    if not match:
        return None
    return {'reason': (match.group(2) or '').strip(), 'by': match.group(1) or ''}


def thought_text(content):
    """What a thinking block says, if the harness kept any of it ('' if not).

    Claude Code often stores thinking with its text emptied, but sometimes
    keeps a short note -- the dimmed lines a terminal shows between tool
    calls. Those are part of how the agent got where it did.
    """
    if not isinstance(content, list):
        return ''
    parts = [b.get('thinking', '') for b in content if isinstance(b, dict) and b.get('type') == 'thinking']
    return '\n'.join(p for p in parts if p).strip()


def is_wrapper(text):
    return text.startswith(_WRAPPER_PREFIXES)


def is_compaction(text):
    return text.startswith(COMPACTION_PREFIX)


def turns(motion, after=None):
    """Yield (message, text) for the readable conversation in a Motion.

    `after` is a Message; only turns created after it are yielded, which is
    what a polling client needs.
    """
    from conversations.models import ThinkingEntity

    speakers = set(ThinkingEntity.objects.values_list('name', flat=True))
    messages = motion.messages.filter(is_sidechain=False).select_related('sender').order_by('created_at')
    if after is not None:
        messages = messages.filter(created_at__gt=after.created_at)

    for msg in messages:
        if msg.sender_id in MACHINERY_SENDERS or msg.sender_id not in speakers:
            continue
        text = prose(msg.content)
        if not text or is_wrapper(text):
            continue
        yield msg, text


# --- markdown-ish to HTML ---------------------------------------------------

_FENCE = re.compile(r'```[^\n]*\n(.*?)```', re.S)
_INLINE_CODE = re.compile(r'`([^`\n]+)`')
_BOLD = re.compile(r'\*\*([^*\n]+)\*\*')
_ITALIC = re.compile(r'(?<![*\w])\*([^*\n]+)\*(?!\*)')
_WIKILINK = re.compile(r'\[\[([^\]|]+)(?:\|([^\]]+))?\]\]')
# @name, but not inside an email, a URL path, or another handle.
_MENTION = re.compile(r'(?<![\w@/.])@([A-Za-z][\w.-]*)')
# ![alt](url): our own stored media, or https from hosts we trust to serve
# images (settings.MOTION_IMAGE_HOSTS); any other host renders as a link,
# so a viewer's browser never fetches from somewhere nobody chose.
_IMAGE = re.compile(r'!\[([^\]\n]*)\]\((/motions/media/[0-9a-f]{64}\.(?:png|jpg|gif|webp)|https://[^)\s]+)\)')
_MD_LINK = re.compile(r'\[([^\]]+)\]\((https?://[^)\s]+)\)')
_URL = re.compile(r'(https?://(?:(?!&quot;|&#x27;|&lt;|&gt;)[^\s<>"\x01\x02])+)')
# Placeholders the renderer uses for markup it has already made; never input.
_PLACEHOLDER_CHARS = re.compile(r'[\x00\x01\x02]')
_TRAILING_PUNCT = '.,;:!?)]\'"'
_HEADING = re.compile(r'^#{1,6}\s+(.+)$')
_BULLET = re.compile(r'^\s*[-*–]\s+(.*)$')
_NUMBERED = re.compile(r'^\s*\d+[.)]\s+(.*)$')
_TABLE_SEP_CELL = re.compile(r'^:?-+:?$')


def _table_cells(line):
    return [c.strip() for c in line.strip().strip('|').split('|')]


def _is_table_separator(cells):
    return all(_TABLE_SEP_CELL.match(c) for c in cells if c) and any(cells)


def _wikilink(match):
    target = match.group(1).strip()
    label = (match.group(2) or target).strip()
    href = f"{pickipedia_url()}/wiki/{target.replace(' ', '_')}"
    return f'<a class="wikilink" href="{href}">{label}</a>'


def _image(match):
    alt, url = match.group(1), match.group(2)
    if url.startswith('/') or _image_host_allowed(url):
        return f'<a class="img" href="{url}"><img src="{url}" alt="{alt}" loading="lazy"></a>'
    return f'<a href="{url}">{alt or url}</a>'


def _image_host_allowed(url):
    from urllib.parse import urlsplit
    host = (urlsplit(url.replace('&amp;', '&')).hostname or '').lower()
    return host in getattr(settings, 'MOTION_IMAGE_HOSTS', ())


def step_images(step_messages):
    """{step id: [media urls in its result]} for steps whose tool returned images."""
    from conversations.models import ToolResult
    from conversations.services.media import urls_in

    by_tool = {(m.tooluse.tool_id, m.session_id): str(m.id) for m in step_messages}
    if not by_tool:
        return {}
    found = {}
    results = (ToolResult.objects.filter(tool_use_id__in={t for t, _ in by_tool},
                                         content__icontains='/motions/media/')
               .values_list('tool_use_id', 'session_id', 'content'))
    for tool_id, session_id, content in results:
        step = by_tool.get((tool_id, session_id))
        if step:
            found.setdefault(step, []).extend(urls_in(content if isinstance(content, str) else str(content)))
    return found


def known_names():
    """Names that can be mentioned: every thinking entity, human or agent."""
    from conversations.models import ThinkingEntity
    return set(ThinkingEntity.objects.values_list('name', flat=True))


def wiki_title(target):
    """A link target as MediaWiki names the page: no fragment, spaces, first letter capital."""
    title = target.split('#', 1)[0].replace('_', ' ').strip().lstrip(':').strip()
    title = re.sub(r'\s+', ' ', title)
    return title[:1].upper() + title[1:]


def wikilinks_in(text):
    """Ordered, de-duplicated PickiPedia titles a text links to with [[...]].

    Code is literal, as in the renderer: a [[link]] inside backticks is an
    example, not a link.
    """
    text = _INLINE_CODE.sub('', _FENCE.sub('', text))
    seen, out = set(), []
    for match in _WIKILINK.finditer(text):
        title = wiki_title(match.group(1))
        if title and title not in seen:
            seen.add(title)
            out.append(title)
    return out


def mentions_in(text, mentionable):
    """Ordered, de-duplicated names mentioned in text, restricted to known ones.

    Restricting to known names is what keeps an email address or a stray
    handle from becoming a mention. Matching is case-insensitive; the
    canonical (lowercase) name is returned.
    """
    lowered = {n.lower() for n in mentionable}
    # Code is literal for the renderer, so it must be literal here too, or
    # the mention count and the highlighted text disagree.
    text = _INLINE_CODE.sub('', _FENCE.sub('', text))
    seen, out = set(), []
    for match in _MENTION.finditer(text):
        name = match.group(1).rstrip('.').lower()
        if name in lowered and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _mention(mentionable, stash=lambda markup: markup):
    lowered = {n.lower() for n in mentionable}

    def repl(match):
        raw = match.group(1)
        trailing = ''
        if raw.endswith('.'):
            raw, trailing = raw[:-1], '.'
        if raw.lower() not in lowered:
            return match.group(0)
        return stash(f'<span class="mention" data-who="{raw.lower()}">@{raw}</span>') + trailing
    return repl


def _link_url(match):
    """Link a bare URL, leaving sentence punctuation outside the anchor."""
    url, tail = match.group(1), ''
    while url and url[-1] in _TRAILING_PUNCT:
        tail, url = url[-1] + tail, url[:-1]
    return f'<a href="{url}">{url}</a>{tail}'


def _inline(text, mentionable=()):
    # Inline code is literal: lift it out so nothing below formats it.
    codes = []

    def keep(match):
        codes.append(match.group(1))
        return f'\x01{len(codes) - 1}\x01'

    text = _INLINE_CODE.sub(keep, text)

    # Each linker's output is lifted out too, so no later pass ever reads
    # markup: a URL inside an href, say, must not be linked again -- that
    # would let text break out of the attribute.
    made = []

    def stash(markup):
        made.append(markup)
        return f'\x02{len(made) - 1}\x02'

    text = _IMAGE.sub(lambda m: stash(_image(m)), text)
    text = _WIKILINK.sub(lambda m: stash(_wikilink(m)), text)
    text = _MD_LINK.sub(lambda m: stash(f'<a href="{m.group(2)}">{m.group(1)}</a>'), text)
    text = _URL.sub(lambda m: stash(_link_url(m)), text)
    if mentionable:
        text = _MENTION.sub(_mention(mentionable, stash), text)
    text = _BOLD.sub(r'<strong>\1</strong>', text)
    text = _ITALIC.sub(r'<em>\1</em>', text)
    text = re.sub(r'\x02(\d+)\x02', lambda m: made[int(m.group(1))], text)
    for i, code in enumerate(codes):
        text = text.replace(f'\x01{i}\x01', f'<code>{code}</code>')
    return text


def render_html(text, mentionable=()):
    """Escape, then translate the markdown the agent writes into HTML."""
    text = html.escape(_PLACEHOLDER_CHARS.sub('', text), quote=True)

    def inline(s):
        return _inline(s, mentionable)

    # Lift fenced code out before anything else can touch it.
    fences = []

    def keep(match):
        fences.append(match.group(1).rstrip('\n'))
        return f'\x00{len(fences) - 1}\x00'

    text = _FENCE.sub(keep, text)

    blocks = []
    paragraph, list_items, list_tag = [], [], None
    table_rows = []

    def flush_paragraph():
        if paragraph:
            blocks.append('<p>' + inline('<br>'.join(paragraph)) + '</p>')
            paragraph.clear()

    def flush_list():
        nonlocal list_tag
        if list_items:
            items = ''.join(f'<li>{inline(i)}</li>' for i in list_items)
            blocks.append(f'<{list_tag}>{items}</{list_tag}>')
            list_items.clear()
        list_tag = None

    def flush_table():
        rows = [r for r in table_rows if not _is_table_separator(r)]
        if rows:
            head = ''.join(f'<th>{inline(c)}</th>' for c in rows[0])
            body = ''.join(
                '<tr>' + ''.join(f'<td>{inline(c)}</td>' for c in r) + '</tr>'
                for r in rows[1:]
            )
            blocks.append(f'<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>')
        table_rows.clear()

    for line in text.split('\n'):
        stripped = line.strip()
        if not stripped:
            flush_paragraph()
            flush_list()
            flush_table()
            continue
        if stripped.startswith('|') and stripped.endswith('|'):
            flush_paragraph()
            flush_list()
            table_rows.append(_table_cells(stripped))
            continue
        flush_table()
        if stripped.startswith('\x00'):
            flush_paragraph()
            flush_list()
            blocks.append(stripped)
            continue
        heading = _HEADING.match(stripped)
        if heading:
            flush_paragraph()
            flush_list()
            blocks.append(f'<h4>{inline(heading.group(1))}</h4>')
            continue
        bullet, numbered = _BULLET.match(line), _NUMBERED.match(line)
        if bullet or numbered:
            flush_paragraph()
            tag = 'ul' if bullet else 'ol'
            if list_tag != tag:
                flush_list()
                list_tag = tag
            list_items.append((bullet or numbered).group(1))
            continue
        flush_list()
        paragraph.append(stripped)

    flush_paragraph()
    flush_list()
    flush_table()

    out = '\n'.join(blocks)
    for i, code in enumerate(fences):
        out = out.replace(f'\x00{i}\x00', f'<pre><code>{code}</code></pre>')
    return out


def timeline(motion, after=None, before=None, limit=None, start=None):
    """Readable turns and the agent's tool steps, oldest first.

    Yields ('turn', message, text), ('quiet', message, reason) for an
    agent's choice not to speak, ('thought', message, text) for thinking the
    harness kept, ('compaction', message, summary) where a session was
    compacted, and ('step', message, None). A step is
    one tool call; its result is fetched on demand (step_detail), so the
    thread stays light. `limit` keeps the newest that many items -- a first
    load, or a page further back with `before`. `start` includes that message
    and everything after it (a runner reading from a linked message).
    """
    from conversations.models import ThinkingEntity

    speakers = set(ThinkingEntity.objects.values_list('name', flat=True))
    rows = motion.messages.filter(is_sidechain=False).select_related('sender', 'tooluse', 'thought')
    if after is not None:
        rows = rows.filter(created_at__gt=after.created_at)
    if start is not None:
        rows = rows.filter(created_at__gte=start.created_at)
    if before is not None:
        rows = rows.filter(created_at__lt=before.created_at)

    def item(msg):
        if msg.source_file in EVENT_SOURCES and isinstance(msg.content, dict):
            return ('event', msg, msg.content)  # a server redeployed, someone stopped an agent: a line in the thread
        if msg.sender_id in MACHINERY_SENDERS or msg.sender_id not in speakers:
            return None
        if hasattr(msg, 'tooluse'):
            return ('step', msg, None)
        if hasattr(msg, 'thought'):
            thinking = thought_text(msg.content)
            return ('thought', msg, thinking) if thinking else None
        text = prose(msg.content)
        if not text:
            return None
        reason = quiet_reason(text)
        if reason is not None:
            return ('quiet', msg, reason)
        if is_compaction(text):
            return ('compaction', msg, text)
        if is_wrapper(text):
            return None
        return ('turn', msg, text)

    if limit is None:
        for msg in rows.order_by('created_at'):
            found = item(msg)
            if found:
                yield found
        return

    # Newest first, in chunks, until there are enough.
    found, last = [], None
    while len(found) < limit:
        chunk = rows.order_by('-created_at')
        if last is not None:
            chunk = chunk.filter(created_at__lt=last)
        chunk = list(chunk[:500])
        if not chunk:
            break
        last = chunk[-1].created_at
        for msg in chunk:
            got = item(msg)
            if got:
                found.append(got)
                if len(found) == limit:
                    break
    yield from reversed(found)


_STEP_WORDS = {
    'Bash': 'ran', 'Read': 'read', 'Edit': 'edited', 'Write': 'wrote', 'Grep': 'searched', 'Glob': 'searched',
    'WebFetch': 'fetched', 'WebSearch': 'searched the web', 'Agent': 'asked a helper', 'Task': 'asked a helper',
    'ToolSearch': 'looked up tools', 'Skill': 'read a skill', 'TodoWrite': 'planned', 'NotebookEdit': 'edited',
    'TaskCreate': 'tracked', 'TaskUpdate': 'tracked', 'TaskList': 'tracked', 'SendMessage': 'messaged a helper',
    'SendUserFile': 'sent a file', 'AskUserQuestion': 'asked',
}


def step_summary(tool, args):
    """A line saying what one tool call was for."""
    if not isinstance(args, dict):
        return ''
    for key in ('description', 'file_path', 'path', 'pattern', 'url', 'query', 'subject', 'prompt', 'command'):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().splitlines()[0][:160]
    for value in args.values():
        if isinstance(value, str) and value.strip():
            return value.strip().splitlines()[0][:160]
    return ''


def step_payload(msg):
    tool = msg.tooluse.tool_name
    return {
        **how_payload(msg),
        'id': str(msg.id),
        'sender': msg.sender_id,
        'created_at': msg.created_at.isoformat(),
        'tool': tool,
        'verb': _STEP_WORDS.get(tool, 'used ' + (tool.split('__')[1] if tool.startswith('mcp__') else tool)),
        'summary': step_summary(tool, msg.content),
    }


def step_detail(msg):
    """One tool call in full: what was asked and what came back."""
    from conversations.models import ToolResult

    result = (ToolResult.objects.filter(tool_use_id=msg.tooluse.tool_id, session_id=msg.session_id)
              .order_by('created_at').first())
    return {
        **step_payload(msg),
        'input': msg.content if isinstance(msg.content, dict) else {'value': msg.content},
        'result': None if result is None else {
            'text': result.content if isinstance(result.content, str) else prose(result.content),
            'is_error': result.is_error,
        },
    }


def model_label(model):
    """'claude-opus-5-5' -> 'Opus 5.5'; anything not Claude's naming as it is."""
    if not model or model.startswith('<'):
        return ''
    if not model.startswith('claude-'):
        return model
    parts = re.sub(r'-\d{8}$', '', model[len('claude-'):]).split('-')
    family = next((p for p in parts if not p.isdigit()), '')
    version = '.'.join(p for p in parts if p.isdigit())
    return f'{family.capitalize()} {version}'.strip()


def how_payload(msg):
    """Model and effort an agent's message ran on ('' when unknown); what it
    wrote and read, in tokens; and whether it ended its turn.

    One response the model gives can be stored as several rows (its thinking,
    its words, a tool call), each with that response's usage: the page counts
    a repeat of the same usage once."""
    out = {'model': model_label(msg.model_backend), 'effort': msg.effort or ''}
    if msg.output_tokens is not None or msg.input_tokens is not None:
        out['out'] = msg.output_tokens or 0
        out['ctx'] = sum(n or 0 for n in (msg.input_tokens, msg.cache_read_input_tokens,
                                          msg.cache_creation_input_tokens))
    if msg.stop_reason:
        out['stop'] = msg.stop_reason
    return out


def attestation_of(msg):
    """What makes a turn an attestation -- exactly what was signed, the
    signature, the key -- or None."""
    c = msg.content
    if msg.source_file != 'motion-attest' or not isinstance(c, dict) or c.get('type') != 'attestation':
        return None
    return {k: c.get(k, '') for k in ('signed', 'signature', 'key', 'namespace')}


def turn_payload(msg, text, mentionable=()):
    return {
        'attested': attestation_of(msg),
        **how_payload(msg),
        'id': str(msg.id),
        'sender': msg.sender_id,
        'is_human': bool(getattr(getattr(msg.sender, 'thinkingentity', None),
                                 'is_biological_human', False)),
        'created_at': msg.created_at.isoformat(),
        # Typed into the web composer rather than a runtime session: nobody
        # live is listening for it, so the poller need not wait.
        'via': 'web' if msg.source_file in POSTED else 'session',
        'text': text,
        'mentions': mentions_in(text, mentionable),
        'html': render_html(text, mentionable),
    }


# --- activity: what an agent is doing right now ------------------------------

TURN_ENDS = {'end_turn', 'refusal', 'stop_sequence', 'max_tokens'}
ACTIVITY_WINDOW = 600  # seconds; a streak older than this is a session that died
RECENT = 60  # rows read to see what's happening now
_TOOL_WORDS = {
    'Bash': 'running a command', 'Read': 'reading', 'Grep': 'searching', 'Glob': 'searching',
    'Edit': 'editing', 'Write': 'writing a file', 'NotebookEdit': 'editing',
    'WebFetch': 'reading the web', 'WebSearch': 'searching the web',
    'Agent': 'working with helpers', 'Task': 'working with helpers',
    'ToolSearch': 'finding a tool', 'Skill': 'reading up', 'TodoWrite': 'planning',
}
_MCP_WORDS = {'playwright': 'using the browser', 'pickipedia': 'on PickiPedia',
              'magenta-memory-v2': 'remembering', 'magenta-memory': 'remembering'}


def _doing(msg):
    """A few words for what a machinery message says the agent is doing."""
    if hasattr(msg, 'tooluse'):
        name = msg.tooluse.tool_name
        if name.startswith('mcp__'):
            server = name.split('__')[1]
            return _MCP_WORDS.get(server, f'using {server}')
        return _TOOL_WORDS.get(name, f'using {name}')
    return 'thinking'


def _when(msg):
    return msg.timestamp / 1000 if msg.timestamp else msg.created_at.timestamp()


# --- how full an agent's context is ------------------------------------------
# Every assistant line records what its model read to write it: fresh input
# plus cache reads and writes. The newest such line in a Motion's newest
# session is how full that agent's context is now -- what a wake would
# resume into. Windows by model; the record shows Opus 5.5 sessions passing
# 865k tokens, so its window is 1M. Anything unlisted is taken as 200k,
# and a session seen past its window is taken to have the larger one.
CONTEXT_WINDOWS = (('claude-opus-5', 1_000_000),)
DEFAULT_WINDOW = 200_000


def context_window(model, tokens=0):
    window = next((w for prefix, w in CONTEXT_WINDOWS if (model or '').startswith(prefix)), DEFAULT_WINDOW)
    return window if tokens <= window else max(window, 1_000_000)


def context_in(motion, agent):
    """{'tokens', 'window', 'model', 'at'} for `agent`'s context here, or None."""
    # A slash command's output (/context, /usage) is a "<synthetic>" message
    # (stored with no model) that read nothing: it says nothing about the context.
    row = (motion.messages.filter(sender_id=agent, is_sidechain=False, input_tokens__isnull=False,
                                  model_backend__isnull=False)
           .order_by('-created_at')
           .values('input_tokens', 'cache_creation_input_tokens', 'cache_read_input_tokens', 'model_backend',
                   'created_at').first())
    if row is None:
        return None
    tokens = sum(row[k] or 0 for k in ('input_tokens', 'cache_creation_input_tokens', 'cache_read_input_tokens'))
    window = context_window(row['model_backend'], tokens)
    # Compacted since (`@magent /compact`): no turn has measured the context
    # yet, so it is about the summary's size until the next one does.
    summary = compacted_since(motion, agent, row['created_at'])
    if summary is not None:
        return {'tokens': len(summary.text) // CHARS_PER_TOKEN, 'window': window, 'model': row['model_backend'] or '',
                'at': summary.at.isoformat(), 'compacted': True}
    return {'tokens': tokens, 'window': window, 'model': row['model_backend'] or '', 'at': row['created_at'].isoformat()}


CHARS_PER_TOKEN = 4  # roughly, for English prose


class _Summary:
    def __init__(self, text, at):
        self.text, self.at = text, at


def compacted_since(motion, agent, when):
    """The summary `agent`'s context went on from, if it was compacted after
    `when` (its last measured turn); else None. What follows a summary
    before the next turn is only the command's own echo."""
    for row in (motion.messages.filter(sender_id=agent, is_sidechain=False, created_at__gt=when)
                .order_by('-created_at').values('content', 'created_at')[:20]):
        content = row['content']
        if isinstance(content, list):
            content = ' '.join(b.get('text', '') for b in content if isinstance(b, dict) and b.get('type') == 'text')
        if isinstance(content, str) and is_compaction(content):
            return _Summary(content, row['created_at'])
    return None


# --- a mention the runner is holding ----------------------------------------
# The record can show that a post names an agent and nothing has answered it,
# but not why: a runner may be holding it -- its hourly cap reached, the
# agent hushed here, a turn already under way. The runner says so, and the
# Motion shows "held" instead of an endless "waking". Ephemeral, like typing:
# a shared cache entry per Motion, agent -> {reason, until, at}, which lapses
# unless the runner renews it, so a runner that dies leaves no stale hold.
HELD_FOR = 600  # seconds a hold lasts unless renewed


def _held_key(slug):
    return f'held:{slug}'


def held_in(slug, now=None):
    """agent -> {'reason', 'until', 'at'} for each hold still in force."""
    from django.core.cache import cache
    import time
    now = now or time.time()
    return {agent: h for agent, h in (cache.get(_held_key(slug)) or {}).items() if now - h['at'] < HELD_FOR}


def set_held(slug, agent, reason, until=None, now=None):
    """Hold `agent`'s next turn in `slug` for `reason`; an empty reason lifts it."""
    from django.core.cache import cache
    import time
    now = now or time.time()
    holds = held_in(slug, now)
    if reason:
        holds[agent] = {'reason': reason, 'until': until, 'at': now}
    else:
        holds.pop(agent, None)
    cache.set(_held_key(slug), holds, HELD_FOR)
    return holds


def activity(motion, now=None):
    """What an agent in this Motion is doing now, or None: see _activity.
    Someone stopping the agent since that began ends it at once, without
    waiting for its runner to notice."""
    doing = _activity(motion, now)
    if doing and doing['doing'] != 'held':
        stopped = latest_interrupt(motion, doing['agent'])
        if stopped and stopped['at_ts'] >= doing['since']:
            return None
    return doing


def latest_interrupt(motion, agent=None):
    """{'agent', 'by', 'at', 'at_ts'} for the newest time someone stopped
    `agent` (any agent, if None) here; None if nobody ever has."""
    for msg in (motion.messages.filter(source_file=INTERRUPT_SOURCE).order_by('-created_at')
                .only('content', 'timestamp', 'created_at')[:20]):
        c = msg.content if isinstance(msg.content, dict) else {}
        if agent is None or c.get('agent') == agent:
            at = _when(msg)
            from datetime import datetime, timezone as tz
            return {'agent': c.get('agent'), 'by': c.get('by'), 'at_ts': at,
                    'at': datetime.fromtimestamp(at, tz.utc).isoformat()}
    return None


def _activity(motion, now=None):
    """What an agent in this Motion is doing now, or None if nothing is underway.

    Read straight from the record, so no process has to report in: every
    thought, tool call and prompt streams into the Motion as it happens, and
    an assistant line whose stop_reason is end_turn closes the turn. So an
    agent is working from the first line after its last finished turn until
    the next one, and the newest line says what it's doing. A web post that
    names an agent and has nothing after it means the agent is being woken,
    unless its runner has said it is holding that turn, and why.
    """
    from conversations.models import ThinkingEntity
    import time

    now = now or time.time()
    agents = set(ThinkingEntity.objects.filter(is_biological_human=False).values_list('name', flat=True))
    # Helpers' lines (sidechains) are the agent's own call still running, so
    # they neither describe nor end its turn. System lines are the harness's
    # bookkeeping -- Claude Code writes one just after a turn ends -- and
    # say nothing about whether anyone is working.
    recent = list(motion.messages.filter(is_sidechain=False).exclude(sender_id='system')
                  .select_related('sender', 'tooluse', 'thought', 'toolresult')
                  .order_by('-created_at')[:RECENT])
    if not recent:
        return None
    newest = recent[0]

    if newest.source_file in POSTED:
        named = [n for n in mentions_in(prose(newest.content), agents)]
        if not named:
            return None
        # Held only if the runner said so after this post: a newer post is
        # waking until the runner has looked at it. A hold is shown for as
        # long as the runner keeps it -- an hour, at the hourly cap -- not
        # just the window an unexplained wait is shown for.
        hold = held_in(motion.slug, now).get(named[0])
        if hold and hold['at'] >= _when(newest):
            return {'agent': named[0], 'doing': 'held', 'why': hold['reason'], 'until': hold.get('until'),
                    'since': _when(newest)}
        if now - _when(newest) > ACTIVITY_WINDOW:
            return None
        return {'agent': named[0], 'doing': 'waking', 'since': _when(newest)}

    if now - _when(newest) > ACTIVITY_WINDOW:
        return None
    if newest.sender_id in agents and newest.stop_reason in TURN_ENDS:
        return None
    # Rows imported before stop_reason was kept: a plain reply that has sat
    # for half a minute with nothing after it is taken as the end of a turn.
    if (newest.sender_id in agents and newest.stop_reason is None and now - _when(newest) > 30
            and not hasattr(newest, 'tooluse') and not hasattr(newest, 'thought')):
        return None

    streak = []
    for msg in recent:
        if msg.sender_id in agents and msg.stop_reason in TURN_ENDS:
            break
        if msg.source_file in POSTED:
            break
        streak.append(msg)
    agent = next((m.sender_id for m in streak if m.sender_id in agents), None) or sorted(agents or {'magent'})[0]
    how = next((how_payload(m) for m in streak if m.sender_id in agents and m.model_backend), {'model': '', 'effort': ''})
    start = streak[-1]
    if len(streak) == len(recent) == RECENT:
        # A long turn runs past the rows read above: find where it began.
        from django.db.models import Q
        mine = motion.messages.filter(is_sidechain=False)
        boundary = (mine.filter(created_at__lt=start.created_at)
                    .filter(Q(sender_id__in=agents, stop_reason__in=TURN_ENDS) | Q(source_file__in=POSTED))
                    .order_by('-created_at').first())
        if boundary is not None:
            start = mine.filter(created_at__gt=boundary.created_at).order_by('created_at').first() or start
    return {'agent': agent, 'doing': _doing(newest), 'since': _when(start), **{k: v for k, v in how.items() if v}}


# --- background tasks an agent is supervising ------------------------------

_TASK_STARTED = re.compile(r'Command running in background with ID: (\w+)|Async agent launched successfully.*?agentId: (\w+)', re.S)
_TASK_ENDED = re.compile(r'<task-id>(\w+)</task-id>.*?<status>(\w+)</status>', re.S)
TASK_ENDINGS = {'completed', 'failed', 'stopped', 'killed', 'error', 'cancelled'}
# A task older than this with no word of its end is presumed gone: its notice
# can be lost when the session that started it exits first. A background
# command can't outlive Claude Code's two-hour cap on its timeout; a helper
# agent has no cap, so it gets longer.
TASK_HORIZONS = {'command': 2.5 * 3600, 'helper': 12 * 3600}
TASK_HORIZON = max(TASK_HORIZONS.values())


def background_tasks(motion, now=None):
    """Commands and helpers an agent started in the background here and that
    haven't ended, read from the record: the tool result that started each
    one, and the <task-notification> that says it ended.
    """
    import json
    import time
    from datetime import datetime, timezone as tz
    from conversations.models import ToolResult, ToolUse

    now = now or time.time()
    since = datetime.fromtimestamp(now - TASK_HORIZON, tz.utc)
    rows = (motion.messages.filter(is_sidechain=False, created_at__gte=since)
            .filter(models_q(content__icontains='in background with ID')
                    | models_q(content__icontains='Async agent launched')
                    | models_q(content__icontains='<task-id>'))
            .order_by('created_at'))
    started, ended = {}, set()
    for msg in rows:
        text = msg.content if isinstance(msg.content, str) else json.dumps(msg.content)
        # Only a tool result that *is* a start message starts a task, and only
        # a notification ends one: output that merely quotes them (a log, a
        # query of this very table) is neither.
        if not hasattr(msg, 'toolresult'):
            for match in _TASK_ENDED.finditer(text):
                if match.group(2).lower() in TASK_ENDINGS:
                    ended.add(match.group(1))
            continue
        match = _TASK_STARTED.match(text.lstrip())
        if not match:
            continue
        task_id = match.group(1) or match.group(2)
        ended.discard(task_id)  # a helper resumed after it last finished
        use = (ToolUse.objects.filter(tool_id=msg.toolresult.tool_use_id, session_id=msg.session_id)
               .only('content', 'tool_name').first())
        args = use.content if use is not None and isinstance(use.content, dict) else {}
        started[task_id] = {
            'id': task_id,
            'kind': 'helper' if match.group(2) else 'command',
            'label': (args.get('description') or args.get('command') or args.get('prompt') or task_id)[:120],
            'since': _when(msg),
        }
    return [task for task_id, task in started.items()
            if task_id not in ended and task['since'] >= now - TASK_HORIZONS[task['kind']]]


def models_q(**kwargs):
    from django.db.models import Q
    return Q(**kwargs)


def motion_payload(motion):
    from django.db.models import Max
    # What was said, not the system's own rows (a redeploy announced in every
    # Mood, a rename, a turn's tally): those mustn't make a Mood look active.
    said = motion.messages.exclude(sender_id='system')
    last = said.aggregate(last=Max('created_at'))['last']
    return {
        'slug': motion.slug,
        'title': motion.title or motion.slug,
        'description': motion.description,
        'eth_blockheight': motion.eth_blockheight,
        'message_count': said.count(),
        'last_at': last.isoformat() if last else None,
        'participants': sorted(e.name for e in motion.thinking_entities()),
    }
