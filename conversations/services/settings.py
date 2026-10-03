"""Knobs: how each agent carries itself in each Motion.

A casual Motion and a focused one want different things from an agent --
how readily it speaks up, how hard it thinks, what it should keep in mind
there. So every knob can be set for one agent in one Motion, for one agent
everywhere, for every agent in one Motion, or for all; the most specific
setting wins:

    (motion, agent) > (motion, every agent) > (every Motion, agent) > (all) > default

Settings are rows (models.Setting), only ever added: the newest row for a
slot is in force, the rest are its history -- who changed what, when, and
why. The runner reads the resolved values every few seconds, in the pulse.

Moderation keys (the scram, bans) are set only by an admin's signed
request (views_admin.py), never through the settings page.
"""

import re
from datetime import datetime, timezone

EFFORTS = ('low', 'medium', 'high', 'xhigh', 'max')
LISTENING = ('on', 'mentions', 'off')

# key: (default, help). Validation per key is in clean().
KNOBS = {
    'listening': ({'mode': 'on', 'until': None},
                  "on: answers mentions and may speak up unasked. mentions: answers mentions only. "
                  "off: wakes for nothing; mentions wait until it's back on. With an 'until', it goes "
                  "back on by itself then, and catches up on what it missed."),
    'consider_after': (10, 'Seconds of quiet (and nobody typing) before it considers new posts.'),
    'idle_after': (3000, 'Seconds of silence before its first unprompted look; doubles after each silent '
                         'one. 0: never.'),
    'considers_per_hour': (6, 'At most this many full considerations an hour, here.'),
    'mention_effort': ('high', 'How hard it thinks when someone @mentions it.'),
    'consider_effort': ('medium', 'How hard it thinks when it decides whether to speak up.'),
    'model': ('', "Which model it runs on here: 'opus', 'sonnet', 'fable', 'haiku', or a full name. "
                  "Empty: its harness's default."),
    'catch_up_tokens': (10_000, "How much of what was said here since it last spoke a wake reads word for word, "
                                "in tokens (about 4 characters each); what's older is summarized. A post that links "
                                "a message has it read from that message on."),
    'rules': ('', 'How it should carry itself here, in a few lines. It reads this at every wake.'),
    'ultracode': (False, "Its full-tools mention wakes here run with Claude Code's ultracode on: standing "
                         "multi-agent workflows, at any effort. Thorough, and costly."),
}
GLOBAL_KNOBS = {
    'consider_usd_per_day': (10.0, 'Dollars a day across screens and considerations (mentions not counted).'),
}
MODERATION_KEYS = ('scram', 'banned')


class Invalid(ValueError):
    pass


def default(key):
    return (KNOBS.get(key) or GLOBAL_KNOBS.get(key) or (None,))[0]


def clean(key, value):
    """The value as stored, or Invalid."""
    if key == 'listening':
        if isinstance(value, str):
            value = {'mode': value, 'until': None}
        if not isinstance(value, dict) or value.get('mode') not in LISTENING:
            raise Invalid(f"listening: one of {', '.join(LISTENING)}")
        until = value.get('until')
        if until:
            try:
                parsed = datetime.fromisoformat(str(until).replace('Z', '+00:00'))
            except ValueError:
                raise Invalid('listening.until: an ISO date and time')
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            until = parsed.isoformat()
        return {'mode': value['mode'], 'until': until or None}
    if key in ('consider_after', 'idle_after', 'considers_per_hour', 'catch_up_tokens'):
        limits = {'consider_after': (0, 3600), 'idle_after': (0, 7 * 86400), 'considers_per_hour': (0, 60),
                  'catch_up_tokens': (1000, 24000)}[key]
        try:
            value = int(value)
        except (TypeError, ValueError):
            raise Invalid(f'{key}: a whole number')
        if not limits[0] <= value <= limits[1]:
            raise Invalid(f'{key}: from {limits[0]} to {limits[1]}')
        return value
    if key in ('mention_effort', 'consider_effort'):
        if value not in EFFORTS:
            raise Invalid(f"{key}: one of {', '.join(EFFORTS)}")
        return value
    if key == 'model':
        value = str(value or '').strip()
        if not re.fullmatch(r'[a-z0-9.\-]{0,60}', value):
            raise Invalid('model: letters, digits, dots and dashes')
        return value
    if key == 'ultracode':
        if value in (True, False):
            return value
        if str(value).lower() in ('true', 'on', '1', 'yes'):
            return True
        if str(value).lower() in ('false', 'off', '0', 'no', ''):
            return False
        raise Invalid('ultracode: on or off')
    if key == 'rules':
        value = str(value or '').strip()
        if len(value) > 4000:
            raise Invalid('rules: at most 4000 characters')
        return value
    if key == 'consider_usd_per_day':
        try:
            value = round(float(value), 2)
        except (TypeError, ValueError):
            raise Invalid('consider_usd_per_day: a number')
        if not 0 <= value <= 500:
            raise Invalid('consider_usd_per_day: from 0 to 500')
        return value
    raise Invalid(f'no such setting: {key}')


def latest(rows):
    """{(motion_id, agent_id, key): row}, the newest row per slot."""
    current = {}
    for row in sorted(rows, key=lambda r: r.created_at):
        current[(row.motion_id, row.agent_id, row.key)] = row
    return current


def resolve(motion, agent, now=None, rows=None):
    """The settings in force for `agent` in `motion` (either may be None for 'every')."""
    from conversations.models import Setting
    now = now or datetime.now(timezone.utc)
    if rows is None:
        rows = Setting.objects.filter(key__in=list(KNOBS)).exclude(key__in=MODERATION_KEYS)
    current = latest(rows)
    motion_id = getattr(motion, 'pk', motion)
    agent_id = getattr(agent, 'pk', agent)
    resolved = {}
    for key, (fallback, _) in KNOBS.items():
        value = fallback
        for slot in ((motion_id, agent_id), (motion_id, None), (None, agent_id), (None, None)):
            row = current.get((*slot, key))
            if row is not None:
                value = row.value
                break
        resolved[key] = value
    listening = resolved['listening']
    if listening.get('until'):
        until = datetime.fromisoformat(listening['until'])
        if until <= now:
            resolved['listening'] = {'mode': 'on', 'until': None}  # its time is up
    return resolved


def global_value(key):
    from conversations.models import Setting
    row = Setting.objects.filter(key=key, motion=None, agent=None).order_by('-created_at').first()
    return row.value if row is not None else default(key)


def scram():
    """The scram in force, or None: {'by': ..., 'at': ..., 'note': ...}."""
    from conversations.models import Setting
    row = Setting.objects.filter(key='scram', motion=None, agent=None).order_by('-created_at').first()
    if row is None or not row.value:
        return None
    return {'by': row.set_by_id, 'at': row.created_at.isoformat(), 'note': row.note}


def banned(name):
    from conversations.models import Setting
    row = Setting.objects.filter(key='banned', motion=None, agent_id=name).order_by('-created_at').first()
    return bool(row and row.value)


def change(key, value, motion=None, agent=None, by=None, note=''):
    """Record a setting (a new row; nothing is overwritten)."""
    from conversations.models import Setting
    if key in MODERATION_KEYS:
        raise Invalid(f'{key} is set only by an admin, with their key')
    if key in GLOBAL_KNOBS and (motion is not None or agent is not None):
        raise Invalid(f'{key} applies everywhere at once')
    return Setting.objects.create(motion=motion, agent=agent, key=key, value=clean(key, value), set_by=by,
                                  note=str(note or '')[:200])


def describe(row):
    return {
        'motion': row.motion_id, 'agent': row.agent_id, 'key': row.key, 'value': row.value,
        'set_by': row.set_by_id, 'note': row.note, 'at': row.created_at.isoformat(),
    }
