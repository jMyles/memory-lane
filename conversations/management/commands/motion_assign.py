"""Open a Motion and attach existing messages to it.

The corpus predates Motions, so conversation is attached deliberately rather
than guessed at. The only handle available today is the Claude Code session,
which is a runtime instance rather than a subject, so a Motion may need
several sessions attached. Repeatable and idempotent.
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from conversations.models import Message, Motion


class Command(BaseCommand):
    help = "Open a Motion (if needed) and attach messages from sessions to it."

    def add_arguments(self, parser):
        parser.add_argument('slug', help='Stable key, e.g. delivery-kid')
        parser.add_argument('--session', action='append', default=[], metavar='UUID',
                            help='Session whose messages belong to this Motion (repeatable)')
        parser.add_argument('--title', default='', help='Human-facing title')
        parser.add_argument('--description', default='', help='What this Motion is for')
        parser.add_argument('--block', type=int, help='Block height at which it was opened')
        parser.add_argument('--reassign', action='store_true',
                            help='Also move messages already attached to another Motion')
        parser.add_argument('--dry-run', action='store_true',
                            help='Report what would change and write nothing')

    @transaction.atomic
    def handle(self, *args, **options):
        slug = options['slug']
        sessions = options['session']
        dry_run = options['dry_run']

        motion, created = Motion.objects.get_or_create(slug=slug)
        for field in ('title', 'description'):
            if options[field]:
                setattr(motion, field, options[field])
        if options['block']:
            motion.eth_blockheight = options['block']
        if not dry_run:
            motion.save()

        self.stdout.write(f"{'Opened' if created else 'Found'} Motion '{slug}'")

        total = 0
        for session in sessions:
            candidates = Message.objects.filter(session_id=session)
            if not candidates.exists():
                raise CommandError(f"No messages for session {session}")

            targets = candidates if options['reassign'] else candidates.filter(motion__isnull=True)
            already = candidates.filter(motion=motion).count()
            count = targets.exclude(motion=motion).count()

            if not dry_run:
                targets.update(motion=motion)

            total += count
            note = f" ({already} already attached)" if already else ""
            self.stdout.write(f"  {session}: {count} messages{note}")

        verb = 'would attach' if dry_run else 'attached'
        self.stdout.write(self.style.SUCCESS(f"{verb} {total} messages to '{slug}'"))

        if dry_run:
            transaction.set_rollback(True)
