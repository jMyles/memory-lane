"""Tests for Motions: the subject a conversation belongs to."""

import uuid
from io import StringIO

from django.core.management import CommandError, call_command
from django.test import TestCase

from conversations.models import (
    ContextHeap, ContextHeapType, ConversationParticipant, Era, Message,
    Motion, ThinkingEntity,
)


class MotionModelTest(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.justin = ThinkingEntity.objects.create(name="justin", is_biological_human=True)
        cls.magent = ThinkingEntity.objects.create(name="magent", is_biological_human=False)
        cls.tool = ConversationParticipant.objects.create(name="tool-result")

        cls.era = Era.objects.create(name="Test Era")
        cls.heap_a = ContextHeap.objects.create(era=cls.era, type=ContextHeapType.FRESH)
        cls.heap_b = ContextHeap.objects.create(era=cls.era, type=ContextHeapType.POST_COMPACTING)

        cls.motion = Motion.objects.create(slug="delivery-kid", title="Delivery Kid")

        # One Motion spanning two heaps: heaps mark where context filled up,
        # the Motion marks what the conversation was about.
        for heap, sender, block in (
            (cls.heap_a, cls.justin, 25_900_000),
            (cls.heap_a, cls.magent, 25_900_010),
            (cls.heap_b, cls.magent, 25_990_000),
            (cls.heap_b, cls.tool, None),
        ):
            Message.objects.create(
                id=uuid.uuid4(), sender=sender, content="x",
                context_heap=heap, motion=cls.motion, eth_blockheight=block,
            )

        # Unattached message, from before Motions existed.
        Message.objects.create(id=uuid.uuid4(), sender=cls.justin, content="older")

    def test_motion_spans_context_heaps(self):
        heaps = {m.context_heap_id for m in self.motion.messages.all()}
        self.assertEqual(heaps, {self.heap_a.id, self.heap_b.id})

    def test_messages_may_have_no_motion(self):
        self.assertEqual(Message.objects.filter(motion__isnull=True).count(), 1)

    def test_blockheight_span(self):
        self.assertEqual(self.motion.earliest_blockheight(), 25_900_000)
        self.assertEqual(self.motion.latest_blockheight(), 25_990_000)

    def test_thinking_entities_excludes_tools(self):
        names = sorted(e.name for e in self.motion.thinking_entities())
        self.assertEqual(names, ["justin", "magent"])

    def test_retiring_a_motion_keeps_its_messages(self):
        self.motion.delete()
        self.assertEqual(Message.objects.count(), 5)
        self.assertEqual(Message.objects.filter(motion__isnull=True).count(), 5)

    def test_str_prefers_title(self):
        self.assertEqual(str(self.motion), "Delivery Kid")
        self.assertEqual(str(Motion.objects.create(slug="untitled")), "untitled")


class MotionAssignCommandTest(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.justin = ThinkingEntity.objects.create(name="justin", is_biological_human=True)
        cls.session_one = uuid.uuid4()
        cls.session_two = uuid.uuid4()
        for session in (cls.session_one, cls.session_two):
            for _ in range(3):
                Message.objects.create(
                    id=uuid.uuid4(), sender=cls.justin, content="x", session_id=session,
                )

    def run_command(self, *args, **kwargs):
        out = StringIO()
        call_command('motion_assign', *args, stdout=out, **kwargs)
        return out.getvalue()

    def test_opens_motion_and_attaches_several_sessions(self):
        # A Motion outlives any one session, so it takes more than one.
        self.run_command('paseo', '--session', str(self.session_one),
                         '--session', str(self.session_two), '--title', 'Paseo')
        motion = Motion.objects.get(slug='paseo')
        self.assertEqual(motion.title, 'Paseo')
        self.assertEqual(motion.messages.count(), 6)

    def test_dry_run_writes_nothing(self):
        output = self.run_command('paseo', '--session', str(self.session_one), dry_run=True)
        self.assertIn('would attach 3', output)
        self.assertFalse(Motion.objects.filter(slug='paseo').exists())
        self.assertEqual(Message.objects.filter(motion__isnull=False).count(), 0)

    def test_rerunning_is_idempotent(self):
        self.run_command('paseo', '--session', str(self.session_one))
        output = self.run_command('paseo', '--session', str(self.session_one))
        self.assertIn('already attached', output)
        self.assertEqual(Motion.objects.get(slug='paseo').messages.count(), 3)

    def test_will_not_steal_from_another_motion_without_reassign(self):
        self.run_command('paseo', '--session', str(self.session_one))
        self.run_command('motions', '--session', str(self.session_one))
        self.assertEqual(Motion.objects.get(slug='paseo').messages.count(), 3)
        self.assertEqual(Motion.objects.get(slug='motions').messages.count(), 0)

        self.run_command('motions', '--session', str(self.session_one), '--reassign')
        self.assertEqual(Motion.objects.get(slug='motions').messages.count(), 3)
        self.assertEqual(Motion.objects.get(slug='paseo').messages.count(), 0)

    def test_unknown_session_is_an_error(self):
        with self.assertRaises(CommandError):
            self.run_command('paseo', '--session', str(uuid.uuid4()))
