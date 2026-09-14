"""
Tests for thread listing and thread-scoped recall.

The fixture reproduces the failure these tools exist to fix: two unrelated
threads whose messages interleave in time, so a flat chronological read
presents them as one stream.
"""

import json
import uuid
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from conversations.models import ConversationParticipant, Message, ThinkingEntity
from conversations.services import MemoryService
from conversations.services.memory import _text_of


class ListThreadsTest(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.justin = ThinkingEntity.objects.create(name="justin", is_biological_human=True)
        cls.skyler = ThinkingEntity.objects.create(name="skyler", is_biological_human=True)
        cls.magent = ThinkingEntity.objects.create(name="magent", is_biological_human=False)
        cls.tool = ConversationParticipant.objects.create(name="tool-result")

        cls.paseo = uuid.uuid4()
        cls.podcast = uuid.uuid4()
        cls.base = timezone.now() - timedelta(hours=1)

        # Interleaved: paseo, podcast, paseo, podcast ... podcast is active last.
        script = [
            (cls.paseo, cls.justin, "reawaken magent", "/home/magent", "main"),
            (cls.podcast, cls.skyler, "<command-name>/clear</command-name>", "/home/magent/workspace/pickipedia", "topic-split"),
            (cls.paseo, cls.magent, "I'll find the reawakening instructions.", "/home/magent", "main"),
            (cls.podcast, cls.skyler, json.dumps([{"type": "text", "text": "The   podcast titles\nstutter."}]), "/home/magent/workspace/pickipedia", "topic-split"),
            (cls.paseo, cls.tool, "exit code 0", "/home/magent", "main"),
            (cls.paseo, cls.justin, "Look at getpaseo/paseo for a web interface.", "/home/magent/workspace/maybelle-config", "paseo-daemon"),
            (cls.podcast, cls.magent, "Titles fixed.", "/home/magent/workspace/pickipedia", "topic-split"),
        ]
        for minute, (session, sender, content, cwd, branch) in enumerate(script):
            msg = Message.objects.create(
                id=uuid.uuid4(), sender=sender, content=content,
                session_id=session, cwd=cwd, git_branch=branch,
            )
            # created_at is auto_now_add, so set the timeline explicitly.
            Message.objects.filter(id=msg.id).update(created_at=cls.base + timedelta(minutes=minute))

        # A message with no session_id must not become a phantom thread.
        Message.objects.create(id=uuid.uuid4(), sender=cls.justin, content="imported markdown, no session")

    def threads_by_id(self, **kwargs):
        return {t['thread_id']: t for t in MemoryService.list_threads(**kwargs)}

    def test_interleaved_messages_separate_into_threads(self):
        threads = self.threads_by_id()
        self.assertEqual(set(threads), {str(self.paseo), str(self.podcast)})
        self.assertEqual(threads[str(self.paseo)]['message_count'], 4)
        self.assertEqual(threads[str(self.podcast)]['message_count'], 3)

    def test_most_recently_active_first(self):
        order = [t['thread_id'] for t in MemoryService.list_threads()]
        self.assertEqual(order, [str(self.podcast), str(self.paseo)])

    def test_participants_are_thinking_entities_only(self):
        threads = self.threads_by_id()
        self.assertEqual(threads[str(self.paseo)]['participants'], ['justin', 'magent'])
        self.assertNotIn('tool-result', threads[str(self.paseo)]['participants'])

    def test_title_hint_skips_reawaken_and_wrapper_prompts(self):
        threads = self.threads_by_id()
        self.assertEqual(threads[str(self.paseo)]['title_hint'], "Look at getpaseo/paseo for a web interface.")
        # JSON-encoded blocks are unwrapped and whitespace collapsed.
        self.assertEqual(threads[str(self.podcast)]['title_hint'], "The podcast titles stutter.")

    def test_cwd_reflects_where_the_thread_is_now(self):
        paseo = self.threads_by_id()[str(self.paseo)]
        self.assertEqual(paseo['cwd'], "/home/magent/workspace/maybelle-config")
        self.assertEqual(paseo['git_branch'], "paseo-daemon")

    def test_since_excludes_threads_quiet_before_it(self):
        # Paseo's last message is minute 5; podcast's is minute 6.
        threads = self.threads_by_id(since=self.base + timedelta(minutes=6))
        self.assertEqual(set(threads), {str(self.podcast)})

    def test_limit(self):
        self.assertEqual(len(MemoryService.list_threads(limit=1)), 1)

    def test_recent_work_scoped_to_one_thread(self):
        scoped = MemoryService.get_recent_work(limit=50, session_id=self.paseo)
        self.assertEqual(len(scoped), 4)
        self.assertTrue(all(m.session_id == self.paseo for m in scoped))

    def test_recent_work_unscoped_is_unchanged(self):
        self.assertEqual(len(MemoryService.get_recent_work(limit=50)), 8)


class TextOfTest(TestCase):

    def test_shapes(self):
        self.assertEqual(_text_of("plain"), "plain")
        self.assertEqual(_text_of({"text": "untyped block"}), "untyped block")
        self.assertEqual(_text_of([{"type": "text", "text": "a"}, {"type": "tool_use", "name": "Bash"}]), "a")
        self.assertEqual(_text_of('[{"type": "text", "text": "encoded"}]'), "encoded")
        # Prose that merely starts with a bracket is not JSON and must survive.
        self.assertEqual(_text_of("[justin] said hello"), "[justin] said hello")
        self.assertEqual(_text_of(None), "")
