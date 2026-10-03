"""Notices (mentions, answers), recent changes, search, and the rules page."""

import time
import uuid

from django.test import TestCase

from conversations.models import ConversationParticipant, Message, Motion, ThinkingEntity, ToolUse
from conversations.services import settings as knobs


class NoticesTest(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.justin = ThinkingEntity.objects.create(name='justin', is_biological_human=True)
        cls.skyler = ThinkingEntity.objects.create(name='skyler', is_biological_human=True)
        cls.magent = ThinkingEntity.objects.create(name='magent', is_biological_human=False)
        cls.m26 = Motion.objects.create(slug='m26', title='Magenta 26 Million')
        cls.dk = Motion.objects.create(slug='delivery-kid', title='delivery-kid')

    def add(self, sender, content, motion=None, seconds=0, model=Message, **fields):
        return model.objects.create(id=uuid.uuid4(), sender=sender, motion=motion or self.m26, content=content,
                                    timestamp=int((time.time() + seconds) * 1000), **fields)

    def notices(self, name='justin'):
        return self.client.get(f'/api/notices/{name}/').json()['notices']

    def test_an_answer_is_the_agents_finished_turn_after_your_words(self):
        self.add(self.justin, '@magent what time is soundcheck?', seconds=1, source_file='motion-web')
        self.add(self.magent, [{'type': 'text', 'text': 'Checking the schedule:'}], seconds=2, stop_reason='tool_use')
        self.add(self.magent, [{'type': 'text', 'text': 'Soundcheck is at 5.'}], seconds=3, stop_reason='end_turn')
        found = self.notices()
        self.assertEqual([(n['kind'], n['turn']['text']) for n in found], [('answer', 'Soundcheck is at 5.')])
        self.assertEqual(self.notices('skyler'), [])  # skyler didn't ask

    def test_the_last_person_to_speak_is_the_one_answered(self):
        self.add(self.justin, 'first', seconds=1)
        self.add(self.skyler, '@magent and mine?', seconds=2)
        self.add(self.magent, [{'type': 'text', 'text': 'Yours, Sky.'}], seconds=3, stop_reason='end_turn')
        self.assertEqual(self.notices('justin'), [])
        self.assertEqual([n['kind'] for n in self.notices('skyler')], ['answer'])

    def test_a_mention_by_someone_else_but_not_your_own_or_a_silence(self):
        self.add(self.skyler, '@justin bring the capo', motion=self.dk, seconds=1)
        self.add(self.justin, '@justin note to self', seconds=2)
        self.add(self.magent, [{'type': 'text', 'text': '<silent>not for me</silent>'}], seconds=3, stop_reason='end_turn')
        found = self.notices()
        self.assertEqual([(n['kind'], n['motion']) for n in found], [('mention', 'delivery-kid')])

    def test_recent_changes_mix_what_was_said_renames_and_settings(self):
        self.add(self.justin, 'hello there', seconds=1)
        self.add(self.magent, [{'type': 'text', 'text': 'Working on it:'}], seconds=2, stop_reason='tool_use')
        self.add(self.magent, [{'type': 'text', 'text': 'Done.'}], seconds=3, stop_reason='end_turn')
        knobs.change('mention_effort', 'max', motion=self.m26, agent=self.magent, by=self.justin)
        events = self.client.get('/api/motions/recent/').json()['events']
        kinds = [e['kind'] for e in events]
        self.assertIn('said', kinds)
        self.assertIn('answered', kinds)
        self.assertIn('set', kinds)
        self.assertNotIn('Working on it:', [e.get('text') for e in events])  # progress lines are left out
        self.assertEqual(next(e for e in events if e['kind'] == 'said')['title'], 'Magenta 26 Million')

    def test_search_finds_what_was_said_here_or_anywhere(self):
        self.add(self.justin, 'Who has the CAPO tonight?', seconds=1)
        self.add(self.skyler, 'the capo is in the van', motion=self.dk, seconds=2)
        self.add(self.magent, {'command': 'grep capo notes.txt'}, model=ToolUse, tool_name='Bash', tool_id='t1', seconds=3)
        everywhere = self.client.get('/api/search/?q=capo').json()['hits']
        self.assertEqual(sorted(h['motion'] for h in everywhere), ['delivery-kid', 'm26'])  # no tool calls
        here = self.client.get('/api/search/?q=capo&motion=m26').json()['hits']
        self.assertEqual([h['text'] for h in here], ['Who has the CAPO tonight?'])
        self.assertEqual(self.client.get('/api/search/?q=c').status_code, 400)

    def test_the_rules_page_shows_what_each_wake_says_and_this_moods_rules(self):
        knobs.change('rules', 'Keep it short after midnight.', motion=self.m26, agent=self.magent, by=self.justin)
        page = self.client.get('/motions/m26/rules/').content.decode()
        self.assertIn('Keep it short after midnight.', page)
        for title in ('full tools', 'look, not touch', 'nobody asks it', 'quiet a long while', 'The screen'):
            self.assertIn(title, page)
        self.assertIn('&lt;silent&gt;a few words on why&lt;/silent&gt;', page)  # the wake's own words, escaped


class WakeFramesTest(TestCase):
    """The rules page and the poller say the same thing: one source."""

    def test_the_frames_are_built_from_what_the_poller_sends(self):
        from poller.motion_poller import CONSIDER_ASK, rules_block, wake_footer, wake_frames
        frames = {f['kind']: f['text'] for f in wake_frames('m26', rules='Be brief.')}
        self.assertTrue(frames['mention-full'].endswith('\n'.join(wake_footer(full=True))))
        self.assertTrue(frames['mention-look'].endswith('\n'.join(wake_footer(full=False))))
        self.assertIn(CONSIDER_ASK, frames['consider'])
        self.assertIn('\n'.join(rules_block('Be brief.')), frames['quiet'])


class OpenWorkTest(TestCase):
    """Open work: what the forge has open, and who asked for it, from the record."""

    @classmethod
    def setUpTestData(cls):
        cls.justin = ThinkingEntity.objects.create(name='justin', is_biological_human=True)
        cls.skyler = ThinkingEntity.objects.create(name='skyler', is_biological_human=True)
        cls.magent = ThinkingEntity.objects.create(name='magent', is_biological_human=False)
        cls.m26 = Motion.objects.create(slug='m26', title='Magenta 26 Million')

    def setUp(self):
        from django.core.cache import cache
        cache.delete('work:forge')
        cache.delete('work:open')

    def test_who_asked_and_where(self):
        from unittest import mock

        def add(sender, text, seconds):
            Message.objects.create(id=uuid.uuid4(), sender=sender, motion=self.m26, content=text,
                                   timestamp=int((time.time() + seconds) * 1000))
        add(self.justin, '@magent can you add dark mode?', 1)
        add(self.magent, [{'type': 'text', 'text': 'Done in https://github.com/jMyles/memory-lane/pull/64.'}], 2)
        add(self.skyler, 'nice, see github.com/jMyles/memory-lane/pull/64', 3)
        forge = {'repository_url': 'https://api.github.com/repos/jMyles/memory-lane', 'number': 64,
                 'title': 'Dark mode', 'html_url': 'https://github.com/jMyles/memory-lane/pull/64',
                 'user': {'login': 'magent-cryptograss'}, 'created_at': '2026-10-03T02:00:00Z',
                 'updated_at': '2026-10-03T02:30:00Z'}
        with mock.patch('conversations.services.work._search', side_effect=[[forge], []]):
            items = self.client.get('/api/work/').json()['items']
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual((item['author'], item['asked_by']), ('magent', 'justin'))
        self.assertEqual(item['people'], ['justin', 'skyler'])
        self.assertEqual([m['slug'] for m in item['moods']], ['m26'])

    def test_the_forge_unreachable_is_said_not_raised(self):
        from unittest import mock
        with mock.patch('conversations.services.work._search', side_effect=OSError('down')):
            body = self.client.get('/api/work/').json()
        self.assertEqual(body['items'], [])
        self.assertIn('could not ask the forge', body['error'])


class AroundTest(TestCase):
    """Who's around in each Mood: who spoke in the last 100 blocks, and who's typing."""

    @classmethod
    def setUpTestData(cls):
        cls.justin = ThinkingEntity.objects.create(name='justin', is_biological_human=True)
        cls.skyler = ThinkingEntity.objects.create(name='skyler', is_biological_human=True)
        cls.magent = ThinkingEntity.objects.create(name='magent', is_biological_human=False)
        cls.m26 = Motion.objects.create(slug='m26')
        cls.dk = Motion.objects.create(slug='delivery-kid')

    def setUp(self):
        from django.core.cache import cache
        cache.delete('motions-live')
        cache.delete('typing:m26')

    def test_recent_speakers_per_mood(self):
        from datetime import timedelta
        from django.utils import timezone
        old = Message.objects.create(id=uuid.uuid4(), sender=self.skyler, motion=self.dk, content='an hour ago')
        Message.objects.filter(pk=old.pk).update(created_at=timezone.now() - timedelta(hours=1))
        Message.objects.create(id=uuid.uuid4(), sender=self.justin, motion=self.m26, content='just now')
        live = self.client.get('/api/motions/live/').json()['motions']
        self.assertEqual(live['m26']['speakers'], ['justin'])
        self.assertEqual(live['delivery-kid']['speakers'], [])  # an hour is more than 100 blocks

    def test_the_block_height_comes_from_the_explorer_or_not_at_all(self):
        from unittest import mock
        from django.core.cache import cache
        cache.delete('eth-head')
        head = mock.Mock(json=lambda: [{'height': 26113794, 'timestamp': '2026-10-03T19:06:23Z'}])
        with mock.patch('requests.get', return_value=head):
            self.assertEqual(self.client.get('/api/block/').json()['height'], 26113794)
        cache.delete('eth-head')
        with mock.patch('requests.get', side_effect=OSError('down')):
            self.assertIsNone(self.client.get('/api/block/').json()['height'])


class MoodMemoryToolsTest(TestCase):
    """The memory server reads Moods: list_moods, and read_mood from a message or a time."""

    @classmethod
    def setUpTestData(cls):
        cls.justin = ThinkingEntity.objects.create(name='justin', is_biological_human=True)
        cls.magent = ThinkingEntity.objects.create(name='magent', is_biological_human=False)
        cls.m26 = Motion.objects.create(slug='m26', title='Magenta Interface(s)', description='the chat itself')
        cls.rows = []
        for i in range(5):
            cls.rows.append(Message.objects.create(id=uuid.uuid4(), sender=cls.justin if i % 2 == 0 else cls.magent,
                                                   motion=cls.m26, content=f'line {i}',
                                                   timestamp=int((time.time() + i) * 1000)))

    def test_list_moods(self):
        from conversations.mcp.tools import list_moods_text
        text = list_moods_text()
        self.assertIn('m26 -- Magenta Interface(s)', text)
        self.assertIn('5 messages', text)

    def test_read_a_mood_whole_or_from_a_message(self):
        from conversations.mcp.tools import read_mood_text
        whole = read_mood_text('m26')
        self.assertIn('Mood: Magenta Interface(s) (m26)', whole)
        self.assertLess(whole.index('line 0'), whole.index('line 4'))  # oldest first
        self.assertIn(f'#m-{self.rows[2].id}', whole)
        tail = read_mood_text('m26', start=str(self.rows[3].id))
        self.assertNotIn('line 2', tail)
        self.assertIn('line 3', tail)
        self.assertIn("No Mood 'nowhere'", read_mood_text('nowhere'))


class ReadFromTest(TestCase):
    """?from= reads one Mood from one of its own messages, never another's."""

    def test_from_a_message_in_this_mood_only(self):
        justin = ThinkingEntity.objects.create(name='justin', is_biological_human=True)
        a = Motion.objects.create(slug='a')
        b = Motion.objects.create(slug='b')
        first = Message.objects.create(id=uuid.uuid4(), sender=justin, motion=a, content='in a, first',
                                       timestamp=int(time.time() * 1000))
        Message.objects.create(id=uuid.uuid4(), sender=justin, motion=b, content='in b, meanwhile',
                               timestamp=int(time.time() * 1000) + 1)
        Message.objects.create(id=uuid.uuid4(), sender=justin, motion=a, content='in a, then',
                               timestamp=int(time.time() * 1000) + 2)
        texts = [t['text'] for t in self.client.get(f'/api/motions/a/turns/?from={first.id}').json()['turns']]
        self.assertEqual(texts, ['in a, first', 'in a, then'])
        wrong = self.client.get(f'/api/motions/b/turns/?from={first.id}')
        self.assertEqual((wrong.status_code, wrong.json()['motion']), (404, 'a'))
