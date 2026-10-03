"""Knobs: how each agent carries itself in each Motion; most specific wins; every change kept."""

import json
from datetime import datetime, timedelta, timezone
from unittest import mock

from django.test import TestCase

from conversations.models import Motion, Setting, ThinkingEntity
from conversations.services import settings as knobs


class ResolveTest(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.justin = ThinkingEntity.objects.create(name='justin', is_biological_human=True)
        cls.magent = ThinkingEntity.objects.create(name='magent', is_biological_human=False)
        cls.m26 = Motion.objects.create(slug='m26')
        cls.general = Motion.objects.create(slug='general')

    def test_defaults_until_something_is_set(self):
        got = knobs.resolve('m26', 'magent')
        self.assertEqual(got['listening'], {'mode': 'on', 'until': None})
        self.assertEqual((got['consider_after'], got['mention_effort'], got['rules']), (10, 'high', ''))

    def test_the_most_specific_setting_wins_whatever_its_age(self):
        knobs.change('consider_effort', 'high', motion=self.m26, agent=self.magent, by=self.justin)
        knobs.change('consider_effort', 'low', by=self.justin)  # newer, but for everyone everywhere
        knobs.change('consider_effort', 'max', agent=self.magent, by=self.justin)
        self.assertEqual(knobs.resolve('m26', 'magent')['consider_effort'], 'high')
        self.assertEqual(knobs.resolve('general', 'magent')['consider_effort'], 'max')
        self.assertEqual(knobs.resolve('general', 'otheragent')['consider_effort'], 'low')

    def test_a_change_is_a_new_row_and_the_newest_is_in_force(self):
        knobs.change('rules', 'Be brief.', motion=self.general, agent=self.magent, by=self.justin)
        knobs.change('rules', 'Be brief and playful.', motion=self.general, agent=self.magent, by=self.justin,
                     note='casual channel')
        self.assertEqual(knobs.resolve('general', 'magent')['rules'], 'Be brief and playful.')
        self.assertEqual(Setting.objects.filter(key='rules').count(), 2)

    def test_a_hush_with_an_end_lifts_itself(self):
        soon = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
        knobs.change('listening', {'mode': 'off', 'until': soon}, motion=self.m26, by=self.justin)
        self.assertEqual(knobs.resolve('m26', 'magent')['listening']['mode'], 'off')
        later = datetime.now(timezone.utc) + timedelta(hours=3)
        self.assertEqual(knobs.resolve('m26', 'magent', now=later)['listening'], {'mode': 'on', 'until': None})

    def test_values_are_checked(self):
        for key, value in (('listening', 'asleep'), ('consider_after', 'soon'), ('consider_after', 99999),
                           ('mention_effort', 'huge'), ('model', 'Opus 5.5!'), ('rules', 'x' * 5000),
                           ('nonsense', 1)):
            with self.subTest(key=key):
                with self.assertRaises(knobs.Invalid):
                    knobs.change(key, value)

    def test_moderation_is_not_a_setting_anyone_can_change(self):
        with self.assertRaises(knobs.Invalid):
            knobs.change('scram', True)
        with self.assertRaises(knobs.Invalid):
            knobs.change('consider_usd_per_day', 5, motion=self.m26)


class SettingsAPITest(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.justin = ThinkingEntity.objects.create(name='justin', is_biological_human=True)
        cls.magent = ThinkingEntity.objects.create(name='magent', is_biological_human=False)
        cls.m26 = Motion.objects.create(slug='m26')

    def as_(self, entity):
        return mock.patch('conversations.services.motion_auth.device_for',
                          return_value=mock.Mock(entity=entity, entity_id=entity.name))

    def post(self, body):
        return self.client.post('/api/settings/', json.dumps(body), content_type='application/json')

    def test_anyone_can_read_only_people_signed_in_can_change(self):
        self.assertEqual(self.client.get('/api/settings/').status_code, 200)
        self.assertEqual(self.post({'key': 'rules', 'value': 'x'}).status_code, 401)
        with self.as_(self.magent):
            self.assertEqual(self.post({'key': 'rules', 'value': 'x'}).status_code, 403)
        with self.as_(self.justin):
            made = self.post({'key': 'rules', 'value': 'Keep it light.', 'motion': 'm26', 'agent': 'magent',
                              'note': 'casual'})
        self.assertEqual(made.status_code, 201)
        state = self.client.get('/api/settings/').json()
        self.assertEqual(state['resolved']['m26']['magent']['rules'], 'Keep it light.')
        self.assertEqual(state['history'][0]['set_by'], 'justin')

    def test_bad_requests_say_why(self):
        with self.as_(self.justin):
            self.assertEqual(self.post({'key': 'consider_after', 'value': -1}).status_code, 400)
            self.assertEqual(self.post({'key': 'rules', 'value': 'x', 'motion': 'nowhere'}).status_code, 400)
            self.assertEqual(self.post({'key': 'rules', 'value': 'x', 'agent': 'justin'}).status_code, 400)
            self.assertEqual(self.post({'key': 'scram', 'value': True}).status_code, 400)

    def test_the_pulse_and_the_motion_carry_the_settings(self):
        knobs.change('listening', 'mentions', motion=self.m26, by=self.justin)
        pulse = self.client.get('/api/motions/pulse/?agent=magent').json()
        self.assertEqual(pulse['motions'][0]['settings']['listening']['mode'], 'mentions')
        self.assertIsNone(pulse['scram'])
        self.assertEqual(pulse['budget'], {'consider_usd_per_day': 10.0})
        turns = self.client.get('/api/motions/m26/turns/').json()
        self.assertEqual(turns['listening']['magent']['mode'], 'mentions')

    def test_the_motion_shows_each_agents_model_effort_and_context(self):
        import uuid
        from conversations.models import Message
        knobs.change('model', 'sonnet', motion=self.m26, agent=self.magent, by=self.justin)
        knobs.change('mention_effort', 'max', motion=self.m26, agent=self.magent, by=self.justin)
        magent = self.client.get('/api/motions/m26/turns/').json()['agents']['magent']
        self.assertEqual((magent['model'], magent['effort'], magent['context']), ('sonnet', 'max', None))
        for tokens, model in ((150_000, 'claude-opus-5-5'), (210_000, 'claude-opus-5-5')):
            Message.objects.create(id=uuid.uuid4(), sender_id='magent', motion=self.m26, content='x',
                                   model_backend=model, input_tokens=10, cache_read_input_tokens=tokens,
                                   cache_creation_input_tokens=5)
        # A helper's line is its own context, not the agent's.
        Message.objects.create(id=uuid.uuid4(), sender_id='magent', motion=self.m26, content='x', is_sidechain=True,
                               model_backend='claude-haiku-4-5', input_tokens=9_000)
        context = self.client.get('/api/motions/m26/turns/').json()['agents']['magent']['context']
        self.assertEqual((context['tokens'], context['window'], context['model']),
                         (210_015, 1_000_000, 'claude-opus-5-5'))

    def test_a_mood_is_renamed_by_someone_signed_in_and_the_record_keeps_its_old_name(self):
        from conversations.models import Message

        def rename(body):
            return self.client.post('/api/motions/m26/rename/', json.dumps(body), content_type='application/json')
        self.m26.title = 'Magenta 26 Million'
        self.m26.save()
        self.assertEqual(rename({'title': 'Magenta Interface(s)'}).status_code, 401)
        with self.as_(self.justin):
            self.assertEqual(rename({'title': '  '}).status_code, 400)
            self.assertEqual(rename({'title': 'x' * 201}).status_code, 400)
            self.assertEqual(rename({'title': 'Magenta Interface(s)'}).status_code, 200)
        self.m26.refresh_from_db()
        self.assertEqual((self.m26.slug, self.m26.title), ('m26', 'Magenta Interface(s)'))  # the slug never changes
        row = Message.objects.get(motion=self.m26, sender_id='system', source_file='motion-rename')
        self.assertEqual((row.content['by'], row.content['from']['title']), ('justin', 'Magenta 26 Million'))
        turns = self.client.get('/api/motions/m26/turns/').json()
        self.assertEqual(turns['motion']['title'], 'Magenta Interface(s)')
        self.assertEqual(turns['turns'], [])  # the note is for the record, not the thread

    def test_ultracode_is_a_switch(self):
        self.assertIs(knobs.clean('ultracode', 'on'), True)
        self.assertIs(knobs.clean('ultracode', False), False)
        with self.assertRaises(knobs.Invalid):
            knobs.clean('ultracode', 'sometimes')
        knobs.change('ultracode', True, motion=self.m26, agent=self.magent, by=self.justin)
        self.assertIs(self.client.get('/api/motions/m26/turns/').json()['agents']['magent']['ultracode'], True)

    def test_installable_as_an_app(self):
        manifest = self.client.get('/motions/manifest.webmanifest')
        self.assertEqual(manifest['Content-Type'], 'application/manifest+json')
        body = manifest.json()
        self.assertEqual((body['name'], body['display'], body['start_url']), ('magenta', 'standalone', '/motions/'))
        icon = self.client.get('/motions/icon-192.png')
        self.assertEqual(icon.content[:8], b'\x89PNG\r\n\x1a\n')
        self.assertEqual(int.from_bytes(icon.content[16:20], 'big'), 192)  # IHDR width
        self.assertEqual(self.client.get('/motions/icon-7.png').status_code, 404)
        self.assertEqual(self.client.get('/motions/sw.js')['Service-Worker-Allowed'], '/motions/')

    def test_a_context_window_by_model(self):
        from conversations.services.motion_view import context_window
        self.assertEqual(context_window('claude-opus-5-5'), 1_000_000)
        self.assertEqual(context_window('claude-haiku-4-5', 150_000), 200_000)
        self.assertEqual(context_window('claude-haiku-4-5', 300_000), 1_000_000)  # seen past it: the larger one
        self.assertEqual(context_window(None), 200_000)
