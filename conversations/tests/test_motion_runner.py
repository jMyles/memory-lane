"""A turn the runner launched streams into its Motion: claimed outright, live, ended exactly."""

import base64
from datetime import datetime, timezone
import json
import uuid

from django.test import TestCase, override_settings

from conversations.models import Media, Message, Motion, MotionSession, ThinkingEntity, ToolResult, ToolUse
from conversations.services.motion_view import activity
from conversations.views import import_lines

KEY = 'k' * 64
AUTH = {'HTTP_AUTHORIZATION': f'Bearer {KEY}'}
PNG = b'\x89PNG\r\n\x1a\n' + b'\x00' * 32


def event(kind, content, **extra):
    """A stream-json event shaped like Claude Code 2.1's (see the module docstring of views_runner)."""
    message = {'role': kind, 'content': content}
    if kind == 'assistant':
        message.update({'model': 'claude-opus-5-5', 'id': 'msg_x', 'type': 'message', 'stop_reason': None,
                        'usage': {'input_tokens': 3, 'output_tokens': 40}})
    return {'type': kind, 'message': message, 'parent_tool_use_id': None, 'session_id': extra.pop('session_id'),
            'uuid': str(uuid.uuid4()), 'timestamp': datetime.now(timezone.utc).isoformat(), **extra}


@override_settings(MOTION_RUNNER_KEYS={'magent': KEY}, TOOL_RESULT_CONTENT_CHARS=20000)
class StreamTest(TestCase):

    @classmethod
    def setUpTestData(cls):
        ThinkingEntity.objects.create(name='justin', is_biological_human=True)
        ThinkingEntity.objects.create(name='magent', is_biological_human=False)
        cls.motion = Motion.objects.create(slug='m26')

    def setUp(self):
        self.session = str(uuid.uuid4())

    def post(self, events, auth=AUTH, slug='m26', **body):
        payload = {'harness': 'claude-code', 'session_id': self.session, 'events': events, **body}
        return self.client.post(f'/api/motions/{slug}/stream/', json.dumps(payload),
                                content_type='application/json', **auth)

    def turn(self):
        s = self.session
        use = event('assistant', [{'type': 'tool_use', 'id': 'toolu_r1', 'name': 'Read',
                                   'input': {'file_path': '/home/magent/workspace/x.txt'}}], session_id=s)
        result = event('user', [{'type': 'tool_result', 'tool_use_id': 'toolu_r1', 'content': 'banjo\nfiddle'}],
                       session_id=s, tool_use_result={'type': 'text'})
        reply = event('assistant', [{'type': 'text', 'text': 'The second line is fiddle.'}], session_id=s)
        done = {'type': 'result', 'subtype': 'success', 'is_error': False, 'result': 'The second line is fiddle.',
                'stop_reason': 'end_turn', 'total_cost_usd': 0.0123, 'duration_ms': 4100, 'num_turns': 2,
                'session_id': s, 'uuid': str(uuid.uuid4())}
        return use, result, reply, done

    # --- who may stream ------------------------------------------------------------

    def test_without_runner_keys_nobody_streams(self):
        with override_settings(MOTION_RUNNER_KEYS={}):
            self.assertEqual(self.post([]).status_code, 503)

    def test_a_wrong_key_is_refused(self):
        self.assertEqual(self.post([], auth={'HTTP_AUTHORIZATION': 'Bearer nope'}).status_code, 401)
        self.assertEqual(self.post([], auth={}).status_code, 401)

    def test_a_key_speaks_only_for_agents_an_importer_can_speak_for(self):
        with override_settings(MOTION_RUNNER_KEYS={'otheragent': KEY}):
            self.assertEqual(self.post([]).status_code, 400)

    def test_a_bad_body_is_refused(self):
        response = self.client.post('/api/motions/m26/stream/', json.dumps({'session_id': 'nope', 'events': []}),
                                    content_type='application/json', **AUTH)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.post([], harness='codex').status_code, 400)
        self.assertEqual(self.post([], slug='nowhere').status_code, 404)

    # --- what a stream does ----------------------------------------------------------

    def test_a_turn_streams_into_the_motion_and_ends_exactly(self):
        use, result, reply, done = self.turn()

        self.assertEqual(self.post([use]).status_code, 200)
        self.assertEqual(MotionSession.motion_for(self.session), self.motion)  # claimed outright
        self.assertEqual(activity(self.motion)['doing'], 'reading')  # live, mid-turn

        self.post([result, reply])
        self.assertIsNotNone(activity(self.motion))  # said something, but not done yet
        body = self.post([done]).json()
        self.assertTrue(body['finished'])
        self.assertIsNone(activity(self.motion))  # done, exactly when it was

        turns = self.client.get('/api/motions/m26/turns/').json()
        self.assertEqual([t['text'] for t in turns['turns']], ['The second line is fiddle.'])
        self.assertEqual([s['tool'] for s in turns['steps']], ['Read'])
        step = self.client.get(f"/api/motions/m26/steps/{turns['steps'][0]['id']}/").json()
        self.assertEqual(step['result']['text'], 'banjo\nfiddle')
        cost = Message.objects.get(sender_id='system', content__type='turn-result')
        self.assertEqual((cost.content['cost_usd'], cost.motion), (0.0123, self.motion))

    def test_posting_the_same_events_again_adds_nothing(self):
        events = list(self.turn())
        self.post(events)
        count = Message.objects.count()
        self.post(events)
        self.assertEqual(Message.objects.count(), count)

    def test_the_transcript_of_the_same_turn_fills_in_rather_than_repeats(self):
        use, result, reply, done = self.turn()
        self.post([use, result, reply, done])
        count = Message.objects.count()
        # What the watcher later sends for the same reply: same uuid, plus
        # what only a transcript knows.
        line = json.dumps({'type': 'assistant', 'uuid': reply['uuid'], 'parentUuid': result['uuid'],
                           'sessionId': self.session, 'timestamp': '2026-10-01T23:00:01.000Z',
                           'userType': 'external', 'isSidechain': False, 'cwd': '/home/magent/workspace',
                           'gitBranch': 'main', 'effort': 'high', 'perTurnEffort': 'xhigh',
                           'message': reply['message'] | {'stop_reason': 'end_turn',
                                                          'usage': {'input_tokens': 3, 'output_tokens': 322}}})
        self.assertEqual(Message.objects.get(id=reply['uuid']).output_tokens, 40)  # the stream's, mid-response
        import_lines([line], source='hunter-watcher', username='justin')
        self.assertEqual(Message.objects.count(), count)
        stored = Message.objects.get(id=reply['uuid'])
        self.assertEqual((stored.effort, stored.cwd, str(stored.parent_id)), ('xhigh', '/home/magent/workspace',
                                                                          result['uuid']))
        self.assertEqual(stored.output_tokens, 322)  # the response's final count

    def test_what_streams_in_is_redacted_and_its_images_kept(self):
        s = self.session
        secret = event('assistant', [{'type': 'text', 'text': 'export GITHUB_TOKEN=zq8Fh2kLm0xY'}], session_id=s)
        shot = event('user', [{'type': 'tool_result', 'tool_use_id': 'toolu_s1', 'content': [
            {'type': 'text', 'text': 'took it'},
            {'type': 'image', 'source': {'type': 'base64', 'media_type': 'image/png',
                                         'data': base64.b64encode(PNG).decode()}}]}], session_id=s)
        self.post([secret, shot])
        self.assertNotIn('zq8Fh2kLm0xY', json.dumps(Message.objects.get(id=secret['uuid']).content))
        self.assertIn(Media.objects.get().url, ToolResult.objects.get(tool_use_id='toolu_s1').content)

    def test_a_helpers_events_are_its_own_sidechain(self):
        helper = event('assistant', [{'type': 'text', 'text': 'helper speaking'}], session_id=self.session,
                       parent_tool_use_id='toolu_agent1')
        self.post([helper])
        self.assertTrue(Message.objects.get(id=helper['uuid']).is_sidechain)

    def test_a_commands_output_is_shown_and_leaves_the_pie_alone(self):
        # /context's answer is a "<synthetic>" message that read nothing.
        Message.objects.create(id=uuid.uuid4(), sender_id='magent', motion=self.motion, session_id=str(uuid.uuid4()),
                               content=[{'type': 'text', 'text': 'Before.'}], timestamp=1, input_tokens=3,
                               cache_read_input_tokens=400_000, model_backend='claude-opus-5-5')
        s = self.session
        table = event('assistant', [{'type': 'text', 'text': '## Context Usage\n\n**Tokens:** 400k / 1m (40%)'}],
                      session_id=s)
        table['message'].update({'model': '<synthetic>', 'stop_reason': 'end_turn',
                                 'usage': {'input_tokens': 0, 'output_tokens': 0}})
        done = {'type': 'result', 'subtype': 'success', 'is_error': False, 'result': table['message']['content'][0]['text'],
                'num_turns': 0, 'local_command': 'context', 'session_id': s, 'uuid': str(uuid.uuid4())}
        self.post([table, done])
        turns = self.client.get('/api/motions/m26/turns/').json()
        self.assertIn('Context Usage', turns['turns'][-1]['text'])
        self.assertEqual(turns['agents']['magent']['context']['tokens'], 400_003)

    def test_a_compaction_streams_in_as_one_and_is_the_session_to_resume(self):
        # `/compact` run by the poller: no reply, just the summary the session
        # goes on from. It must count as the agent's, or the next wake would
        # resume the session from before it, uncompacted.
        older = str(uuid.uuid4())
        Message.objects.create(id=uuid.uuid4(), sender_id='magent', motion=self.motion, session_id=older,
                               content=[{'type': 'text', 'text': 'Before.'}], timestamp=1,
                               input_tokens=3, cache_read_input_tokens=900_000, model_backend='claude-opus-5-5')
        s = self.session
        boundary = {'type': 'system', 'subtype': 'compact_boundary', 'session_id': s, 'uuid': str(uuid.uuid4()),
                    'compact_metadata': {'trigger': 'manual', 'pre_tokens': 970145, 'post_tokens': 12650}}
        summary = event('user', 'This session is being continued from a previous conversation that ran out '
                        'of context. The summary below covers the earlier portion of the conversation.\n\n'
                        'Summary:\n1. Banjo setlist.', session_id=s, isReplay=True)
        stdout = event('user', '<local-command-stdout>Compacted </local-command-stdout>', session_id=s, isReplay=True)
        done = {'type': 'result', 'subtype': 'success', 'is_error': False, 'result': '', 'num_turns': 0,
                'total_cost_usd': 0.4, 'local_command': 'compact', 'session_id': s, 'uuid': str(uuid.uuid4())}
        self.assertTrue(self.post([boundary, summary, stdout, done]).json()['finished'])

        sessions = self.client.get('/api/motions/m26/sessions/', {'sender': 'magent'}).json()['sessions']
        self.assertEqual(sessions[0]['session_id'], s)
        turns = self.client.get('/api/motions/m26/turns/').json()
        self.assertEqual(len(turns['compactions']), 1)
        self.assertIn('Banjo setlist', turns['compactions'][0]['html'])
        self.assertEqual([t['text'] for t in turns['turns']], ['Before.'])  # no stray "Compacted" turn
        # The pie: about the summary's size, until a turn measures it.
        context = turns['agents']['magent']['context']
        self.assertTrue(context['compacted'])
        self.assertLess(context['tokens'], 100)


@override_settings(MOTION_RUNNER_KEYS={'magent': KEY})
class PulseAndQuietTest(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.justin = ThinkingEntity.objects.create(name='justin', is_biological_human=True)
        cls.magent = ThinkingEntity.objects.create(name='magent', is_biological_human=False)
        cls.motion = Motion.objects.create(slug='m26')
        Motion.objects.create(slug='quiet-one')

    def test_the_pulse_shows_every_motion_at_a_glance(self):
        Message.objects.create(id=uuid.uuid4(), sender=self.justin, motion=self.motion, content='from the web',
                               timestamp=1, source_file='motion-web')
        reply = Message.objects.create(id=uuid.uuid4(), sender=self.magent, motion=self.motion,
                                       content=[{'type': 'text', 'text': 'hi'}], timestamp=2, stop_reason='end_turn')
        pulse = {m['slug']: m for m in self.client.get('/api/motions/pulse/').json()['motions']}
        self.assertEqual(pulse['m26']['newest']['id'], str(reply.id))
        self.assertEqual(pulse['m26']['last_web_post']['sender'], 'justin')
        self.assertEqual(pulse['m26']['last_human']['sender'], 'justin')
        self.assertIsNone(pulse['m26']['activity'])
        self.assertIsNone(pulse['quiet-one']['newest'])

    def test_a_screen_records_a_dot_marked_as_its_own(self):
        def post(body, auth=AUTH):
            return self.client.post('/api/motions/m26/quiet/', json.dumps(body),
                                    content_type='application/json', **auth)
        self.assertEqual(post({'reason': 'x'}, auth={}).status_code, 401)
        self.assertEqual(post({'reason': 'x', 'by': 'not one word'}).status_code, 400)
        self.assertEqual(post({'reason': 'two people <b>sorting</b> the bus; GITHUB_TOKEN=zq8Fh2kLm0xY'}).status_code, 201)
        quiet = self.client.get('/api/motions/m26/turns/').json()['quiet']
        self.assertEqual(len(quiet), 1)
        self.assertEqual(quiet[0]['by'], 'screen')
        self.assertNotIn('<b>', quiet[0]['reason'])
        self.assertNotIn('zq8Fh2kLm0xY', quiet[0]['reason'])
        stored = Message.objects.get(id=quiet[0]['id'])
        self.assertIsNone(stored.session_id)  # never a session anyone would resume
        self.assertIsNone(activity(self.motion))

    def test_a_runner_says_why_a_mention_is_held(self):
        from django.core.cache import cache
        cache.delete('held:m26')

        def post(body, auth=AUTH):
            return self.client.post('/api/motions/m26/held/', json.dumps(body),
                                    content_type='application/json', **auth)
        Message.objects.create(id=uuid.uuid4(), sender=self.justin, motion=self.motion, content='@magent hello?',
                               source_file='motion-web')
        self.assertEqual(activity(self.motion)['doing'], 'waking')
        self.assertEqual(post({'reason': 'x'}, auth={}).status_code, 401)
        self.assertEqual(post({'reason': 'x', 'until': 'soonish'}).status_code, 400)
        self.assertEqual(post({'reason': '30 wakes <i>this hour</i> already', 'until': '2026-10-02T23:15:00Z'}).status_code, 200)
        shown = self.client.get('/api/motions/m26/turns/').json()['activity']
        self.assertEqual((shown['doing'], shown['why'], shown['until']),
                         ('held', '30 wakes this hour already', '2026-10-02T23:15:00+00:00'))
        self.assertEqual(post({'reason': ''}).status_code, 200)  # lifted
        self.assertEqual(activity(self.motion)['doing'], 'waking')

    def test_recent_context_only_when_asked(self):
        for i in range(5):
            Message.objects.create(id=uuid.uuid4(), sender=self.justin, motion=self.motion, content=f'line {i}',
                                   timestamp=i)
        turns = self.client.get('/api/motions/m26/turns/?limit=2').json()['turns']
        self.assertEqual([t['text'] for t in turns], ['line 3', 'line 4'])
