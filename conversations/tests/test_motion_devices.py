"""Devices that time out and are renewed by name; statements attested with a key; servers and their redeploys.

Uses the real ssh-keygen with a throwaway key, as test_motion_auth does.
"""

import json
import os
import subprocess
import tempfile
from datetime import timedelta
from unittest import mock, skipUnless

from django.test import Client, TestCase, override_settings
from django.utils import timezone

from conversations.models import Device, Message, Motion, ThinkingEntity
from conversations.services import motion_auth, servers
from conversations.tests.test_motion_auth import HAS_SSH_KEYGEN, make_key, sign


@skipUnless(HAS_SSH_KEYGEN, 'needs ssh-keygen')
class DevicesTest(TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.dir = tempfile.mkdtemp()
        cls.justin_key = make_key(cls.dir, 'justin')
        cls.signers = os.path.join(cls.dir, 'allowed_signers')
        with open(cls.signers, 'w') as f:
            pub = open(cls.justin_key + '.pub').read().strip()
            f.write(f'justin namespaces="{motion_auth.NAMESPACE}" {pub}\n')

    def setUp(self):
        ThinkingEntity.objects.create(name='justin', is_biological_human=True)
        ThinkingEntity.objects.create(name='magent', is_biological_human=False)
        Motion.objects.create(slug='m26')
        patcher = override_settings(MOTION_ALLOWED_SIGNERS=self.signers)
        patcher.enable()
        self.addCleanup(patcher.disable)

    def sign_in(self, label='phone', client=None):
        client = client or Client()
        challenge = client.get('/api/auth/challenge/').json()['challenge']
        message = motion_auth.signed_message(challenge, 'http://testserver')
        url = client.post('/api/auth/enroll/', json.dumps({'challenge': challenge, 'signature': sign(self.justin_key, message)}),
                          content_type='application/json').json()['url']
        path = url.split('testserver', 1)[1]
        client.get(path)
        client.post(path, {'label': label, 'csrfmiddlewaretoken': client.cookies['csrftoken'].value})
        return client

    def signed_post(self, url, purpose, extra, text=None):
        challenge = self.client.get('/api/auth/challenge/').json()['challenge']
        message = motion_auth.signed_message(challenge, 'http://testserver', purpose=purpose)
        if text is not None:
            message += '\n' + text
        body = {'challenge': challenge, 'signature': sign(self.justin_key, message), **extra}
        return self.client.post(url, json.dumps(body), content_type='application/json')

    def test_your_devices_listed_and_one_revoked(self):
        phone = self.sign_in('phone')
        laptop = self.sign_in('laptop')
        listed = laptop.get('/api/auth/devices/').json()['devices']
        self.assertEqual([(d['label'], d['state'], d['this']) for d in listed],
                         [('laptop', 'live', True), ('phone', 'live', False)])
        phone_id = next(d['id'] for d in listed if d['label'] == 'phone')
        revoke = laptop.post(f'/api/auth/devices/{phone_id}/revoke/', HTTP_X_CSRFTOKEN=laptop.cookies['csrftoken'].value)
        self.assertEqual(revoke.status_code, 200)
        self.assertEqual(phone.get('/api/auth/devices/').status_code, 401)  # signed out
        self.assertEqual(Client().get('/api/auth/devices/').status_code, 401)

    def test_an_unused_device_times_out_and_renewing_brings_it_back(self):
        phone = self.sign_in('phone')
        Device.objects.update(last_used_at=timezone.now() - motion_auth.DEVICE_IDLE_LIMIT - timedelta(days=1))
        self.assertEqual(phone.get('/api/auth/devices/').status_code, 401)  # timed out
        self.assertEqual(self.signed_post('/api/auth/renew/', 'renew laptop', {'label': 'laptop'}).status_code, 404)
        # A signature for one device can't renew another.
        wrong = self.signed_post('/api/auth/renew/', 'renew laptop', {'label': 'phone'})
        self.assertEqual(wrong.status_code, 403)
        renewed = self.signed_post('/api/auth/renew/', 'renew phone', {'label': 'phone'})
        self.assertEqual((renewed.status_code, renewed.json()['state']), (200, 'live'))
        self.assertEqual(phone.get('/api/auth/devices/').status_code, 200)  # the same cookie works again

    def test_an_attestation_lands_in_general_with_its_proof(self):
        words = "I'll bring the PA on Saturday."
        made = self.signed_post('/api/attest/', 'attest', {'text': words}, text=words)
        self.assertEqual(made.status_code, 201)
        row = Message.objects.get(motion_id='general', source_file='motion-attest')
        self.assertEqual((row.sender_id, row.content['text']), ('justin', words))
        self.assertTrue(row.content['key'].startswith('ssh-ed25519 '))
        # Anyone can check it with ssh-keygen alone, from what the record keeps.
        with tempfile.TemporaryDirectory() as tmp:
            signers, sig = os.path.join(tmp, 'allowed'), os.path.join(tmp, 'sig')
            open(signers, 'w').write(f"justin {row.content['key']}\n")
            open(sig, 'w').write(row.content['signature'])
            check = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', signers, '-I', 'justin', '-n',
                                    row.content['namespace'], '-s', sig], input=row.content['signed'],
                                   capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)
        body = self.client.get('/api/motions/general/turns/').json()
        turns = body['turns']
        self.assertEqual(turns[0]['text'], words)
        self.assertIsNone(body['activity'])  # posted words, not a session's prompt with an agent at work
        self.assertTrue(turns[0]['attested']['signature'])
        # Signed words can't be swapped for others.
        forged = self.signed_post('/api/attest/', 'attest', {'text': 'I owe magent $100.'}, text=words)
        self.assertEqual(forged.status_code, 403)


@override_settings(MOTION_DEPLOY_KEY='d' * 40)
class ServersTest(TestCase):

    @classmethod
    def setUpTestData(cls):
        ThinkingEntity.objects.create(name='justin', is_biological_human=True)
        for slug in ('m26', 'delivery-kid', 'pickipedia-and-rabbithole'):
            Motion.objects.create(slug=slug, title=slug)

    def setUp(self):
        from django.core.cache import cache
        for s in servers.NAMES:
            cache.delete(f'server-check:{s}')

    def deploy(self, body, key='d' * 40):
        return self.client.post('/api/deploys/', json.dumps(body), content_type='application/json',
                                HTTP_AUTHORIZATION=f'Bearer {key}')

    def test_a_hunter_redeploy_is_told_in_every_mood_and_pulses_its_dot(self):
        self.assertEqual(self.deploy({'server': 'hunter', 'state': 'started'}, key='x').status_code, 401)
        self.assertEqual(self.deploy({'server': 'mars', 'state': 'started'}).status_code, 400)
        self.assertEqual(self.deploy({'server': 'hunter', 'state': 'started', 'by': 'justin'}).json()['moods'], 3)
        with mock.patch('conversations.services.servers.probe', return_value=(True, 5)):
            listed = {s['name']: s for s in self.client.get('/api/servers/').json()['servers']}
        self.assertTrue(listed['hunter']['deploying'])
        self.assertFalse(listed['pickipedia']['deploying'])
        self.deploy({'server': 'hunter', 'state': 'finished', 'commit': 'abc123def'})
        events = self.client.get('/api/motions/m26/turns/').json()['events']
        self.assertEqual([(e['server'], e['state']) for e in events], [('hunter', 'started'), ('hunter', 'finished')])
        self.assertIsNotNone(events[1]['took'])
        self.assertEqual(self.client.get('/api/motions/m26/turns/').json()['turns'], [])  # not a turn

    def test_a_delivery_kid_redeploy_stays_in_its_own_mood(self):
        self.assertEqual(self.deploy({'server': 'delivery-kid', 'state': 'started'}).json()['moods'], 1)
        self.assertEqual(self.client.get('/api/motions/m26/turns/').json()['events'], [])
        self.assertEqual(len(self.client.get('/api/motions/delivery-kid/turns/').json()['events']), 1)
        recent = self.client.get('/api/motions/recent/').json()['events']
        self.assertEqual([e['kind'] for e in recent].count('deploy'), 1)

    def test_a_redeploy_doesnt_make_a_mood_look_active(self):
        before = {m['slug']: (m['last_at'], m['message_count']) for m in self.client.get('/api/motions/').json()['motions']}
        self.deploy({'server': 'maybelle', 'state': 'finished'})
        after = {m['slug']: (m['last_at'], m['message_count']) for m in self.client.get('/api/motions/').json()['motions']}
        self.assertEqual(before, after)

    def test_without_a_key_nobody_tells_of_redeploys(self):
        with override_settings(MOTION_DEPLOY_KEY=''):
            self.assertEqual(self.deploy({'server': 'hunter', 'state': 'started'}).status_code, 503)
