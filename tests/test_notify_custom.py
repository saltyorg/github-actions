from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from .test_notify import NOW, PullRequestEnricher, workflow_event
from .http_fakes import FakeResponse, RecordingOpener
from salty_actions.notify import build_notification, run_action


class LegacyCompatibilityTests(unittest.TestCase):
    def test_wire_payloads_match_unmodified_v101(self):
        baseline = json.loads((Path(__file__).parent / 'fixtures/notify-v1.0.1.json').read_text())
        for case in baseline['cases']:
            with self.subTest(**case):
                mode = case['mode']
                args = {'github': None, 'now': NOW}
                if mode == 'retry':
                    args.update(terminal_reason='attempt-limit', execution_attempt=2)
                if mode == 'enriched':
                    args['github'] = PullRequestEnricher()
                if mode == 'enrichment-failure':
                    args['github'] = PullRequestEnricher(error=ValueError('unavailable'))
                payload = workflow_event(event=case['event'], conclusion=case['conclusion'],
                                         run_attempt=3, pull_requests=[{'number': 538}])
                expected_hash = case['sha256']
                actual = build_notification(payload, **args)
                self.assertEqual(hashlib.sha256(json.dumps(actual, separators=(',', ':')).encode()).hexdigest(), expected_hash)
                with TemporaryDirectory() as directory:
                    event_path = Path(directory) / 'event.json'
                    event_path.write_text(json.dumps(payload))
                    for opt_in in ({}, {'NOTIFICATION_ARTIFACT': '', 'NOTIFICATION_DATA_PATH': '/must/not/read'}):
                        opener = RecordingOpener([FakeResponse(204)])
                        with redirect_stdout(StringIO()):
                            run_action({'GITHUB_EVENT_PATH': str(event_path),
                                        'DISCORD_WEBHOOK': 'https://discord.invalid/test',
                                        'TERMINAL_REASON': 'attempt-limit' if mode == 'retry' else '',
                                        'EXECUTION_ATTEMPT': '2' if mode == 'retry' else '', **opt_in},
                                       github=args['github'], opener=opener, now=NOW)
                        self.assertEqual(len(opener.requests), 1)
                        self.assertEqual(hashlib.sha256(opener.requests[0].data).hexdigest(), expected_hash)


class CustomNotificationTests(unittest.TestCase):
    def send(self, data, *, outcome='success', attempt=1, terminal_reason=""):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'event.json').write_text(json.dumps(workflow_event(event='schedule', conclusion='success', run_attempt=attempt)))
            if data is not None:
                (root / 'notification.json').write_text(data if isinstance(data, str) else json.dumps(data))
            env = {'GITHUB_EVENT_PATH': str(root / 'event.json'),
                   'DISCORD_WEBHOOK': 'https://discord.invalid/test',
                   'NOTIFICATION_ARTIFACT': 'build-notification-1',
                   'TERMINAL_REASON': terminal_reason,
                   'NOTIFICATION_DOWNLOAD_OUTCOME': outcome,
                   'NOTIFICATION_DATA_PATH': str(root / 'notification.json')}
            opener = RecordingOpener([FakeResponse(204)])
            with redirect_stdout(StringIO()):
                run_action(env, github=None, opener=opener, now=NOW)
            self.assertEqual(len(opener.requests), 1)
            return json.loads(opener.requests[0].data)

    def data(self, count=1):
        return {'schema': 1, 'run_id': 1234, 'run_attempt': 1,
                'event_details': 'Base image updated: [before](https://example.com/before) → [after](https://example.com/after).',
                'fields': [{'name': tag, 'value': 'qBittorrent: 5.2.3\nlibtorrent: 2.0.14\nRevision: 4 → 5', 'inline': True}
                           for tag in ['libtorrent2', 'libtorrent1', 'legacy'][:count]]}

    def test_one_two_three_tags_keep_metadata_on_final_row(self):
        for count in (1, 2, 3):
            with self.subTest(count=count):
                data = self.data(count)
                payload = self.send(data)
                embed = payload['embeds'][0]
                fields = embed['fields']
                self.assertEqual(fields[2], {'name': 'Event - schedule', 'value': data['event_details'], 'inline': False})
                self.assertEqual(fields[3:3+count], data['fields'])
                self.assertEqual(fields[3+count:6], [{'name': '\u200b', 'value': '\u200b', 'inline': True}] * (3-count))
                self.assertEqual([f['name'] for f in fields[6:]], ['Triggered by', 'Workflow'])
                self.assertEqual(embed['title'], 'Success: CI')
                self.assertEqual(embed['description'], 'GitHub attempt: 1')
                self.assertEqual(payload['allowed_mentions'], {'parse': []})

    def test_missing_invalid_or_stale_data_preserves_result_and_reports_unavailable(self):
        invalid = [None, '{', ' ' * 65537, [], {},
                   {**self.data(), 'schema': 2},
                   {**self.data(), 'extra': 'unknown'},
                   {**self.data(), 'event_details': ''}, {**self.data(), 'run_attempt': 2},
                   {**self.data(), 'run_id': 999}, {**self.data(), 'schema': True},
                   {**self.data(), 'fields': [{'name': 'x', 'value': 'y', 'inline': 'true'}]},
                   {**self.data(), 'fields': [{'name': 'x', 'value': 'y' * 1025}]},
                   {**self.data(), 'fields': [{'name': 'x' * 257, 'value': 'y'}]},
                   {**self.data(), 'fields': [{'name': 'x', 'value': 'y'}] * 21},
                   {**self.data(), 'fields': [{'name': 'x', 'value': 'y' * 1000}] * 6},
                   {**self.data(), 'event_details': 'x' * 1025}]
        for data in invalid:
            with self.subTest(data=str(data)[:100]):
                embed = self.send(data)['embeds'][0]
                self.assertEqual(embed['title'], 'Success: CI')
                self.assertEqual(len(embed['fields']), 5)
                self.assertEqual(embed['fields'][2], {'name': 'Event', 'value': 'schedule'})
                self.assertIn('Notification details unavailable', embed['description'])

    def test_failed_download_does_not_use_leftover_file(self):
        embed = self.send(self.data(), outcome='failure')['embeds'][0]
        self.assertEqual(len(embed['fields']), 5)
        self.assertIn('Notification details unavailable', embed['description'])

    def test_fields_only_keeps_original_event(self):
        data = self.data()
        del data['event_details']
        fields = self.send(data)['embeds'][0]['fields']
        self.assertEqual(fields[2], {'name': 'Event', 'value': 'schedule'})
        self.assertEqual(fields[3]['name'], 'libtorrent2')

    def test_details_only_does_not_add_padding(self):
        data = self.data()
        del data['fields']
        fields = self.send(data)['embeds'][0]['fields']
        self.assertEqual(len(fields), 5)
        self.assertEqual(fields[2]['value'], data['event_details'])

    def test_terminal_retry_reason_remains_after_final_metadata(self):
        fields = self.send(self.data(), terminal_reason='attempt-limit')['embeds'][0]['fields']
        self.assertEqual([f['name'] for f in fields[-3:]], ['Triggered by', 'Workflow', 'Result'])
        self.assertEqual(fields[-1]['value'], 'attempt-limit')

    def test_full_width_field_resets_inline_row_padding(self):
        data = self.data()
        data['fields'] += [{'name': 'Details', 'value': 'Full width', 'inline': False},
                           {'name': 'Another tag', 'value': 'Version: 1', 'inline': True}]
        fields = self.send(data)['embeds'][0]['fields']
        self.assertEqual(fields[3:6], data['fields'])
        self.assertEqual(fields[6:8], [{'name': '\u200b', 'value': '\u200b', 'inline': True}] * 2)
        self.assertEqual([f['name'] for f in fields[8:]], ['Triggered by', 'Workflow'])

    def test_noninline_custom_field_needs_no_padding(self):
        data = self.data()
        data['fields'] = [{'name': 'Details', 'value': 'Full width'}]
        fields = self.send(data)['embeds'][0]['fields']
        self.assertEqual(fields[3], {'name': 'Details', 'value': 'Full width', 'inline': False})
        self.assertEqual([f['name'] for f in fields[4:]], ['Triggered by', 'Workflow'])
