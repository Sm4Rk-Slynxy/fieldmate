"""Regression checks for the security/privacy review and publication boundary."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

from fieldmate.core import clean
from fieldmate.ingest import http_record, record
from fieldmate.store import Store
from fieldmate.engine import snapshot, build_context
from fieldmate.review import batches
from tools.prepare_publication import FILES, TREES, audit, prepare


class ReviewRegressions(unittest.TestCase):
    def test_redaction_masks_text_sessions_password_aliases_and_url_credentials(self):
        for value in ('pwd=fixture-value', 'sessionid=fixture-value', '{"session_id":"fixture-value"}',
                      'postgresql://tester:fixture-value@db.example.test/database'):
            with self.subTest(value=value):
                self.assertNotIn('fixture-value', clean(value))
        self.assertIn('/api/invoices/42', clean('https://portal.example.test/api/invoices/42'))

    def test_existing_token_permissions_are_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            token = Path(directory) / 'token'
            os.chmod(token, 0o644)
            self.assertEqual(Store(directory).token, store.token)
            self.assertEqual(token.stat().st_mode & 0o777, 0o600)

    def test_report_preserves_untrusted_markdown_as_literal_text(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            payload = '![tracking](https://tracking.example.test/pixel) <img src="https://tracking.example.test/pixel">'
            eid = store.create_engagement(payload, ['portal.example.test'], payload)['id']
            store.save_finding(eid, {'title':payload, 'reproduction':payload, 'impact':payload})
            store.save_test(eid, {'subject':payload, 'check_name':'review', 'notes':payload})
            report = store.report(eid)
            self.assertNotIn('![tracking]', report)
            self.assertNotIn('<img', report)
            self.assertIn('tracking', report)
            self.assertIn('## Scope', report)

    def test_event_paging_uses_snapshot_boundary_and_small_pages(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            eid = store.create_engagement('Lab', ['portal.example.test'])['id']
            store.ingest(eid, [record('note',str(i),'test','portal.example.test') for i in range(140)])
            iterator = store.iter_events(eid, in_scope_only=True)
            first = next(iterator)
            store.ingest(eid, [record('note','arrived during review','test','portal.example.test')])
            events = [first, *iterator]
            self.assertEqual(len(events),140)
            self.assertNotIn('arrived during review', {e['content'] for e in events})
            self.assertEqual(len({e['id'] for e in events}),140)

    def test_inventory_and_snapshot_do_not_fetch_all_response_bodies(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            eid = store.create_engagement('Lab', ['portal.example.test'])['id']
            event = http_record({'url':'https://portal.example.test/api/me'}, {'status':200,'content':{'text':'large body '*2000}}, 'test','tester')
            store.ingest(eid,[event])
            self.assertNotIn('response_body', json.dumps(store.event_summaries(eid)))
            original = store.events
            def bounded(eid, limit=None, images=False):
                self.assertIsNotNone(limit)
                return original(eid, limit, images)
            with patch.object(store,'events',side_effect=bounded):
                self.assertEqual(snapshot(store,eid)['total_events'],1)
                context,_ = build_context(store,eid)
                self.assertEqual(context['selection']['eligible'],1)

    def test_project_batches_are_lazy_and_consume_bounded_input(self):
        seen = []
        def events():
            for i in range(1000):
                seen.append(i)
                yield {'id':str(i),'kind':'http','target':'https://portal.example.test/api/me','identity':'tester','content':'observed','metadata':{'response_body':'x'*4500}}
        iterator = batches(events(),4000)
        first = next(iterator)
        self.assertLess(len(seen),10)
        self.assertLessEqual(len(json.dumps(first)),4000)
        self.assertTrue(first)


class PublicationBoundary(unittest.TestCase):
    def fixture(self, root):
        for name in FILES:
            path = root / name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(b'\x89PNG\r\n\x1a\n' if path.suffix=='.png' else b'synthetic source\n')
        for name in TREES:
            (root/name).mkdir(parents=True,exist_ok=True)
        (root/'fieldmate/core.py').write_text('pass\n')

    def test_publication_excludes_private_state_exports_and_unreviewed_images(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            for name in ('.fieldmate/token','client.burp','fieldmate/client.har','docs/screenshots/private.png','private/notes.txt','.env'):
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('DO NOT PUBLISH')
            output=root/'source.zip'
            names=prepare(root,output)
            self.assertFalse(any('.fieldmate' in name or name.endswith(('.burp','.har')) for name in names))
            with ZipFile(output) as archive:
                self.assertFalse(any(b'DO NOT PUBLISH' in archive.read(name) for name in archive.namelist()))
                self.assertIn('fieldmate/docs/screenshots/overview.png',archive.namelist())

    def test_publication_blocks_credentials_without_printing_their_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            self.fixture(root)
            secret='ghp_'+'A'*36
            (root/'fieldmate/core.py').write_text('credential = "'+secret+'"\n')
            with self.assertRaises(ValueError) as caught:
                prepare(root)
            self.assertIn('GitHub credential',str(caught.exception))
            self.assertNotIn(secret,str(caught.exception))

    def test_publication_rejects_linked_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            self.fixture(root)
            (root/'fieldmate/linked.py').symlink_to(root/'README.md')
            with self.assertRaisesRegex(ValueError,'Linked publication'):
                prepare(root)
