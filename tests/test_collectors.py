"""Exercise real terminal PTYs, file watching, and replay through the HTTP app."""
import json
import os
import pty
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from fieldmate.client import Client
from fieldmate.server import AppServer
from fieldmate.store import Store
from fieldmate.engine import build_context

ROOT = Path(__file__).resolve().parent.parent


class Collectors(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / 'data')
        self.eid = self.store.create_engagement('Collector lab',['portal.example.test','192.168.56.0/24'])['id']
        self.server = AppServer(('127.0.0.1',0),self.store)
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.base = [sys.executable,'-m','fieldmate','--data',str(self.store.directory),'--url',f'http://127.0.0.1:{self.server.server_port}']

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.directory.cleanup()

    def run_cli(self,*arguments):
        return subprocess.run(self.base + list(arguments),cwd=ROOT,capture_output=True,text=True,timeout=15)

    def test_replay_sequential_and_existing_engagement_guard(self):
        result = self.run_cli('replay','--engagement',self.eid,str(ROOT / 'examples/session.jsonl'),'--delay','0')
        self.assertEqual(result.returncode,0,result.stderr)
        events = list(reversed(self.store.events(self.eid)))
        self.assertEqual([e['kind'] for e in events],['terminal','note','http'])
        result = self.run_cli('replay','--engagement',self.eid,str(ROOT / 'examples/session.jsonl'),'--delay','0')
        self.assertEqual(result.returncode,1)
        self.assertIn('empty engagement',result.stderr)

    def test_directory_watcher_ingests_stable_export_and_growing_log(self):
        watch = Path(self.directory.name) / 'evidence'; watch.mkdir()
        (watch / 'scan.xml').write_text((ROOT / 'examples/network.xml').read_text())
        logfile = watch / 'session.log'; logfile.write_text('first-watcher-proof\n')
        process = subprocess.Popen(self.base + ['watch',str(watch),'--engagement',self.eid,'--target','portal.example.test'],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if len(self.store.events(self.eid)) >= 3: break
                time.sleep(.1)
            self.assertEqual(len(self.store.events(self.eid)),3)
            with logfile.open('a') as stream: stream.write('second-watcher-proof\n')
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if len(self.store.events(self.eid)) >= 4: break
                time.sleep(.1)
            self.assertEqual(len(self.store.events(self.eid)),4)
            content = '\n'.join(e['content'] for e in self.store.events(self.eid))
            self.assertEqual(content.count('first-watcher-proof'),1)
            self.assertEqual(content.count('second-watcher-proof'),1)
        finally:
            process.send_signal(signal.SIGINT)
            process.wait(timeout=5)

    def test_real_pty_capture_streams_output_without_persisting_password(self):
        master, slave = pty.openpty()
        process = subprocess.Popen(self.base + ['capture','--engagement',self.eid,'--target','portal.example.test','--shell','/bin/sh'],cwd=ROOT,stdin=slave,stdout=slave,stderr=slave,start_new_session=True)
        os.close(slave)
        try:
            time.sleep(.3)
            os.write(master,b"printf 'collector-proof\\n'; printf 'password=do-not-store\\n'; exit\n")
            process.wait(timeout=15)
            self.assertEqual(process.returncode,0)
            events = self.store.events(self.eid)
            self.assertTrue(any('collector-proof' in e['content'] for e in events))
            self.assertNotIn('do-not-store',json.dumps(events))
        finally:
            if process.poll() is None: process.kill(); process.wait()
            os.close(master)

    def test_shell_hook_records_completion_metadata(self):
        env = {**os.environ,'FIELDMATE_LAST_COMMAND':'   42  printf hook-proof','FIELDMATE_LAST_STATUS':'7','FIELDMATE_LAST_CWD':'/tmp','FIELDMATE_SESSION':'test-session'}
        result = subprocess.run(self.base + ['hook','--engagement',self.eid,'--target','portal.example.test','--identity','tester'],cwd=ROOT,env=env,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        event = self.store.events(self.eid)[0]
        self.assertEqual(event['kind'],'command')
        self.assertEqual(event['content'],'printf hook-proof')
        self.assertEqual(event['metadata']['exit_status'],7)

    def test_total_context_is_bounded_with_large_history(self):
        self.store.save_settings({'context_chars':4000})
        for i in range(10):
            self.store.ingest(self.eid,[{'kind':'note','source':'test','target':'portal.example.test','content':'x'*500,'metadata':{'sequence':i}}])
            self.store.save_test(self.eid,{'subject':'portal.example.test','check_name':f'check-{i}','notes':'y'*1000})
        context,images = build_context(self.store,self.eid)
        self.assertLessEqual(len(json.dumps(context,ensure_ascii=False)),4000)


if __name__ == '__main__': unittest.main()
