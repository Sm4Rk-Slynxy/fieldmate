import base64
import hashlib
import http.client
import io
import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from fieldmate.store import Store
from fieldmate.ingest import http_record, parse_export
from fieldmate import projects
from fieldmate.repeater import template
from fieldmate.review import parse,review_project,batches
from fieldmate.engine import AnalysisManager,snapshot
from fieldmate.server import AppServer


def http_event(url='https://portal.example.test/api/invoices/1',identity='customer-a',body=''):
    return http_record({'url':url,'method':'POST','headers':[{'name':'Authorization','value':'Bearer never-store'},{'name':'Cookie','value':'session=never-store'},{'name':'Content-Type','value':'application/json'},{'name':'Content-Length','value':'999'}],'postData':{'text':body}},
                       {'status':200,'content':{'text':'{"owner":"customer-a"}'}},'test-project',identity)


class ProjectTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.store=Store(self.directory.name)
        self.eid=self.store.create_engagement('Project lab',['portal.example.test'])['id']
        self.project=projects.create_project(self.store,self.eid,'practice.burp')
        self.pid=self.project['id']

    def tearDown(self):self.directory.cleanup()

    def imported(self):
        result=projects.ingest_batch(self.store,self.eid,self.pid,[http_event(body='{"invoice":1}')])
        projects.complete_import(self.store,self.eid,self.pid)
        return self.store.event(self.eid,result['ids'][0])

    def context_item(self,event):
        return {'title':'Check invoice access','assessment':'needs_validation','explanation':'Ownership has not been established in the captured request.',
                'evidence':[event['id']],'counter_evidence':[],'false_positive_checks':['Use two known owners and compare the actual response body.'],
                'manual_tests':[{'title':'Compare another account','purpose':'Change only the account authorization.','expected':'A response containing another account’s object supports the hypothesis; a denial may refute it for this object only.',
                                 'evidence_id':event['id'],'changes':{'headers':{'Authorization':'Bearer <OTHER_ACCOUNT_TOKEN>','Cookie':None}}}]}

    def test_native_upload_is_private_staging_not_fake_parsing(self):
        raw=b'unknown-native-project\x00\xffbinary-data'
        p=projects.upload(self.store,self.eid,'client.burp',len(raw),io.BytesIO(raw))
        self.assertEqual(p['status'],'awaiting_data')
        self.assertEqual(p['sha256'],hashlib.sha256(raw).hexdigest())
        path=projects.archive_path(self.store,self.eid,p['id'])
        self.assertEqual(path.read_bytes(),raw)
        self.assertEqual(os.stat(path).st_mode & 0o777,0o600)
        self.assertEqual(self.store.events(self.eid),[])
        with self.assertRaises(ValueError),patch('fieldmate.review.completion') as model:
            AnalysisManager(self.store).start(self.eid,project_id=p['id'])
        model.assert_not_called()

    def test_incomplete_and_oversized_uploads_leave_no_archive(self):
        with self.assertRaises(ValueError):projects.upload(self.store,self.eid,'bad.burp',100,io.BytesIO(b'x'))
        self.assertEqual(list((self.store.directory/'projects').iterdir()),[])
        with self.assertRaises(ValueError):projects.upload(self.store,self.eid,'huge.burp',projects.MAX_PROJECT_BYTES+1,io.BytesIO())
        with self.assertRaises(ValueError):projects.upload(self.store,self.eid,'script.sh',1,io.BytesIO(b'x'))

    def test_ten_gib_boundary_accepts_streaming_and_rejects_larger_files(self):
        # Exercise the boundary without allocating or writing a ten-GiB test artifact.
        class ShortStream:
            def __init__(self):self.read_sizes=[]
            def read(self,size):self.read_sizes.append(size);return b''
        stream=ShortStream()
        with patch('fieldmate.projects.shutil.disk_usage') as disk:
            disk.return_value.free=11*1024**3
            with self.assertRaisesRegex(ValueError,'incomplete'):
                projects.upload(self.store,self.eid,'large.burp',10*1024**3,stream)
        self.assertEqual(stream.read_sizes,[1024**2])
        self.assertEqual(list((self.store.directory/'projects').iterdir()),[])
        stream=ShortStream()
        with self.assertRaisesRegex(ValueError,'10 GiB'):
            projects.upload(self.store,self.eid,'oversized.burp',10*1024**3+1,stream)
        self.assertEqual(stream.read_sizes,[])

    def test_native_archive_never_falls_back_to_terminal_import(self):
        with self.assertRaisesRegex(ValueError,'Native archives are not text'):
            parse_export('project.burp','GET /secret HTTP/1.1')

    def test_project_isolation_and_credential_redaction(self):
        event=self.imported()
        self.assertEqual(event['metadata']['project_id'],self.pid)
        self.assertNotIn('never-store',json.dumps(event))
        other=self.store.create_engagement('Other',['portal.example.test'])['id']
        with self.assertRaises(KeyError):projects.project(self.store,other,self.pid)
        with self.assertRaises(KeyError):projects.ingest_batch(self.store,other,self.pid,[http_event()])

    def test_burp_issue_report_imports_claim_and_actual_messages(self):
        req=base64.b64encode(b'GET /api/test HTTP/1.1\r\nHost: portal.example.test\r\n\r\n').decode()
        res=base64.b64encode(b'HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{"error":"denied"}').decode()
        xml=f'<issues><issue><name>Potential authorization issue</name><host>https://portal.example.test</host><path>/api/test</path><severity>High</severity><confidence>Tentative</confidence><issueDetail>Scanner claim only</issueDetail><requestresponse><request base64="true">{req}</request><response base64="true">{res}</response></requestresponse></issue></issues>'
        records=parse_export('issues.xml',xml)
        self.assertEqual([r['kind'] for r in records],['http','scanner_issue'])
        ids=projects.ingest_batch(self.store,self.eid,self.pid,records)['ids']
        message,issue=[self.store.event(self.eid,i) for i in ids]
        self.assertIn(message['metadata']['http_key'],issue['metadata']['http_keys'])
        self.assertEqual(message['metadata']['status'],403)
        self.assertEqual(self.store.findings(self.eid),[])

    def test_repeater_has_only_captured_destination_and_secret_placeholders(self):
        event=self.imported();value=template(event)
        self.assertTrue(value['never_sent'])
        self.assertEqual(value['destination'],{'host':'portal.example.test','port':443,'tls':True})
        self.assertIn('POST /api/invoices/1 HTTP/1.1\r\nHost: portal.example.test',value['request'])
        self.assertIn('<YOUR_AUTHORIZATION_VALUE>',value['request'])
        self.assertNotIn('never-store',value['request'])
        self.assertNotIn('Content-Length: 999',value['request'])
        self.assertIn('Content-Length: 13',value['request'])

    def test_request_changes_cannot_inject_host_or_another_request(self):
        event=self.imported()
        for change in [{'headers':{'Host':'outside.test'}},{'path':'https://outside.test/a'},{'path':'//outside.test/a'},{'path':'/a\r\nGET /admin HTTP/1.1'},{'headers':{'X-Test':'ok\r\nHost: outside.test'}},{'path':'/a%0d%0aX:yes'},{'method':'CONNECT'}]:
            with self.subTest(change=change),self.assertRaises(ValueError):template(event,change)

    def test_manual_control_can_remove_authentication_without_sending(self):
        event=self.imported();value=template(event,{'headers':{'Authorization':None,'Cookie':None}})
        self.assertNotIn('Authorization:',value['request'])
        self.assertNotIn('Cookie:',value['request'])
        self.assertTrue(value['never_sent'])

    def test_out_of_scope_and_nonhttp_templates_rejected(self):
        event=self.imported()
        with self.assertRaises(ValueError):template({**event,'scope_state':'out_of_scope'})
        with self.assertRaises(ValueError):template({**event,'kind':'scanner_issue'})

    def test_likely_false_positive_requires_captured_counter_evidence(self):
        event=self.imported();item=self.context_item(event);item['assessment']='likely_false_positive'
        context={'evidence':[event]};lookup={event['id']:event}
        with self.assertRaisesRegex(ValueError,'counter-evidence'):parse(json.dumps({'assessments':[item]}),context,lookup)
        item['counter_evidence']=[event['id']]
        accepted=parse(json.dumps({'assessments':[item]}),context,lookup)
        self.assertEqual(accepted[0]['assessment'],'likely_false_positive')
        self.assertTrue(accepted[0]['manual_tests'][0]['never_sent'])

    def test_invented_or_other_batch_evidence_is_rejected(self):
        event=self.imported();item=self.context_item(event);item['evidence']=['invented']
        with self.assertRaises(ValueError):parse(json.dumps({'assessments':[item]}),{'evidence':[event]},{event['id']:event})

    def test_chunked_review_covers_all_events_without_confirming_findings(self):
        self.store.save_settings({'base_url':'http://127.0.0.1:8888','model':'synthetic','context_chars':4000})
        events=[http_event(f'https://portal.example.test/api/{i}',body='x'*1000) for i in range(12)]
        projects.ingest_batch(self.store,self.eid,self.pid,events);projects.complete_import(self.store,self.eid,self.pid)
        calls=[]
        def fake(settings,messages):
            context=json.loads(messages[1]['content']);calls.append(context)
            event=self.store.event(self.eid,context['evidence'][0]['id'])
            return json.dumps({'assessments':[self.context_item(event)]})
        manager=AnalysisManager(self.store)
        with patch('fieldmate.review.completion',side_effect=fake):
            job=manager.start(self.eid,project_id=self.pid)
            deadline=time.monotonic()+5
            while manager.lock.locked() and time.monotonic()<deadline:time.sleep(.01)
        run=projects.runs(self.store,self.eid)[0]
        self.assertEqual(run['status'],'complete',run['message'])
        self.assertEqual(run['reviewed_events'],12)
        self.assertGreater(len(calls),1)
        self.assertTrue(all(len(json.dumps(c,ensure_ascii=False))<=4000 for c in calls))
        self.assertEqual(self.store.findings(self.eid),[])
        items=projects.assessments(self.store,self.eid)
        self.assertTrue(items)
        self.assertTrue(all(i['disposition']=='open' for i in items))
        projects.disposition(self.store,self.eid,items[0]['id'],'ruled_out')
        self.assertEqual(projects.assessments(self.store,self.eid)[0]['disposition'],'ruled_out')
        self.assertIn('manual Repeater use',self.store.report(self.eid))

    def test_cancellation_does_not_contact_the_model(self):
        self.imported();self.store.save_settings({'base_url':'http://127.0.0.1:8888','model':'synthetic'})
        self.store.execute("INSERT INTO review_runs VALUES('cancel',?,?,'running',0,0,0,0,0,'',?,'')",(self.eid,self.pid,'2026-10-27'))
        cancel=threading.Event();cancel.set()
        with patch('fieldmate.review.completion') as model:
            message,status=review_project(self.store,self.eid,self.pid,'cancel',cancel)
        self.assertEqual(status,'cancelled');model.assert_not_called()


class ProjectAPI(unittest.TestCase):
    def test_real_model_round_trip_never_contacts_the_test_target(self):
        target_hits=[]
        class Target(BaseHTTPRequestHandler):
            def do_GET(self):target_hits.append(self.path);self.send_response(200);self.end_headers()
            def do_POST(self):target_hits.append(self.path);self.send_response(200);self.end_headers()
            def log_message(self,*args):pass
        class Model(BaseHTTPRequestHandler):
            def do_POST(self):
                payload=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                context=json.loads(payload['messages'][1]['content']);event=context['evidence'][0]
                item={'title':'Compare baseline and unauthenticated control','assessment':'needs_validation','explanation':'A captured authenticated response is not enough to establish authorization behavior.',
                    'evidence':[event['id']],'counter_evidence':[],'false_positive_checks':['Check actual ownership and compare response contents.'],
                    'manual_tests':[{'title':'Unauthenticated control','purpose':'Remove the credential header only.','expected':'Compare the object and ownership, rather than relying on status alone.','evidence_id':event['id'],'changes':{'headers':{'Authorization':None,'Cookie':None}}}]}
                raw=json.dumps({'choices':[{'message':{'content':json.dumps({'assessments':[item]})}}]}).encode()
                self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            def log_message(self,*args):pass
        target=ThreadingHTTPServer(('127.0.0.1',0),Target);model=ThreadingHTTPServer(('127.0.0.1',0),Model)
        for server in (target,model):threading.Thread(target=server.serve_forever,daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                store=Store(directory);eid=store.create_engagement('Never execute lab',['127.0.0.1'])['id']
                pid=projects.create_project(store,eid,'saved-project')['id']
                projects.ingest_batch(store,eid,pid,[http_event(f'http://127.0.0.1:{target.server_port}/resource')]);projects.complete_import(store,eid,pid)
                store.save_settings({'base_url':f'http://127.0.0.1:{model.server_port}/v1','model':'synthetic'})
                manager=AnalysisManager(store);manager.start(eid,project_id=pid)
                deadline=time.monotonic()+5
                while manager.lock.locked() and time.monotonic()<deadline:time.sleep(.01)
                run=projects.runs(store,eid)[0]
                self.assertEqual(run['status'],'complete',run['message'])
                item=projects.assessments(store,eid)[0]
                self.assertEqual(item['manual_tests'][0]['destination']['port'],target.server_port)
                self.assertTrue(item['manual_tests'][0]['never_sent'])
                self.assertEqual(target_hits,[])
        finally:
            for server in (target,model):server.shutdown();server.server_close()

    def test_upload_download_and_repeater_are_passive_http_endpoints(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Store(directory);eid=store.create_engagement('API lab',['portal.example.test'])['id']
            server=AppServer(('127.0.0.1',0),store);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            def call(method,path,body=b'',mime='application/json',extra=None):
                headers={'Authorization':'Bearer '+store.token,'Content-Type':mime,**(extra or {})}
                connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=10)
                connection.request(method,f'/api/engagements/{eid}/'+path,body,headers)
                response=connection.getresponse();result=response.status,response.read();connection.close();return result
            try:
                raw=b'synthetic project bytes\0\xff'
                status,body=call('POST','projects',raw,'application/octet-stream',{'X-Filename':'practice.burp'})
                self.assertEqual(status,201);pid=json.loads(body)['id']
                self.assertEqual(call('GET',f'projects/{pid}/archive')[1],raw)
                self.assertEqual(call('POST',f'projects/{pid}/review',b'{}')[0],400)
                payload=json.dumps({'events':[http_event()]}).encode()
                status,body=call('POST',f'projects/{pid}/batches',payload)
                self.assertEqual(status,201);identifier=json.loads(body)['ids'][0]
                self.assertEqual(call('POST',f'projects/{pid}/complete',b'{}')[0],200)
                status,body=call('GET','repeater/'+identifier)
                self.assertEqual(status,200);self.assertTrue(json.loads(body)['never_sent'])
                self.assertEqual(call('POST','execute',b'{}')[0],404)
                self.assertEqual(call('POST','send-request',b'{}')[0],404)
                self.assertEqual(call('POST','repeater/'+identifier,b'{}')[0],404)
            finally:server.shutdown();server.server_close();thread.join()


if __name__=='__main__':unittest.main()
