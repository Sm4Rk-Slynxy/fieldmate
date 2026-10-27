import base64
import http.client
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from fieldmate.core import clean, redact, safe_url, validate_scope, in_scope, image_bytes
from fieldmate.store import Store
from fieldmate.ingest import parse_export, http_record, record
from fieldmate.engine import run_rules, snapshot, build_context, parse_suggestions, analyze, AnalysisManager
from fieldmate.inference import validate_base_url, allowed_address, request_json
from fieldmate.server import AppServer
from fieldmate.client import Client

ROOT = Path(__file__).resolve().parent.parent
PNG = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j2ioAAAAASUVORK5CYII='


class StoreCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(self.temp.name)
        self.engagement = self.store.create_engagement('Lab', ['192.168.56.0/24', 'portal.example.test'])
        self.eid = self.engagement['id']

    def tearDown(self):
        self.temp.cleanup()

    def service(self):
        return self.store.ingest(self.eid, parse_export('scan.xml', (ROOT / 'examples/network.xml').read_text()))['ids']

    def web(self, identity='customer-a'):
        event = http_record({'url':'https://portal.example.test/api/invoice/1', 'method':'GET', 'headers':[{'name':'Authorization','value':'Bearer super-secret'}]},
                            {'status':200,'content':{'text':'{"password":"hidden"}','mimeType':'application/json'}}, 'test', identity)
        return self.store.ingest(self.eid, [event])['ids'][0]


class ScopeAndParsing(unittest.TestCase):
    def test_scope_wildcards_cidr_and_boundary(self):
        scope = validate_scope(['*.example.test', '192.168.56.9/24', '2001:db8::/32'])
        self.assertTrue(in_scope('https://a.example.test/path',scope))
        self.assertFalse(in_scope('example.test',scope))
        self.assertFalse(in_scope('a.example.test.evil.test',scope))
        self.assertTrue(in_scope('192.168.56.20',scope))
        self.assertFalse(in_scope('192.168.57.20',scope))
        self.assertTrue(in_scope('2001:db8::12',scope))

    def test_redaction_nested_headers_json_commands_and_urls(self):
        value = redact({'headers':[{'name':'Authorization','value':'Bearer secret'}], 'password':'secret',
                        'body':'{"access_token":"secret-value"}', 'output':'\x1b[31mAuthorization: Bearer secret\n--password hidden\x1b[0m'})
        raw = json.dumps(value)
        self.assertNotIn('secret',raw.lower())
        self.assertNotIn('hidden',raw)
        self.assertNotIn('31m',raw)
        url = safe_url('https://user:password@portal.example.test/path?token=hidden&invoice=42#secret')
        self.assertNotIn('hidden',url)
        self.assertNotIn('password',url)
        self.assertIn('invoice=42',url)

    def test_nmap_only_open_ports_and_safe_doctype(self):
        content = (ROOT / 'examples/network.xml').read_text().replace('</ports>','<port protocol="tcp" portid="80"><state state="closed"/></port></ports>')
        events = parse_export('scan.xml',content)
        self.assertEqual([r['metadata']['port'] for r in events],[443,445])
        with self.assertRaises(ValueError):
            parse_export('evil.xml','<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun>&x;</nmaprun>')

    def test_burp_base64_and_har_capture_equivalent_content(self):
        request = base64.b64encode(b'GET /api/me HTTP/1.1\r\nHost: portal.example.test\r\nAuthorization: Bearer hidden\r\n\r\n').decode()
        response = base64.b64encode(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"role":"user"}').decode()
        xml = f'<items><item><url>https://portal.example.test/api/me</url><method>GET</method><status>200</status><request base64="true">{request}</request><response base64="true">{response}</response></item></items>'
        event = parse_export('burp.xml',xml,identity='customer-a')[0]
        self.assertEqual(event['metadata']['response_body'],'{"role":"user"}')
        self.assertEqual(event['identity'],'customer-a')
        har = {'log':{'entries':[{'request':{'url':'https://portal.example.test/api/me'},'response':{'status':200,'content':{'text':'hello'}}}]}}
        self.assertEqual(parse_export('zap.har',json.dumps(har))[0]['metadata']['response_body'],'hello')

    def test_import_rejects_invalid_formats_and_nonobjects(self):
        for filename, content in [('bad.xml','<wrong/>'),('bad.har','{}'),('bad.jsonl','[1,2,3]')]:
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                parse_export(filename,content)

    def test_multichunk_terminal_preserves_output(self):
        events = parse_export('terminal.log','x' * 50000,target='192.168.56.1')
        self.assertEqual(''.join(e['content'] for e in events),'x' * 50000)
        self.assertEqual(len(events),3)


class PersistenceAndGrounding(StoreCase):
    def test_private_storage_and_persistent_token(self):
        self.assertEqual(os.stat(self.temp.name).st_mode & 0o777,0o700)
        self.assertEqual(os.stat(Path(self.temp.name) / 'token').st_mode & 0o777,0o600)
        self.assertEqual(Store(self.temp.name).token,self.store.token)

    def test_import_dedup_and_transaction_validation(self):
        events = parse_export('scan.xml',(ROOT / 'examples/network.xml').read_text())
        self.assertEqual(self.store.ingest(self.eid,events)['inserted'],2)
        self.assertEqual(self.store.ingest(self.eid,events)['duplicates'],2)
        with self.assertRaises(ValueError):
            self.store.ingest(self.eid,[record('note','valid','test'), {'kind':'execute'}])
        self.assertEqual(len(self.store.events(self.eid)),2)

    def test_credentials_are_redacted_before_storage(self):
        identifier = self.web()
        raw = json.dumps(self.store.event(self.eid,identifier))
        self.assertNotIn('super-secret',raw)
        self.assertNotIn('hidden',raw)
        self.assertIn('[REDACTED]',raw)

    def test_cookie_attributes_survive_without_cookie_values(self):
        event = http_record({'url':'https://portal.example.test/','headers':[]},
            {'status':200,'headers':[{'name':'Set-Cookie','value':'session=do-not-store; Secure; HttpOnly; SameSite=Lax'}]},'test','customer-a')
        identifier = self.store.ingest(self.eid,[event])['ids'][0]
        event = self.store.event(self.eid,identifier)
        self.assertNotIn('do-not-store',json.dumps(event))
        self.assertEqual(event['metadata']['cookie_attributes'],[{'cookie_name':'session','secure':True,'httponly':True,'samesite':'Lax'}])

    def test_relabel_preserves_evidence_and_updates_coverage_identity(self):
        identifier = self.web('unlabeled')
        run_rules(self.store,self.eid)
        self.store.relabel(self.eid,identifier,'customer-a',True)
        value = snapshot(self.store,self.eid)
        self.assertEqual(self.store.event(self.eid,identifier)['identity'],'customer-a')
        self.assertEqual(value['coverage'][0]['identity'],'customer-a')
        self.assertFalse(any(s['state']=='open' and s['check_name'].endswith(':unlabeled') for s in value['suggestions']))

    def test_error_and_transport_signals_remain_unconfirmed_hypotheses(self):
        event = http_record({'url':'http://portal.example.test/api','headers':[{'name':'Authorization','value':'Bearer never-store'}]},
            {'status':500,'content':{'text':'Traceback (most recent call last):\nFile /app/server.py'}},'test','customer-a')
        self.store.ingest(self.eid,[event]);run_rules(self.store,self.eid)
        signals = [s for s in self.store.suggestions(self.eid) if s['kind']=='hypothesis']
        self.assertEqual(len(signals),2)
        self.assertTrue(all(s['priority']=='high' for s in signals))
        self.assertEqual(self.store.findings(self.eid),[])

    def test_negative_scanner_result_does_not_generate_vulnerability_lead(self):
        event = record('service','scan result','nmap','192.168.56.12',metadata={'port':443,'protocol':'tcp','scripts':[{'id':'example','output':'State: NOT VULNERABLE'}]})
        self.store.ingest(self.eid,[event]);run_rules(self.store,self.eid)
        self.assertFalse(any(s['kind']=='hypothesis' for s in self.store.suggestions(self.eid)))

    def test_out_of_scope_and_unattributed_excluded_from_model(self):
        self.service()
        self.store.ingest(self.eid,[record('terminal','DO NOT INCLUDE OUTSIDE','test','outside.example.test'), record('note','DO NOT INCLUDE UNATTRIBUTED','test')])
        context,_ = build_context(self.store,self.eid)
        raw = json.dumps(context)
        self.assertNotIn('DO NOT INCLUDE',raw)
        self.assertEqual(len(context['evidence']),2)
        value = snapshot(self.store,self.eid)
        self.assertEqual(value['scope_counts']['out_of_scope'],1)
        self.assertEqual(value['scope_counts']['unattributed'],1)

    def test_cross_engagement_and_invented_evidence_rejected(self):
        identifier = self.web()
        other = self.store.create_engagement('Other',['portal.example.test'])['id']
        for eid, ids in [(other,[identifier]),(self.eid,['invented'])]:
            with self.assertRaises(ValueError):
                self.store.save_test(eid,{'subject':'test','check_name':'auth','evidence':ids})

    def test_http_endpoint_cannot_spoof_another_host(self):
        event = record('http','request','test','portal.example.test',metadata={'url':'https://outside.test/x'})
        with self.assertRaises(ValueError): self.store.ingest(self.eid,[event])

    def test_test_results_resolve_only_matching_identity_coverage(self):
        a, b = self.web('customer-a'), self.web('customer-b')
        run_rules(self.store,self.eid)
        self.store.save_test(self.eid,{'subject':'GET https://portal.example.test/api/invoice/1','check_name':'authorization','identity':'customer-a','state':'attempted','evidence':[a]})
        run_rules(self.store,self.eid)
        suggestions = self.store.suggestions(self.eid)
        self.assertEqual(len(suggestions),2)
        self.assertEqual(next(s['state'] for s in suggestions if s['check_name'].endswith('customer-a')),'tested')
        self.assertEqual(next(s['state'] for s in suggestions if s['check_name'].endswith('customer-b')),'open')

    def test_feedback_dismissal_is_not_reset_by_repeated_rules(self):
        self.service(); run_rules(self.store,self.eid)
        suggestion = self.store.suggestions(self.eid)[0]
        self.store.feedback(self.eid,suggestion['id'],'dismissed')
        run_rules(self.store,self.eid)
        self.assertEqual(next(s['state'] for s in self.store.suggestions(self.eid) if s['id'] == suggestion['id']),'dismissed')

    def test_already_tested_feedback_uses_actual_category_and_identity(self):
        self.web(); run_rules(self.store,self.eid)
        suggestion = self.store.suggestions(self.eid)[0]
        self.store.feedback(self.eid,suggestion['id'],'tested')
        test = self.store.tests(self.eid)[0]
        self.assertEqual((test['check_name'],test['identity']),('authorization','customer-a'))

    def test_confirmed_findings_require_complete_evidence_and_export(self):
        identifier = self.web()
        with self.assertRaises(ValueError): self.store.save_finding(self.eid,{'title':'Unsupported','status':'confirmed'})
        self.store.save_finding(self.eid,{'title':'Manually validated example','status':'confirmed','severity':'low','reproduction':'Step 1: compare responses','impact':'Demonstrated in the lab','evidence':[identifier]})
        report = self.store.report(self.eid)
        self.assertIn(identifier,report)
        self.assertIn('Manually validated example',report)
        self.assertNotIn('super-secret',report)

    def test_schema_validation_rejects_model_invented_citations(self):
        self.service(); context,_ = build_context(self.store,self.eid)
        valid = {'title':'Review the service','kind':'hypothesis','priority':'low','observation':'Open service observed','next_step':'Review expected exposure','rationale':'Configuration is unknown','subject':context['allowed_subjects'][0],'check_name':'exposure','evidence':[context['evidence'][0]['id']]}
        self.assertEqual(len(parse_suggestions(json.dumps({'suggestions':[valid]}),context)),1)
        with self.assertRaises(ValueError): parse_suggestions(json.dumps({'suggestions':[{**valid,'evidence':['fake']}]}),context)
        with self.assertRaises(ValueError): parse_suggestions(json.dumps({'suggestions':[{**valid,'subject':'outside.test'}]}),context)
        with self.assertRaises(ValueError): parse_suggestions(json.dumps({'suggestions':[{**valid,'priority':'critical'}]}),context)

    def test_model_cannot_write_findings_or_execute_tools(self):
        self.service()
        self.store.save_settings({'base_url':'http://127.0.0.1:8888','model':'test-model'})
        with patch('fieldmate.engine.completion',return_value='{"suggestions": []}') as model:
            result = analyze(self.store,self.eid)
            self.assertIn('2 of 2',result)
            self.assertIn('UNTRUSTED DATA',model.call_args.args[1][0]['content'])
        self.assertEqual(self.store.findings(self.eid),[])

    def test_screenshots_not_in_snapshot_or_text_only_requests(self):
        self.store.ingest(self.eid,[record('screenshot','A frame','screen','portal.example.test',metadata={'mime':'image/png','image_base64':PNG})])
        self.assertNotIn(PNG,json.dumps(snapshot(self.store,self.eid)))
        context,images = build_context(self.store,self.eid)
        self.assertEqual(images,[])
        self.assertNotIn(PNG,json.dumps(context))
        self.store.save_settings({'vision':True})
        _,images = build_context(self.store,self.eid)
        self.assertEqual(images[0]['data'],PNG)

    def test_background_job_records_failure_and_releases_lock(self):
        manager = AnalysisManager(self.store)
        with patch('fieldmate.engine.analyze',side_effect=ValueError('Model unavailable')):
            job = manager.start(self.eid)
            deadline = time.monotonic() + 3
            while manager.lock.locked() and time.monotonic() < deadline: time.sleep(.01)
        row = self.store.rows('SELECT * FROM analyses WHERE id=?',(job['id'],))[0]
        self.assertEqual(row['status'],'failed')
        self.assertEqual(row['message'],'Model unavailable')
        self.assertFalse(manager.lock.locked())


class NetworkPolicy(unittest.TestCase):
    def test_private_and_loopback_only(self):
        for address in ['127.0.0.1','192.168.1.5','10.1.2.3','172.16.1.1','::1','fd00::1']:
            self.assertTrue(allowed_address(address))
        for address in ['8.8.8.8','169.254.169.254','0.0.0.0','224.0.0.1','100.64.1.1','2001:4860:4860::8888']:
            self.assertFalse(allowed_address(address))

    def test_url_normalization_and_redirect_schemes_rejected(self):
        self.assertEqual(validate_base_url('http://192.168.1.50:8888'),'http://192.168.1.50:8888/v1')
        for url in ['http://8.8.8.8/v1','file:///etc/passwd','http://user:key@localhost:8888','http://localhost/v1?key=secret','http://localhost/arbitrary-route']:
            with self.assertRaises(ValueError): validate_base_url(url)

    def test_public_dns_resolution_rejected_before_connection(self):
        settings = {'base_url':'http://model.example.test/v1','timeout':10}
        with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',80))]), patch('http.client.HTTPConnection') as connection:
            with self.assertRaises(ValueError): request_json(settings,'/models')
            connection.assert_not_called()


class HTTPWorkflow(StoreCase):
    def setUp(self):
        super().setUp()
        self.server = AppServer(('127.0.0.1',0),self.store)
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.port = self.server.server_port
        self.client = Client(self.temp.name,f'http://127.0.0.1:{self.port}')

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        super().tearDown()

    def http(self, method, path, headers=None, body=None):
        connection = http.client.HTTPConnection('127.0.0.1',self.port,timeout=5)
        connection.request(method,path,body,headers or {})
        response = connection.getresponse(); result = (response.status,response.read(),dict(response.getheaders())); connection.close()
        return result

    def test_auth_origin_and_dns_rebinding_guards(self):
        self.assertEqual(self.http('GET','/api/bootstrap')[0],403)
        headers = {'Authorization':'Bearer ' + self.store.token,'Origin':'https://evil.test'}
        self.assertEqual(self.http('GET','/api/bootstrap',headers)[0],403)
        headers = {'Authorization':'Bearer ' + self.store.token,'Host':f'evil.test:{self.port}'}
        self.assertEqual(self.http('GET','/api/bootstrap',headers)[0],403)
        self.assertEqual(self.client.call('bootstrap')['version'],'0.1.0')

    def test_complete_import_feedback_finding_report_workflow(self):
        result = self.client.call(f'engagements/{self.eid}/import',{'filename':'network.xml','content':(ROOT / 'examples/network.xml').read_text()})
        self.assertEqual(result['inserted'],2)
        value = self.client.call(f'engagements/{self.eid}')
        self.assertEqual(len(value['suggestions']),2)
        card = value['suggestions'][0]
        self.client.call(f'engagements/{self.eid}/feedback',{'id':card['id'],'state':'tested'})
        self.client.call(f'engagements/{self.eid}/findings',{'title':'Draft only','evidence':card['evidence']})
        response = self.http('GET',f'/api/engagements/{self.eid}/report',{'Authorization':'Bearer ' + self.store.token})
        self.assertEqual(response[0],200)
        self.assertIn(b'Draft only',response[1])
        self.assertIn('attachment',response[2]['Content-Disposition'])

    def test_api_key_never_returned_and_oversized_body_rejected(self):
        self.client.call('settings',{'base_url':'http://127.0.0.1:8888','api_key':'fake-test-key','model':'test'})
        bootstrap = self.client.call('bootstrap')
        self.assertNotIn('fake-test-key',json.dumps(bootstrap))
        self.assertTrue(bootstrap['settings']['has_api_key'])
        headers = {'Authorization':'Bearer ' + self.store.token,'Content-Type':'application/json','Content-Length':'25000000'}
        self.assertEqual(self.http('POST','/api/settings',headers,b'{}')[0],400)

    def test_screen_api_and_private_image_fetch(self):
        result = self.client.call(f'engagements/{self.eid}/screenshot',{'target':'portal.example.test','image_base64':PNG})
        identifier = result['ids'][0]
        response = self.http('GET',f'/api/engagements/{self.eid}/image/{identifier}',{'Authorization':'Bearer ' + self.store.token})
        self.assertEqual(response[0],200)
        self.assertEqual(response[1],base64.b64decode(PNG))
        self.assertEqual(response[2]['Content-Type'],'image/png')
        self.assertEqual(self.http('GET',f'/api/engagements/{self.eid}/image/{identifier}')[0],403)

    def test_static_assets_csp_and_traversal(self):
        response = self.http('GET','/')
        self.assertEqual(response[0],200)
        self.assertIn("script-src 'self'",response[2]['Content-Security-Policy'])
        self.assertNotIn(self.store.token.encode(),response[1])
        self.assertNotEqual(self.http('GET','/../../etc/passwd')[0],200)


if __name__ == '__main__': unittest.main()
