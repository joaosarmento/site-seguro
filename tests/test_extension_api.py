"""API real de jobs em loopback; motor substituído apenas na fronteira de rede."""
import sys,json,http.client,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
from http.server import ThreadingHTTPServer
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
try:
 import app as bridge
except ModuleNotFoundError:
 import server as bridge
engine=getattr(bridge,'engine',bridge)

class ExtensionApiTests(unittest.TestCase):
 def setUp(self):
  handler=getattr(bridge,'ExtensionHandler',engine.Handler)
  if hasattr(bridge,'JobRegistry'):handler.jobs=bridge.JobRegistry()
  self.httpd=ThreadingHTTPServer(('127.0.0.1',0),handler)
  self.thread=threading.Thread(target=self.httpd.serve_forever,daemon=True);self.thread.start()
  identity_path=Path(__file__).resolve().parents[1]/'backend'/'extension-identity.json'
  self.extension_id=json.loads(identity_path.read_text())['id'] if identity_path.exists() else 'a'*32
  self.origin='chrome-extension://'+self.extension_id
 def tearDown(self):
  self.httpd.shutdown();self.httpd.server_close();self.thread.join()
 def post(self,path,data,origin=None):
  conn=http.client.HTTPConnection('127.0.0.1',self.httpd.server_port,timeout=3)
  headers={'Content-Type':'application/json','Origin':origin if origin is not None else self.origin}
  conn.request('POST',path,json.dumps(data),headers);response=conn.getresponse();raw=response.read();code=response.status;conn.close()
  return code,json.loads(raw)
 def wait_result(self,job):
  for _ in range(100):
   code,data=self.post('/api/extension/status',{'jobId':job})
   if data.get('state')!='pending':return code,data
   time.sleep(.01)
  self.fail('Job não terminou no prazo do teste')
 def test_start_returns_quickly_and_result_preserves_engine_score(self):
  entered=threading.Event();finish=threading.Event()
  def analyze(host,url):
   entered.set();finish.wait(2);return {'url':url,'hostname':host,'score':60,'capsApplied':[{'name':'Domínio recente','value':60}]},False
  with patch.object(engine,'cached_or_analyze',side_effect=analyze):
   try:
    started=time.monotonic();code,data=self.post('/api/extension/start',{'url':'https://example.com/'})
    self.assertEqual(code,202);self.assertLess(time.monotonic()-started,.5)
    self.assertTrue(entered.wait(.5));self.assertRegex(data['jobId'],r'^[A-Za-z0-9_-]{32}$')
    self.assertEqual(self.post('/api/extension/status',{'jobId':data['jobId']})[1]['state'],'pending')
   finally:finish.set()
   code,result=self.wait_result(data['jobId'])
  self.assertEqual(code,200);self.assertEqual(result['state'],'done');self.assertEqual(result['result']['score'],60)
 def test_start_and_result_share_engine_canonical_url(self):
  with patch.object(engine,'cached_or_analyze',side_effect=lambda host,url:({'url':url,'score':90},False)):
   for raw,expected in [('https://example.com/?filter[]=a','https://example.com/?filter%5B%5D=a'),('https://example.com./a[b]','https://example.com/a%5Bb%5D')]:
    with self.subTest(raw=raw):
     code,data=self.post('/api/extension/start',{'url':raw});self.assertEqual(code,202);self.assertEqual(data['url'],expected)
     _,result=self.wait_result(data['jobId']);self.assertEqual(result['result']['url'],expected)
 def test_another_extension_and_external_websites_cannot_start_jobs(self):
  for origin in ['chrome-extension://'+'b'*32,'https://attacker.example','null',self.origin+'.evil']:
   with self.subTest(origin=origin):self.assertEqual(self.post('/api/extension/start',{'url':'https://example.com/'},origin)[0],403)
 def test_invalid_input_does_not_start_worker(self):
  for body in [[],{}, {'url':'file:///etc/passwd'}, {'url':'https://example.com:22/'}, {'url':'https://example.com/','extra':True}]:
   with self.subTest(body=body):self.assertEqual(self.post('/api/extension/start',body)[0],400)
 def test_missing_and_malformed_job_ids_do_not_disclose_results(self):
  self.assertEqual(self.post('/api/extension/status',{'jobId':'!'})[0],400)
  self.assertEqual(self.post('/api/extension/status',{'jobId':'z'*32})[0],404)
 def test_private_destinations_remain_blocked_by_engine(self):
  code,data=self.post('/api/extension/start',{'url':'http://127.0.0.1/'})
  self.assertEqual(code,202)
  code,data=self.wait_result(data['jobId'])
  self.assertEqual(data['state'],'error');self.assertNotIn('score',data)
 def test_saturation_is_bounded_and_not_queued(self):
  acquired=0
  try:
   for _ in range(3):self.assertTrue(engine.ANALYSIS_SLOTS.acquire(False));acquired+=1
   self.assertEqual(self.post('/api/extension/start',{'url':'https://example.com/'})[0],429)
  finally:
   for _ in range(acquired):engine.ANALYSIS_SLOTS.release()
 def test_engine_errors_do_not_expose_internal_exception(self):
  with patch.object(engine,'cached_or_analyze',side_effect=RuntimeError('SECRET_INTERNAL_DETAIL')):
   code,data=self.post('/api/extension/start',{'url':'https://example.com/'})
   self.assertEqual(code,202);_,result=self.wait_result(data['jobId'])
  self.assertEqual(result['state'],'error');self.assertNotIn('SECRET_INTERNAL_DETAIL',json.dumps(result))

if __name__=='__main__':unittest.main()
