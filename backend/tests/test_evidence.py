import time,unittest
from unittest.mock import patch
import server
import test_scoring as fixtures

class ChainTests(unittest.TestCase):
    def test_intermediate_downgrade_is_preserved(self):
        result=fixtures.ScoringTests().analyze(url='https://example.com/',final_url='https://final.example/',redirects=[(302,'http://middle.example/'),(302,'https://final.example/')])
        self.assertEqual(result['risk']['band'],'bad')
        self.assertTrue(any(x['code']=='downgrade' for x in result['risk']['reasons']))
    def test_final_and_intermediate_brand_are_evaluated(self):
        result=fixtures.ScoringTests().analyze(url='https://bit.ly/link',final_url='https://paypal.golf/',redirects=[(302,'https://paypal.golf/')])
        self.assertEqual(result['risk']['band'],'medium')
        self.assertTrue(any(x['code']=='brand_unverified' for x in result['risk']['reasons']))
    def test_threat_on_intermediate_hop_cannot_be_hidden_by_clean_final(self):
        def safe(url,key):return {'status':'malicious' if 'middle' in url else 'clean','detail':'Fixture'}
        with patch.object(server,'_check_safe_browsing',side_effect=safe) as sb,patch.object(server,'_check_virustotal',return_value={'status':'unknown','detail':'Fixture'}),patch.object(server,'_check_urlhaus',return_value={'status':'unknown','detail':'Fixture'}):
            result=fixtures.ScoringTests().analyze(url='https://example.com/',final_url='https://final.example/',redirects=[(302,'https://middle.example/'),(302,'https://final.example/')],providers=True)
        self.assertEqual(result['risk']['band'],'bad');self.assertEqual(sb.call_count,3)

class ReputationTests(unittest.TestCase):
    def vt(self,mal=0,sus=0,days=0):
        data={'data':{'attributes':{'last_analysis_stats':{'malicious':mal,'suspicious':sus,'undetected':80},'last_analysis_date':time.time()-days*86400}}}
        with patch.object(server,'_api_json',return_value=data):return server._check_virustotal('https://example.com/','test')
    def test_one_suspicious_or_malicious_is_not_confirmed(self):
        self.assertEqual(self.vt(sus=1)['status'],'suspicious')
        self.assertEqual(self.vt(mal=1)['status'],'suspicious')
    def test_consistent_detection_and_stale_analysis_differ(self):
        self.assertEqual(self.vt(mal=4)['status'],'malicious')
        self.assertEqual(self.vt(mal=4,days=100)['status'],'historical')
        self.assertEqual(self.vt(days=100)['status'],'unknown')
    def test_sensitive_url_not_sent_to_url_providers(self):
        with patch.object(server,'_check_safe_browsing') as sb,patch.object(server,'_check_virustotal') as vt,patch.object(server,'_check_urlhaus',return_value={'status':'clean','detail':'Sem registros','scope':'host'}) as uh:
            result=server._evaluate_threat_intel('https://example.com/reset?token=private','example.com')
        sb.assert_not_called();vt.assert_not_called();uh.assert_called_once_with('example.com')
    def test_encoded_paths_and_params_are_private(self):
        for url in ['https://example.com/%63allback/session','https://example.com/login;session=secret','https://example.com/%2563allback/session']:
            self.assertTrue(server._private_link(url),url)
    def test_urlhaus_host_and_inactive_records_are_not_active_exact_url(self):
        with patch.dict(server.os.environ,{'URLHAUS_AUTH_KEY':'test'}):
            with patch.object(server,'_api_json',return_value={'query_status':'ok','urls':[{'url_status':'offline'}]}):
                self.assertEqual(server._check_urlhaus('example.com')['status'],'historical')
            with patch.object(server,'_api_json',return_value={'query_status':'ok','url_status':'online'}):
                self.assertEqual(server._check_urlhaus('https://example.com/file')['status'],'malicious')

class ContentTests(unittest.TestCase):
    def content(self,html,url='https://shop.example/account/login'):
        return server._analyze_html(html.encode(),url)[0]
    def test_base_and_relative_action_and_detached_form_input(self):
        for html in ['<base href="https://other.example/"><form action="send"><input type="password"></form>',
                     '<form id="f" action="https://other.example/"></form><input form="f" type="password">']:
            self.assertTrue(self.content(html)['signals'])
        self.assertFalse(self.content('<form action="../session"><input type="password"></form>')['signals'])
    def test_legitimate_auth_provider_is_context_not_fraud(self):
        result=self.content('<form action="https://login.microsoftonline.com/session"><input type="password"></form>')
        self.assertFalse(result['signals'])
    def test_shared_hosting_is_not_same_owner(self):
        result=self.content('<form action="https://attacker.github.io/"><input type="password"></form>','https://victim.github.io/login')
        self.assertEqual(result['signals'][0]['code'],'external_password_form')
    def test_detached_submitter_override_is_resolved(self):
        html='<form id="f"><input type="password"></form><button form="f" formaction="http://collector.example/">Enviar</button>'
        self.assertEqual(self.content(html)['signals'][0]['code'],'insecure_password_form')

if __name__=='__main__':unittest.main()
