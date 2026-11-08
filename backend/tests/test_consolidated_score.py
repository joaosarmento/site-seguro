import unittest
from unittest.mock import patch
import server
import risk_model
import test_scoring as fixtures

class ConsolidatedPolicyTests(unittest.TestCase):
    def decide(self, records=(), age=None, technical=100, **kwargs):
        risk=risk_model.decide_risk(technical_coverage=kwargs.get('coverage',100),age_days=age,
            brands=kwargs.get('brands',[]),reputation=records,content=kwargs.get('content',[]),
            tls_invalid=kwargs.get('tls_invalid',False),http=kwargs.get('http',False),downgrade=kwargs.get('downgrade',False))
        return risk_model.consolidate_score(technical,risk,list(records))

    def test_fresh_credible_threats_override_perfect_technical_result(self):
        cases=[{'source':'Safe Browsing','status':'malicious','threatTypes':['MALWARE'],'scope':'url'},
               {'source':'URLhaus','status':'malicious','scope':'url'},
               {'source':'VirusTotal','status':'malicious','maliciousEngines':3,'ageDays':1,'scope':'url'}]
        for rec in cases:
            with self.subTest(rec=rec):
                score,decision,risk=self.decide([rec,{'source':'Other','status':'clean'}])
                self.assertLessEqual(score,10);self.assertEqual(decision['severity'],'critical')
                self.assertEqual(risk['band'],'bad');self.assertIn(rec['source'].replace('Safe Browsing','Google Safe Browsing'),risk['reasons'][0]['detail'])

    def test_virustotal_suspicion_malicious_and_history_are_distinct(self):
        cases=[({'status':'suspicious','maliciousEngines':0,'suspiciousEngines':1,'ageDays':1},69,'attention'),
               ({'status':'suspicious','maliciousEngines':1,'suspiciousEngines':0,'ageDays':1},39,'high'),
               ({'status':'malicious','maliciousEngines':2,'suspiciousEngines':0,'ageDays':1},39,'high'),
               ({'status':'historical','maliciousEngines':5,'suspiciousEngines':0,'ageDays':120},79,'attention'),
               ({'status':'historical','maliciousEngines':5,'ageDays':None},79,'attention')]
        for data,limit,severity in cases:
            with self.subTest(data=data):
                score,decision,risk=self.decide([{'source':'VirusTotal','scope':'url',**data}])
                self.assertLessEqual(score,limit);self.assertEqual(decision['severity'],severity)
                self.assertEqual(risk['band'],'bad' if severity=='high' else 'medium')

    def test_urlhaus_scope_and_no_fabricated_active_record(self):
        for status in ('suspicious','historical','malicious'):
            score,decision,_=self.decide([{'source':'URLhaus','status':status,'scope':'host'}])
            self.assertEqual(score,79);self.assertEqual(decision['severity'],'attention')

    def test_unknown_and_clean_are_not_positive_evidence(self):
        score,decision,risk=self.decide([{'source':'VirusTotal','status':'unknown'}, {'source':'URLhaus','status':'clean'}])
        self.assertEqual(score,100);self.assertEqual(decision['severity'],'none');self.assertFalse(risk['reasons'])
        score,decision,risk=self.decide(technical=55,coverage=5)
        self.assertEqual(score,55);self.assertEqual(risk['band'],'unknown');self.assertEqual(decision['severity'],'limited')

    def test_recent_domain_and_combined_signals_are_capped(self):
        self.assertLessEqual(self.decide(age=1)[0],79)
        brand=risk_model.brand_signal('g00gle.example')
        form={'code':'external_password_form','points':15,'detail':'Envio para outro domínio.'}
        self.assertLessEqual(self.decide(age=1,brands=[brand],content=[form])[0],39)

    def test_both_detecting_sources_are_preserved_above_other_reasons(self):
        records=[{'source':'VirusTotal','status':'suspicious','maliciousEngines':1,'ageDays':1,'scope':'url'},
                 {'source':'Safe Browsing','status':'malicious','threatTypes':['SOCIAL_ENGINEERING'],'scope':'url'}]
        score,decision,risk=self.decide(records,age=1)
        self.assertLessEqual(score,10);self.assertEqual(set(decision['evidenceRefs']),{0,1})
        self.assertEqual(risk['reasons'][0]['source'],'Google Safe Browsing')
        self.assertIn('SOCIAL_ENGINEERING',decision['threatTypes'])

    def test_important_certificate_precedes_two_weak_reputation_suspicions(self):
        records=[{'source':'VirusTotal','status':'suspicious','maliciousEngines':0,'suspiciousEngines':1,'ageDays':1,'scope':'url'}]*2
        _,_,risk=self.decide(records,tls_invalid=True)
        self.assertEqual(risk['reasons'][0]['code'],'invalid_tls')

    def test_virustotal_history_keeps_counts_and_high_risk_gives_guidance(self):
        old={'source':'VirusTotal','status':'historical','maliciousEngines':5,'suspiciousEngines':2,'ageDays':120,'scope':'url'}
        _,_,risk=self.decide([old]);self.assertIn('5',risk['reasons'][0]['detail']);self.assertIn('2',risk['reasons'][0]['detail'])
        recent={'source':'VirusTotal','status':'suspicious','maliciousEngines':1,'ageDays':1,'scope':'url'}
        _,_,risk=self.decide([recent]);self.assertIn('Evite',risk['reasons'][0]['detail'])

    def test_combined_weak_signals_are_explained_before_individual_suspicion(self):
        vt={'source':'VirusTotal','status':'suspicious','maliciousEngines':0,'suspiciousEngines':1,'ageDays':1,'scope':'url'}
        score,decision,risk=self.decide([vt],brands=[risk_model.brand_signal('g00gle.example')],http=True)
        self.assertLessEqual(score,39);self.assertEqual(decision['severity'],'high')
        self.assertEqual(risk['reasons'][0]['code'],'combined_signals')
        self.assertIn('marca',risk['reasons'][0]['detail']);self.assertIn('HTTP',risk['reasons'][0]['detail'])
        self.assertEqual(risk['reasons'][1]['source'],'VirusTotal')

class EvidenceIntegrationTests(unittest.TestCase):
    def test_provider_data_reaches_consolidated_result(self):
        fake={'matches':[{'threatType':'SOCIAL_ENGINEERING'}]}
        with patch.dict(server.os.environ,{'SAFE_BROWSING_KEY':'fixture'}),patch.object(server,'_api_json',return_value=fake), \
             patch.object(server,'_check_virustotal',return_value={'status':'unknown','detail':''}), \
             patch.object(server,'_check_urlhaus',return_value={'status':'unknown','detail':''}):
            result=fixtures.ScoringTests().analyze(providers=True)
        self.assertEqual(result['technicalScore'],100);self.assertLessEqual(result['score'],10)
        self.assertEqual(result['decision']['severity'],'critical')
        self.assertEqual(result['decision']['threatTypes'],['SOCIAL_ENGINEERING'])
        self.assertIn('Google Safe Browsing',result['risk']['reasons'][0]['detail'])

    def test_intermediate_alert_preserves_source_and_position(self):
        def safe(url,key):return {'status':'malicious' if 'middle' in url else 'clean','detail':'Fixture','threatTypes':['MALWARE'] if 'middle' in url else []}
        with patch.object(server,'_check_safe_browsing',side_effect=safe),patch.object(server,'_check_virustotal',return_value={'status':'unknown','detail':''}),patch.object(server,'_check_urlhaus',return_value={'status':'unknown','detail':''}):
            result=fixtures.ScoringTests().analyze(url='https://example.com/',final_url='https://final.example/',redirects=[(302,'https://middle.example/'),(302,'https://final.example/')],providers=True)
        hit=next(r for r in result['reputationResults'] if r['source']=='Safe Browsing' and r['status']=='malicious')
        self.assertEqual(hit['chainPosition'],'intermediate');self.assertEqual(hit['chainIndex'],1)
        self.assertLessEqual(result['score'],10)

    def test_urlhaus_unknown_status_is_not_inactive_or_clean(self):
        with patch.dict(server.os.environ,{'URLHAUS_AUTH_KEY':'fixture'}),patch.object(server,'_api_json',return_value={'query_status':'ok','url_status':'unknown'}):
            self.assertEqual(server._check_urlhaus('https://example.com/')['status'],'unknown')

    def test_incomplete_provider_responses_are_unknown(self):
        with patch.object(server,'_api_json',return_value={'matches':[{}]}):
            self.assertEqual(server._check_safe_browsing('https://example.com/','test')['status'],'unknown')
        incomplete={'data':{'attributes':{'last_analysis_stats':{'undetected':80},'last_analysis_date':__import__('time').time()}}}
        with patch.object(server,'_api_json',return_value=incomplete):
            self.assertEqual(server._check_virustotal('https://example.com/','test')['status'],'unknown')

    def test_valid_match_is_not_discarded_when_another_match_is_malformed(self):
        response={'matches':[{'threatType':'MALWARE'},{}]}
        with patch.object(server,'_api_json',return_value=response):
            result=server._check_safe_browsing('https://example.com/','test')
        self.assertEqual(result['status'],'malicious');self.assertEqual(result['threatTypes'],['MALWARE'])

if __name__=='__main__':unittest.main()
