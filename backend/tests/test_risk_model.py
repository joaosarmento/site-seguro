import unittest
from risk_model import registrable_domain, brand_signal, age_signal, decide_risk

class DomainTests(unittest.TestCase):
    def test_public_private_wildcard_and_exception_suffixes(self):
        for host,expected in [('a.b.com.br','b.com.br'),('a.cliente.github.io','cliente.github.io'),
                              ('x.store.blogspot.com','store.blogspot.com'),('a.b.ck','a.b.ck'),
                              ('a.www.ck','www.ck'),('127.0.0.1','127.0.0.1')]:
            with self.subTest(host=host): self.assertEqual(registrable_domain(host),expected)
    def test_brand_context(self):
        self.assertIsNone(brand_signal('www.paypal.com'))
        self.assertEqual(brand_signal('paypal.golf')['code'],'brand_unverified')
        self.assertEqual(brand_signal('paypal.com.seguranca-login.net')['code'],'brand_subdomain')
        self.assertEqual(brand_signal('g00gle.example')['code'],'brand_lookalike')
        self.assertEqual(brand_signal('раypal.example')['code'],'brand_lookalike')
        self.assertIsNone(brand_signal('café.example'))
    def test_age_decays_without_day_32_cliff_or_old_domain_bonus(self):
        values=[age_signal(n)['points'] for n in (1,7,31,32,60)]
        self.assertEqual(values,sorted(values,reverse=True))
        self.assertLessEqual(values[2]-values[3],1)
        self.assertIsNone(age_signal(None));self.assertIsNone(age_signal(5000))

class RiskTests(unittest.TestCase):
    def risk(self,**changes):
        args=dict(technical_coverage=100,age_days=5000,brands=[],reputation=[],content=[],tls_invalid=False,http=False,downgrade=False)
        args.update(changes);return decide_risk(**args)
    def test_technical_quality_does_not_cancel_threat(self):
        self.assertEqual(self.risk(reputation=[{'status':'malicious','source':'Safe Browsing','scope':'url'}])['band'],'bad')
    def test_isolated_suspicion_is_attention(self):
        self.assertEqual(self.risk(reputation=[{'status':'suspicious','source':'VirusTotal'}])['band'],'medium')
    def test_age_alone_is_attention_and_combination_is_stronger(self):
        self.assertEqual(self.risk(age_days=1)['band'],'medium')
        self.assertEqual(self.risk(age_days=1,brands=[brand_signal('g00gle.example')],content=[{'code':'external_password_form','points':15,'detail':'Senha para outro domínio.'}])['band'],'bad')
    def test_no_data_is_unknown_and_sso_alone_is_attention(self):
        self.assertEqual(self.risk(technical_coverage=0)['band'],'unknown')
        self.assertEqual(self.risk(content=[{'code':'external_password_form','points':15,'detail':'Autenticação externa.'}])['band'],'medium')
    def test_duplicate_brand_signal_not_counted_twice(self):
        signal=brand_signal('g00gle.example')
        self.assertEqual(self.risk(brands=[signal,signal])['points'],self.risk(brands=[signal])['points'])

if __name__=='__main__':unittest.main()
