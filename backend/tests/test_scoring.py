"""Propriedades do modelo, usando análise real com fontes externas substituídas."""
from contextlib import ExitStack
import socket
import ssl
import unittest
from unittest.mock import MagicMock, patch
import server


class ScoringTests(unittest.TestCase):
    def analyze(self, ips=None, age=5000, email=5, reputation=15, tls_valid=True, url='https://example.com/', malicious=False, final_url=None, redirects=None, html=b'<html>Example page</html>', providers=False):
        addresses=ips or ['93.184.215.14']
        headers={'strict-transport-security':'max-age=31536000; includeSubDomains; preload',
                 'content-security-policy':"default-src 'self'; frame-ancestors 'none'",
                 'x-frame-options':'DENY','x-content-type-options':'nosniff',
                 'referrer-policy':'no-referrer','permissions-policy':'geolocation=()'}
        doubles={
            '_public_addresses':['93.184.215.14'],
            '_dns_info':{'ok':True,'ips':addresses,'ipv4':[x for x in addresses if ':' not in x],
                         'ipv6':[x for x in addresses if ':' in x]},
            '_follow_redirects':(redirects or [], final_url or url, 'HTTP 200', False),
            '_check_tls':{'valid':tls_valid,'version':'TLSv1.3','issuer':'CA', 'error':'Certificado inválido.'},
            '_fetch_headers':(headers,None),
            'get_domain_age':(age,'2010-01-01','rdap',None),
            '_evaluate_threat_intel':(reputation,'Fonte simulada para teste automatizado.',malicious,0 if reputation is None else 3),
            '_fetch_html':(html,None),
            '_check_email_security':(email,'SPF/DMARC de teste.',{}),
        }
        if providers: doubles.pop('_evaluate_threat_intel')
        with ExitStack() as stack:
            for name,value in doubles.items():stack.enter_context(patch.object(server,name,return_value=value))
            return server.analyze_url(url)

    def test_one_ip_is_not_worse_than_many_ips(self):
        one=self.analyze(ips=['93.184.215.14'])
        many=self.analyze(ips=['93.184.215.14','93.184.215.15','2606:4700:10::6814:179a'])
        self.assertEqual(one['score'],many['score'])
        self.assertEqual(one['coverage'],many['coverage'])

    def test_email_authentication_does_not_change_webpage_score(self):
        self.assertEqual(self.analyze(email=0)['score'],self.analyze(email=5)['score'])

    def test_weighted_contributions_sum_to_100(self):
        result=self.analyze()
        self.assertEqual(sum(c['max'] for c in result['checks']),100)
        by_title={c['title']:c for c in result['checks']}
        self.assertEqual(by_title['Certificado e TLS']['max'],55)
        self.assertEqual(by_title['Threat Intelligence']['max'],0)
        for name in ('Resolução DNS','Segurança de e-mail (SPF/DMARC)','Infraestrutura'):
            self.assertEqual(by_title[name]['max'],0)
            self.assertIsNone(by_title[name]['score'])
        self.assertEqual(result['score'],100)
        self.assertEqual(result['coverage'],100)
        self.assertEqual(result['totalScoredChecks'],5)

    def test_recent_domain_alone_is_not_proof_of_fraud(self):
        result=self.analyze(age=15)
        self.assertFalse(any('recém-criado' in c['name'].lower() for c in result['capsApplied']))
        self.assertEqual(result['score'],79)
        self.assertEqual(result['technicalScore'],100)
        self.assertEqual(result['risk']['band'],'medium')
        self.assertEqual(result['level'],'medio')

    def test_reputation_missing_keeps_numeric_estimate_with_partial_label(self):
        result=self.analyze(reputation=None)
        self.assertEqual(result['score'],100)
        self.assertEqual(result['level'],'alto')
        self.assertTrue(result['partial'])
        self.assertEqual(result['coverage'],75)

    def test_invalid_certificate_cannot_be_offset_by_other_signals(self):
        result=self.analyze(tls_valid=False)
        self.assertLessEqual(result['score'],40)
        self.assertEqual(result['level'],'baixo')

    def test_fuzzy_brand_similarity_is_attention_not_proven_fraud(self):
        result=self.analyze(url='https://gogle.example/')
        self.assertEqual(result['score'],79)
        self.assertEqual(result['technicalScore'],95)
        self.assertEqual(result['risk']['band'],'medium')
        self.assertEqual(result['level'],'medio')

    def test_direct_homoglyph_imitation_keeps_stronger_warning(self):
        result=self.analyze(url='https://g00gle.example/')
        self.assertEqual(result['score'],79)
        self.assertEqual(result['technicalScore'],95)
        self.assertEqual(result['risk']['reasons'][0]['code'],'brand_lookalike')
        self.assertEqual(result['risk']['band'],'medium')


class TlsEvidenceTests(unittest.TestCase):
    def test_observed_bad_certificate_survives_later_timeout(self):
        error=ssl.SSLCertVerificationError(1,'INTERNAL_DETAIL')
        error.verify_code=62
        context=MagicMock()
        context.wrap_socket.side_effect=error
        token=server._TLS_OBSERVATIONS.set({})
        connection=server._PinnedHTTP('example.com',443,['93.184.215.14'],context=context)
        try:
            with patch.object(server.socket,'create_connection',return_value=MagicMock()):
                with self.assertRaises(ssl.SSLCertVerificationError):connection.connect()
            with patch.object(server,'_public_addresses',return_value=['93.184.215.14']), \
                 patch.object(server._PinnedHTTP,'connect',side_effect=socket.timeout()):
                self.assertIs(server._check_tls('example.com')['valid'],False)
                self.assertIsNone(server._check_tls('other.example')['valid'])
        finally:
            connection.close()
            server._TLS_OBSERVATIONS.reset(token)


if __name__=='__main__':unittest.main()
