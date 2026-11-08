"""Notas estimadas com cobertura variável; nenhuma consulta externa."""
import socket
import unittest
from contextlib import ExitStack
from unittest.mock import patch
import server
import test_scoring as fixtures
import test_server as network_fixtures


class PartialScoringTests(unittest.TestCase):
    def test_missing_reputation_still_produces_weighted_estimate(self):
        result=fixtures.ScoringTests().analyze(reputation=None)
        self.assertEqual(result['score'],100)  # Reputação ausente não é falha técnica.
        self.assertEqual(result['coverage'],75)
        self.assertTrue(result['partial'])
        self.assertEqual(result['coverageLevel'],'média')
        self.assertFalse(result['reputationVerified'])
        self.assertNotEqual(result['level'],'inconclusivo')

    def test_low_coverage_does_not_become_100_percent(self):
        checks=[server._make_check('Texto',10,10,'OK'),server._make_check('Restante',None,90,'Sem dados')]
        result=server._summarize_checks(checks,[])
        self.assertEqual(result['score'],55)
        self.assertEqual(result['measuredScore'],100)
        self.assertEqual(result['coverage'],10)
        self.assertEqual(result['coverageLevel'],'baixa')

    def test_formula_uses_importance_not_count_of_checks(self):
        checks=[server._make_check('Obtido',63,70,'Dados'),server._make_check('Ausente',None,30,'Sem dados')]
        result=server._summarize_checks(checks,[])
        self.assertEqual(result['score'],90)  # Qualidade ponderada observada, sem imputação.
        self.assertEqual(result['coverage'],70)
        self.assertEqual(result['measuredScore'],90)

    def test_unknown_data_is_neutral_not_a_failed_check(self):
        unknown=server._summarize_checks([server._make_check('A',None,100,'Sem dados')],[])
        failed=server._summarize_checks([server._make_check('A',0,100,'Falha observada')],[])
        self.assertEqual(unknown['score'],50)
        self.assertEqual(unknown['coverage'],0)
        self.assertEqual(failed['score'],0)
        self.assertEqual(failed['coverage'],100)

    def test_observed_critical_alert_still_limits_estimate(self):
        checks=[server._make_check('Positivo',10,10,'OK'),server._make_check('Sem dados',None,90,'?')]
        self.assertEqual(server._summarize_checks(checks,[('Certificado inválido',40)])['score'],40)
        self.assertEqual(server._summarize_checks(checks,[('Alerta confirmado',5)])['score'],5)

    def test_each_available_reputation_source_contributes(self):
        clean={'status':'clean','detail':'Sem alerta no teste.'}
        unknown={'status':'unknown','detail':'Não configurada.'}
        with patch.object(server,'_check_safe_browsing',return_value=clean), \
             patch.object(server,'_check_urlhaus',return_value=unknown), \
             patch.object(server,'_check_virustotal',return_value=unknown):
            score,detail,malicious,count=server._evaluate_threat_intel('https://example.com/','example.com')
        self.assertEqual(count,1)
        self.assertEqual(score,15)
        self.assertFalse(malicious)
        check=server._weighted_check('reputation','Reputação',score,15,detail,'Reputação',availability=count/3)
        self.assertIsNone(check['score'])
        self.assertEqual(check['max'],0)
        self.assertEqual(check['status'],'informational')
        self.assertIn('Sem alerta',check['detail'])

    def test_dns_failure_does_not_abort_lexical_estimate(self):
        doubles={
            '_public_addresses':socket.gaierror('DNS indisponível'),
            '_dns_info':{'ok':False,'ips':[],'ipv4':[],'ipv6':[]},
            '_follow_redirects':([], 'https://example.com/','DNS indisponível',True),
            '_check_tls':{'valid':None,'error':'DNS indisponível'},
            '_fetch_headers':(None,'DNS indisponível'),
            'get_domain_age':(None,None,None,'Não consultado'),
            '_evaluate_threat_intel':(None,'Sem configuração',False,0),
            '_fetch_html':(None,'DNS indisponível'),
            '_check_email_security':(None,'Opcional',{}),
        }
        with ExitStack() as stack:
            for name,value in doubles.items():
                stack.enter_context(patch.object(server,name,side_effect=value) if isinstance(value,Exception)
                                    else patch.object(server,name,return_value=value))
            result=server.analyze_url('https://example.com/')
        self.assertEqual(result['score'],55)
        self.assertEqual(result['coverage'],3)
        self.assertEqual(result['technicalCoverage'],5)
        self.assertTrue(result['partial'])
        self.assertEqual(result['coverageLevel'],'baixa')

    def test_redirect_dns_failure_returns_unverified_destination(self):
        response=network_fixtures.Response(302,{'Location':'https://redirect.example/'})
        with patch.object(server,'_fetch',return_value=response), \
             patch.object(server,'_public_addresses',side_effect=socket.gaierror('DNS indisponível')):
            redirects,final,detail,failed=server._follow_redirects('https://example.com/')
        self.assertEqual(final,'https://redirect.example/')
        self.assertEqual(len(redirects),1)
        self.assertTrue(failed)
        self.assertTrue(detail)

    def test_empty_dns_answer_is_unavailable_not_unsafe(self):
        with patch.object(server,'_resolve',return_value=[]):
            with self.assertRaises(socket.gaierror):
                server._public_addresses('example.com',443)


if __name__=='__main__':unittest.main()
