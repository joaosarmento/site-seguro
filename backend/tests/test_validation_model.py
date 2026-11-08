"""Semântica das verificações: sem exceções para empresas ou domínios."""
import unittest
from unittest.mock import patch
import server
import test_scoring as fixtures


class HeaderSemanticsTests(unittest.TestCase):
    def score(self,csp,**extra):
        headers={'content-security-policy':csp,'x-frame-options':'SAMEORIGIN','x-content-type-options':'nosniff'}
        headers.update(extra)
        return server._evaluate_security_headers(headers)[0]

    def test_inline_styles_do_not_weaken_script_policy(self):
        self.assertEqual(self.score("default-src 'self'; style-src 'unsafe-inline'"),
                         self.score("default-src 'self'; style-src 'self'"))

    def test_nonce_and_strict_dynamic_do_not_get_naive_inline_penalty(self):
        self.assertEqual(self.score("script-src 'nonce-YWJjZGVmZ2hpamtsbW5vcA==' 'strict-dynamic' 'unsafe-inline'"),10)

    def test_unsafe_eval_reduces_score_even_with_nonce(self):
        strong=self.score("script-src 'nonce-YWJjZGVmZ2hpamtsbW5vcA=='")
        weak=self.score("script-src 'nonce-YWJjZGVmZ2hpamtsbW5vcA==' 'unsafe-eval'")
        self.assertLess(weak,strong)

    def test_permissions_and_server_banner_are_not_security_points(self):
        strong=self.score("default-src 'self'",**{'permissions-policy':'geolocation=()','server':'Safe'})
        same=self.score("default-src 'self'",**{'server':'ExampleServer/99.1'})
        self.assertEqual(strong,same)

    def test_report_only_csp_is_not_treated_as_enforced(self):
        score,_,_=server._evaluate_security_headers({'content-security-policy-report-only':"default-src 'none'"})
        self.assertEqual(score,0)

    def test_upgrade_only_csp_does_not_claim_script_restrictions(self):
        self.assertLess(self.score('upgrade-insecure-requests'),self.score("script-src 'self'"))

    def test_wildcard_frame_ancestors_does_not_block_framing(self):
        score,_,_=server._evaluate_security_headers({'content-security-policy':"frame-ancestors *"})
        self.assertEqual(score,0)

    def test_scheme_host_wildcards_do_not_protect_against_framing(self):
        score,present,_=server._evaluate_security_headers({'content-security-policy':"frame-ancestors http://* https://*"})
        self.assertEqual(score,0)
        self.assertNotIn('Proteção contra enquadramento',present)

    def test_element_only_script_policy_does_not_restrict_eval_or_handlers(self):
        self.assertLess(self.score("script-src-elem 'self'"),self.score("script-src 'self'"))


class TechnicalIndexTests(unittest.TestCase):
    def test_missing_reputation_does_not_lower_observed_technical_quality(self):
        result=fixtures.ScoringTests().analyze(reputation=None)
        self.assertEqual(result['score'],100)
        self.assertEqual(result['technicalCoverage'],100)
        self.assertEqual(result['coverage'],75)
        self.assertEqual(result['reputationStatus'],'unverified')
        self.assertFalse(result['identityVerified'])
        self.assertTrue(result['partial'])

    def test_apple_like_headers_have_small_justified_deduction(self):
        headers={'content-security-policy':"script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'unsafe-inline'",
                 'x-frame-options':'SAMEORIGIN','x-content-type-options':'nosniff'}
        score,_,_=server._evaluate_security_headers(headers)
        checks=[server._make_check('Outros controles',90,90,'OK'),server._make_check('Cabeçalhos',score,10,'CSP')]
        summary=server._summarize_checks(checks,[])
        self.assertEqual(summary['score'],97)
        self.assertEqual(score,7)

    def test_observed_quality_does_not_impute_missing_points(self):
        checks=[server._make_check('A',63,70,'Observado'),server._make_check('B',None,30,'Ausente')]
        self.assertEqual(server._summarize_checks(checks,[])['score'],90)

    def test_hidden_iframe_alone_is_context_not_proof_of_phishing(self):
        result,error=server._analyze_html(b'<iframe hidden src="/metrics"></iframe>','example.com')
        self.assertIsNone(error)
        self.assertEqual(result['score'],10)
        self.assertEqual(result['critical'],0)

    def test_good_technical_quality_cannot_override_reputation_alert(self):
        checks=[server._make_check('Proteções',100,100,'OK')]
        result=server._summarize_checks(checks,[('URL em base de ameaças',5)])
        self.assertEqual(result['score'],5)

    def test_applied_limit_is_returned_by_api_summary(self):
        result=server._summarize_checks([server._make_check('A',100,100,'OK')],[('Alerta',40)])
        self.assertEqual(result['appliedCap'],{'name':'Alerta','value':40})

    def test_late_verified_tls_is_reflected_in_final_result(self):
        def verified_headers(url):
            server._TLS_SUCCESSES.get()[('example.com',443)] = {'valid':True,'version':'TLSv1.3','issuer':'Test CA'}
            return {'content-security-policy':"default-src 'self'; frame-ancestors 'none'",
                    'x-content-type-options':'nosniff'}, None
        original=server._analyze_url
        def wrapped(raw):
            with patch.object(server,'_fetch_headers',side_effect=verified_headers):
                return original(raw)
        with patch.object(server,'_analyze_url',side_effect=wrapped):
            result=fixtures.ScoringTests().analyze(tls_valid=None)
        tls_check=next(c for c in result['checks'] if c['category']=='TLS')
        self.assertEqual(tls_check['score'],55)
        self.assertEqual(result['technicalCoverage'],100)

    def test_successful_https_connection_is_reused_and_failure_still_wins(self):
        import ssl
        from unittest.mock import MagicMock
        sock=MagicMock()
        sock.getpeercert.return_value={'notAfter':'Jan  1 00:00:00 2030 GMT','issuer':((('organizationName','Test CA'),),)}
        sock.version.return_value='TLSv1.3'
        sock.cipher.return_value=('TLS_AES_256_GCM_SHA384','TLSv1.3',256)
        sock.selected_alpn_protocol.return_value='http/1.1'
        context=MagicMock();context.wrap_socket.return_value=sock
        success_token=server._TLS_SUCCESSES.set({})
        failure_token=server._TLS_OBSERVATIONS.set({})
        connection=server._PinnedHTTP('example.com',443,['93.184.215.14'],context=context)
        try:
            with patch.object(server.socket,'create_connection',return_value=MagicMock()):
                connection.connect()
            with patch.object(server._PinnedHTTP,'connect',side_effect=TimeoutError()):
                result=server._check_tls('example.com')
            self.assertTrue(result['valid'])
            error=ssl.SSLCertVerificationError(1,'INTERNAL')
            error.verify_code=62
            server._record_tls_failure('example.com',443,error)
            self.assertFalse(server._check_tls('example.com')['valid'])
        finally:
            if connection.deadline_timer:connection.deadline_timer.cancel()
            connection.close()
            server._TLS_SUCCESSES.reset(success_token)
            server._TLS_OBSERVATIONS.reset(failure_token)


if __name__=='__main__':unittest.main()
