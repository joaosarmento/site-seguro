"""Domínio recente gera cautela; não é prova de fraude nem de má proteção TLS."""
from datetime import datetime,timezone
import unittest
from unittest.mock import patch
import server
import test_scoring as fixtures

class DomainAgeRiskTests(unittest.TestCase):
    def test_first_week_is_attention_with_independent_technical_score(self):
        for age in (0,1,6):
            with self.subTest(age=age):
                result=fixtures.ScoringTests().analyze(age=age)
                self.assertEqual(result['technicalScore'],100)
                self.assertEqual(result['score'],79)
                self.assertEqual(result['risk']['band'],'medium')
                self.assertEqual(result['measuredScore'],100)
                self.assertEqual(result['level'],'medio')
                self.assertTrue(any(c['code']=='recent_domain' for c in result['risk']['reasons']))

    def test_recent_registration_remains_attention_through_day_31(self):
        for age in (7,15,31):
            with self.subTest(age=age):
                result=fixtures.ScoringTests().analyze(age=age)
                self.assertEqual(result['technicalScore'],100)
                self.assertEqual(result['score'],79)
                self.assertEqual(result['risk']['band'],'medium')
                self.assertEqual(result['level'],'medio')

    def test_age_does_not_add_technical_bonus_or_penalty(self):
        for age in (32,90,5000):
            with self.subTest(age=age):
                result=fixtures.ScoringTests().analyze(age=age)
                self.assertEqual(result['technicalScore'],100)
                self.assertEqual(result['score'],79 if age == 32 else 100)

    def test_missing_age_is_not_classified_as_recent(self):
        result=fixtures.ScoringTests().analyze(age=None)
        self.assertEqual(result['score'],100)
        self.assertEqual(result.get('domainAgeRisk',{}).get('status'),'unverified')
        self.assertFalse(any('Domínio' in c['name'] for c in result['capsApplied']))

    def test_confirmed_threat_overrides_age_and_other_positive_signals(self):
        result=fixtures.ScoringTests().analyze(age=1,malicious=True)
        self.assertEqual(result['score'],10)
        self.assertEqual(result['technicalScore'],100)
        self.assertEqual(result['risk']['band'],'bad')
        self.assertEqual(result['level'],'baixo')

    def test_invalid_certificate_still_dominates_recent_domain(self):
        result=fixtures.ScoringTests().analyze(age=1,tls_valid=False)
        self.assertLessEqual(result['score'],40)
        self.assertEqual(result['level'],'baixo')

class RdapDateTests(unittest.TestCase):
    def test_registration_timezone_is_preserved(self):
        result=server._parse_iso_date('2026-11-04T19:47:30.213-03:00')
        self.assertEqual(result,datetime(2026,11,4,22,47,30,213000,tzinfo=timezone.utc))

    def test_last_update_cannot_replace_registration_date(self):
        data={'events':[{'eventAction':'last changed','eventDate':'2026-11-05T00:00:00Z'},
                        {'eventAction':'registration','eventDate':'2020-01-01T00:00:00Z'}]}
        with patch.object(server,'_api_json',return_value=data):
            result=server._rdap_lookup('example.com')
        self.assertEqual(result,datetime(2020,1,1,tzinfo=timezone.utc))

    def test_no_registration_event_remains_unverified(self):
        data={'events':[{'eventAction':'last update of RDAP database','eventDate':'2026-11-05T00:00:00Z'}]}
        with patch.object(server,'_api_json',return_value=data):
            with self.assertRaises(ValueError):server._rdap_lookup('example.com')

if __name__=='__main__':unittest.main()
