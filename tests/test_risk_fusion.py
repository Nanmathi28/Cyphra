import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from ml.security import url_security_analyzer as security_module

import backend.main as backend_main
from ml.security.risk_fusion import RiskFusionEngine
from ml.security.threat_intelligence import ThreatIntelligenceAggregator, ThreatIntelligenceProvider
from ml.security.url_security_analyzer import URLSecurityAnalyzer


class MatchedProvider(ThreatIntelligenceProvider):
    name = "test_openphish"

    def check(self, normalized_url):
        return {
            "provider": self.name,
            "status": "matched",
            "checked": True,
            "matched": True,
            "category": "phishing",
            "details": {"source": "automated_test"},
        }


class RiskFusionTests(unittest.TestCase):
    def setUp(self):
        self.engine = RiskFusionEngine()
        self.analyzer = URLSecurityAnalyzer()
        self.ti_clean = {
            "status": "not_matched",
            "providers": [{"provider": "openphish_community_feed", "status": "not_matched",
                           "checked": True, "matched": False, "category": None, "details": None}],
            "matched_providers": [], "categories": [],
        }

    @staticmethod
    def ml(label="benign", confidence=0.97, probabilities=None):
        if probabilities is None:
            probabilities = {"benign": 0.97, "defacement": 0.01, "malware": 0.01, "phishing": 0.01}
        return {"prediction": label, "prediction_index": 0, "confidence": confidence,
                "probabilities": probabilities, "model": "cnn_bilstm"}

    def analyze(self, url):
        return self.analyzer.analyze(url, follow_redirects=False)

    def redirect_result(self, url, responses):
        with patch.object(security_module, "_resolve_public_addresses", return_value=["93.184.216.34"]), \
             patch.object(self.analyzer, "_fetch_once", side_effect=responses):
            return self.analyzer.analyze_redirects(url)

    def evaluate(self, url="https://example.com/", ml=None, security=None, ti=None, redirect=None):
        security = security if security is not None else self.analyze(url)
        return self.engine.evaluate(
            url,
            self.ml() if ml is None else ml,
            security,
            self.ti_clean if ti is None else ti,
            security.get("redirect_analysis") if redirect is None else redirect,
        )

    def assert_decision(self, result, risk, action):
        self.assertEqual(result["risk_level"], risk)
        self.assertEqual(result["action"], action)
        self.assertGreaterEqual(result["decision_confidence"], 0.0)
        self.assertLessEqual(result["decision_confidence"], 1.0)
        self.assertEqual(result["decision_policy_version"], "3C-v1")
        self.assertIsInstance(result["reasons"], list)
        self.assertIn("evidence_summary", result)

    def test_clearly_benign_evidence_is_safe_without_guarantee(self):
        result = self.evaluate(redirect=self.redirect_result("https://example.com/", [(200, None)]))
        self.assert_decision(result, "SAFE", "PROCEED")
        self.assertEqual(result["evidence_quality"], "complete")
        self.assertIn("NO_SIGNIFICANT_RISK_INDICATORS", [r["code"] for r in result["reasons"]])
        self.assertEqual(result["evidence_summary"]["ml"]["malicious_probability"], 0.03)

    def test_phishing_prediction_with_suspicious_url_is_suspicious_when_below_block_gate(self):
        url = "http://secure-login-bank.com/account/verify"
        result = self.evaluate(url, ml=self.ml("phishing", 0.82,
            {"benign": 0.18, "defacement": 0.0, "malware": 0.0, "phishing": 0.82}))
        self.assert_decision(result, "SUSPICIOUS", "CAUTION")
        codes = [reason["code"] for reason in result["reasons"]]
        self.assertIn("ML_PHISHING", codes)
        self.assertIn("SUSPICIOUS_KEYWORDS", codes)
        self.assertIn("HTTP_SCHEME", codes)

    def test_strong_malware_prediction_plus_structure_blocks(self):
        url = "http://192.0.2.10:23/admin"
        result = self.evaluate(url, ml=self.ml("malware", 0.96,
            {"benign": 0.02, "defacement": 0.01, "malware": 0.96, "phishing": 0.01}))
        self.assert_decision(result, "MALICIOUS", "BLOCK")
        codes = [reason["code"] for reason in result["reasons"]]
        self.assertIn("ML_MALWARE", codes)
        self.assertIn("IP_LITERAL", codes)

    def test_defacement_prediction_is_explained(self):
        result = self.evaluate(ml=self.ml("defacement", 0.7,
            {"benign": 0.2, "defacement": 0.7, "malware": 0.05, "phishing": 0.05}))
        self.assert_decision(result, "SUSPICIOUS", "CAUTION")
        self.assertIn("ML_DEFACEMENT", [reason["code"] for reason in result["reasons"]])

    def test_checked_threat_intelligence_match_blocks_and_preserves_provider(self):
        ti = ThreatIntelligenceAggregator([MatchedProvider()]).check("https://example.com/")
        result = self.evaluate(ti=ti)
        self.assert_decision(result, "MALICIOUS", "BLOCK")
        self.assertEqual(result["evidence_summary"]["threat_intelligence"]["matched_providers"], ["test_openphish"])
        reason = next(reason for reason in result["reasons"] if reason["code"] == "THREAT_INTELLIGENCE_MATCH")
        self.assertIn("test_openphish", reason["message"])

    def test_unavailable_threat_intelligence_is_limited_not_malicious(self):
        unavailable = {"status": "unavailable", "providers": [], "matched_providers": [], "categories": []}
        result = self.evaluate(ti=unavailable, redirect=self.redirect_result("https://example.com/", [(200, None)]))
        self.assert_decision(result, "SUSPICIOUS", "CAUTION")
        self.assertEqual(result["evidence_quality"], "limited")
        self.assertIn("THREAT_INTELLIGENCE_UNAVAILABLE", [r["code"] for r in result["reasons"]])

    def test_http_only_is_caution_not_malicious(self):
        result = self.evaluate("http://example.com/")
        self.assert_decision(result, "SUSPICIOUS", "CAUTION")
        self.assertIn("HTTP_SCHEME", [r["code"] for r in result["reasons"]])

    def test_ip_literal_and_userinfo_are_reported(self):
        ip_result = self.evaluate("http://192.0.2.10/")
        userinfo_result = self.evaluate("https://user@example.com/")
        self.assertIn("IP_LITERAL", [r["code"] for r in ip_result["reasons"]])
        self.assertIn("USERINFO_PRESENT", [r["code"] for r in userinfo_result["reasons"]])
        self.assert_decision(userinfo_result, "SUSPICIOUS", "CAUTION")

    def test_punycode_is_reported(self):
        result = self.evaluate("https://xn--e1afmkfd.example/")
        self.assertIn("PUNYCODE_HOSTNAME", [r["code"] for r in result["reasons"]])

    def test_known_shortener_is_a_weak_signal(self):
        result = self.evaluate("https://bit.ly/abc")
        self.assert_decision(result, "SUSPICIOUS", "CAUTION")
        self.assertIn("URL_SHORTENER", [r["code"] for r in result["reasons"]])

    def test_cross_domain_redirect_is_suspicious_evidence(self):
        redirect = self.redirect_result("https://example.com/", [(302, "https://destination.example.net/"), (200, None)])
        result = self.evaluate(redirect=redirect)
        self.assert_decision(result, "SUSPICIOUS", "CAUTION")
        codes = [reason["code"] for reason in result["reasons"]]
        self.assertIn("CROSS_DOMAIN_REDIRECT", codes)
        self.assertIn("DESTINATION_CHANGED", codes)

    def test_excessive_redirects_are_suspicious_evidence(self):
        redirect = self.redirect_result(
            "https://example.com/start",
            [(302, f"/hop/{index + 1}") for index in range(4)] + [(200, None)],
        )
        result = self.evaluate(redirect=redirect)
        self.assert_decision(result, "SUSPICIOUS", "CAUTION")
        self.assertIn("EXCESSIVE_REDIRECTS", [reason["code"] for reason in result["reasons"]])

    def test_redirect_timeout_is_unavailable_not_malicious(self):
        redirect = self.redirect_result("https://example.com/", [TimeoutError()])
        result = self.evaluate(redirect=redirect)
        self.assert_decision(result, "SUSPICIOUS", "CAUTION")
        self.assertEqual(result["evidence_quality"], "limited")
        self.assertIn("REDIRECT_ANALYSIS_UNAVAILABLE", [reason["code"] for reason in result["reasons"]])

    def test_benign_ml_conflicts_with_suspicious_structure_and_reduces_confidence(self):
        result = self.evaluate("https://user@example.com/")
        self.assert_decision(result, "SUSPICIOUS", "CAUTION")
        self.assertEqual(result["decision_confidence"], 0.5)

    def test_ml_unavailable_does_not_become_safe(self):
        result = self.evaluate(ml={"status": "unavailable", "model": "cnn_bilstm"})
        self.assert_decision(result, "SUSPICIOUS", "CAUTION")
        self.assertEqual(result["evidence_quality"], "limited")
        self.assertIn("ML_UNAVAILABLE", [reason["code"] for reason in result["reasons"]])

    def test_invalid_url_gets_non_proceed_decision(self):
        result = self.engine.evaluate("http://", self.ml(), self.analyze("https://example.com/"), self.ti_clean)
        self.assert_decision(result, "SUSPICIOUS", "CAUTION")
        self.assertEqual([reason["code"] for reason in result["reasons"]], ["URL_INVALID"])

    def test_analyzer_failure_is_explicit_and_limited(self):
        result = self.engine.evaluate("https://example.com/", self.ml(), None, self.ti_clean)
        self.assert_decision(result, "SUSPICIOUS", "CAUTION")
        self.assertEqual(result["evidence_quality"], "limited")
        self.assertIn("ANALYZER_UNAVAILABLE", [reason["code"] for reason in result["reasons"]])

    def test_blocked_private_destination_is_caution(self):
        redirect = self.analyzer.analyze_redirects("http://127.0.0.1/admin")
        result = self.evaluate("http://127.0.0.1/admin", redirect=redirect)
        self.assert_decision(result, "SUSPICIOUS", "CAUTION")
        self.assertIn("DESTINATION_BLOCKED", [reason["code"] for reason in result["reasons"]])

    def test_endpoint_returns_limited_decision_when_analyzer_fails(self):
        with patch.object(backend_main.url_security_analyzer, "analyze", side_effect=RuntimeError("internal detail")), \
             patch.object(backend_main, "get_url_predictor") as predictor, \
             TestClient(backend_main.app) as client:
            response = client.post("/api/v1/analyze/url", json={"url": "https://example.com/", "follow_redirects": False})
        self.assertEqual(response.status_code, 200, response.text)
        predictor.assert_not_called()
        body = response.json()
        self.assertIsNone(body["url"])
        self.assertEqual(body["risk_decision"]["risk_level"], "SUSPICIOUS")
        self.assertEqual(body["risk_decision"]["action"], "CAUTION")
        self.assertEqual(body["risk_decision"]["evidence_quality"], "limited")
        self.assertIn("ANALYZER_UNAVAILABLE", [r["code"] for r in body["risk_decision"]["reasons"]])
        self.assertNotIn("internal detail", response.text)

    def test_weak_ml_without_corroboration_does_not_block(self):
        result = self.evaluate(ml=self.ml("malware", 0.55,
            {"benign": 0.45, "defacement": 0.0, "malware": 0.55, "phishing": 0.0}))
        self.assert_decision(result, "SUSPICIOUS", "CAUTION")
        self.assertNotEqual(result["risk_level"], "MALICIOUS")

    def test_endpoint_integrates_mocked_match_and_ml_unavailable(self):
        class UnavailablePredictor:
            def predict(self, url):
                raise FileNotFoundError("saved model missing")

        with patch.object(backend_main, "get_url_predictor", return_value=UnavailablePredictor()), \
             patch.object(backend_main, "threat_intelligence_aggregator", ThreatIntelligenceAggregator([MatchedProvider()])), \
             TestClient(backend_main.app) as client:
            response = client.post("/api/v1/analyze/url", json={"url": "https://example.com/", "follow_redirects": False})
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["ml"]["status"], "unavailable")
        self.assertEqual(body["risk_decision"]["risk_level"], "MALICIOUS")
        self.assertEqual(body["risk_decision"]["action"], "BLOCK")
        self.assertEqual(body["risk_decision"]["decision_policy_version"], "3C-v1")
        self.assertEqual(body["threat_intelligence"]["providers"][0]["status"], "matched")


if __name__ == "__main__":
    unittest.main()
