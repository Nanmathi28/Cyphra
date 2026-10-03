import socket
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.main import app, get_url_predictor
from ml.security.threat_intelligence import OpenPhishCommunityFeedProvider, ThreatIntelligenceAggregator
from ml.features.url_features import URLFeatureExtractor
from ml.security import url_security_analyzer as security_module
from ml.security.url_security_analyzer import URLSecurityAnalyzer


class URLSecurityAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = URLSecurityAnalyzer(timeout_seconds=1.0, max_redirects=5)

    def test_https_and_http_structure(self):
        https = self.analyzer.analyze("https://www.example.com/a/b#section", follow_redirects=False)
        http = self.analyzer.analyze("http://example.org/path", follow_redirects=False)
        self.assertEqual(https["url_structure"]["scheme"], "https")
        self.assertTrue(https["security_indicators"]["https"])
        self.assertEqual(https["url_structure"]["path_depth"], 2)
        self.assertTrue(http["security_indicators"]["http"])
        self.assertFalse(http["security_indicators"]["https"])

    def test_query_and_fragment_parsing(self):
        result = self.analyzer.analyze("https://example.com/search?q=one&lang=en#top", follow_redirects=False)
        self.assertEqual(result["url_structure"]["query"], "q=one&lang=en")
        self.assertEqual(result["url_structure"]["fragment"], "top")
        self.assertEqual(result["phase2_ml_features"]["query_param_count"], 2)

    def test_subdomain_and_registered_domain(self):
        result = self.analyzer.analyze("https://a.b.example.co.uk/page", follow_redirects=False)
        domain = result["domain_characteristics"]
        self.assertEqual(domain["registered_domain"], "example.co.uk")
        self.assertEqual(domain["public_suffix"], "co.uk")
        self.assertEqual(domain["subdomain"], "a.b")
        self.assertEqual(domain["subdomain_count"], result["phase2_ml_features"]["subdomain_count"])
        self.assertEqual(domain["subdomain_count"], 3)
        self.assertEqual(domain["registered_subdomain_count"], 2)

    def test_ip_and_suspicious_structure_evidence(self):
        url = "http://user:secret@192.0.2.10:23/login/verify?account=1"
        result = self.analyzer.analyze(url, follow_redirects=False)
        domain = result["domain_characteristics"]
        indicators = result["security_indicators"]
        self.assertTrue(domain["is_ip_address"])
        self.assertEqual(domain["ip_version"], 4)
        self.assertTrue(indicators["suspicious_patterns"]["userinfo_present"])
        self.assertTrue(indicators["suspicious_patterns"]["at_symbol_present"])
        self.assertTrue(indicators["suspicious_patterns"]["suspicious_port"])
        self.assertGreaterEqual(indicators["suspicious_keyword_count"], 1)
        self.assertNotIn("secret", result["url"])
        self.assertNotIn("secret", result["normalized_url"])
        self.assertNotIn("secret", result["url_structure"]["userinfo"].values())

    def test_scheme_less_host_with_port_is_normalized(self):
        result = self.analyzer.analyze("Example.COM:8080/a", follow_redirects=False)
        self.assertEqual(result["normalized_url"], "http://example.com:8080/a")
        self.assertEqual(result["url_structure"]["port"], 8080)

    def test_malformed_url_is_rejected(self):
        from ml.security.url_security_analyzer import URLInputError
        with self.assertRaises(URLInputError):
            self.analyzer.analyze("http://", follow_redirects=False)

    def test_shared_phase2_features_agree(self):
        url = "https://www.sub.example.com/login/path?q=auth&x=1"
        result = self.analyzer.analyze(url, follow_redirects=False)
        features = URLFeatureExtractor().extract_features([url]).iloc[0].to_dict()
        for key in ("url_length", "path_depth", "query_param_count", "has_https", "suspicious_keyword_count", "subdomain_count"):
            self.assertEqual(result["phase2_ml_features"][key], features[key], key)

    def test_redirect_chain_and_destination_features(self):
        responses = [(302, "https://example.com/final?q=1"), (200, None)]
        with patch.object(security_module, "_resolve_public_addresses", return_value=["93.184.216.34"]), \
             patch.object(self.analyzer, "_fetch_once", side_effect=responses):
            result = self.analyzer.analyze_redirects("https://bit.ly/abc")
        self.assertEqual(result["resolution_status"], "reachable")
        self.assertEqual(result["redirect_count"], 1)
        self.assertEqual(result["final_hostname"], "example.com")
        self.assertTrue(result["domain_changed"])
        self.assertTrue(result["crossed_registered_domains"])
        self.assertTrue(result["shortened_url_expanded"])
        self.assertEqual(result["final_destination_features"]["domain_characteristics"]["registered_domain"], "example.com")

    def test_excessive_redirect_indicator_is_evidence_only(self):
        responses = [(302, f"/hop/{index + 1}") for index in range(4)] + [(200, None)]
        with patch.object(security_module, "_resolve_public_addresses", return_value=["93.184.216.34"]), \
             patch.object(self.analyzer, "_fetch_once", side_effect=responses):
            result = self.analyzer.analyze_redirects("https://example.com/start")
        self.assertEqual(result["redirect_count"], 4)
        self.assertTrue(result["excessive_redirects"])
        self.assertEqual(result["resolution_status"], "reachable")

    def test_timeout_and_private_destination_are_structured(self):
        with patch.object(security_module, "_resolve_public_addresses", return_value=["93.184.216.34"]), \
             patch.object(self.analyzer, "_fetch_once", side_effect=socket.timeout()):
            timed_out = self.analyzer.analyze_redirects("https://example.com")
        blocked = self.analyzer.analyze_redirects("http://127.0.0.1/admin")
        self.assertEqual(timed_out["resolution_status"], "timeout")
        self.assertEqual(blocked["resolution_status"], "blocked")
        self.assertEqual(blocked["reason"], "non_public_ip_address")

    def test_live_public_redirect_is_network_tolerant(self):
        result = self.analyzer.analyze_redirects("https://httpbin.org/redirect/1")
        self.assertIn(result["resolution_status"], {"reachable", "timeout", "unreachable", "blocked", "error"})
        self.assertLessEqual(result["redirect_count"], self.analyzer.max_redirects)

    def test_backend_endpoint_uses_saved_model_and_returns_evidence(self):
        get_url_predictor.cache_clear()
        aggregator = ThreatIntelligenceAggregator([OpenPhishCommunityFeedProvider(enabled=False)])
        with patch("backend.main.threat_intelligence_aggregator", aggregator), TestClient(app) as client:
            response = client.post("/api/v1/analyze/url", json={"url": "https://example.com/login", "follow_redirects": False})
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertIn(body["ml"]["prediction"], {"benign", "defacement", "malware", "phishing"})
        self.assertTrue(body["security_indicators"]["https"])
        self.assertIsNone(body["security_indicators"]["excessive_redirects"])
        self.assertIn(body["risk_decision"]["risk_level"], {"SAFE", "SUSPICIOUS", "MALICIOUS"})
        self.assertEqual(body["risk_decision"]["decision_policy_version"], "3C-v1")
        self.assertEqual(body["threat_intelligence"]["status"], "unavailable")
        self.assertEqual(body["threat_intelligence"]["providers"][0]["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
