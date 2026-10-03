import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import backend.main as backend_main
from ml.security.threat_intelligence import (
    OpenPhishCommunityFeedProvider,
    ThreatIntelligenceAggregator,
    ThreatIntelligenceProvider,
)


class StaticProvider(ThreatIntelligenceProvider):
    name = "test_provider"

    def __init__(self, result):
        self.result = result
        self.calls = []

    def check(self, normalized_url):
        self.calls.append(normalized_url)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class ThreatIntelligenceTests(unittest.TestCase):
    def test_provider_interface_is_abstract(self):
        with self.assertRaises(TypeError):
            ThreatIntelligenceProvider()

    def test_disabled_provider_is_unavailable(self):
        provider = OpenPhishCommunityFeedProvider(enabled=False)
        result = provider.check("https://example.com/path")
        self.assertEqual(result["status"], "unavailable")
        self.assertFalse(result["checked"])
        self.assertFalse(result["matched"])
        self.assertEqual(result["details"]["reason"], "provider_disabled")

    def test_malformed_url_does_not_fetch_feed(self):
        provider = OpenPhishCommunityFeedProvider()
        with patch.object(provider, "_download_feed") as download:
            result = provider.check("http://")
        download.assert_not_called()
        self.assertEqual(result["status"], "error")
        self.assertFalse(result["checked"])

    def test_feed_timeout_is_unavailable_without_leaking_exception(self):
        provider = OpenPhishCommunityFeedProvider()
        with patch.object(provider, "_download_feed", side_effect=TimeoutError("private diagnostic")) as download:
            result = provider.check("https://example.com")
            second_result = provider.check("https://example.org")
        download.assert_called_once()
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(second_result["status"], "unavailable")
        self.assertEqual(result["details"], {"reason": "feed_unavailable"})
        self.assertNotIn("private diagnostic", str(result))

    def test_feed_match_has_normalized_result_format_and_is_cached(self):
        provider = OpenPhishCommunityFeedProvider(cache_ttl_seconds=3600)
        content = b"https://example.com/login\nnot a url\n"
        with patch.object(provider, "_download_feed", return_value=content) as download:
            first = provider.check("HTTPS://EXAMPLE.COM/login")
            second = provider.check("https://example.com/elsewhere")
        download.assert_called_once()
        self.assertEqual(set(first), {"provider", "status", "checked", "matched", "category", "details"})
        self.assertEqual(first["status"], "matched")
        self.assertTrue(first["checked"])
        self.assertEqual(first["category"], "phishing")
        self.assertEqual(second["status"], "not_matched")
        self.assertIsNone(second["category"])

    def test_aggregator_handles_provider_error(self):
        provider = StaticProvider(TimeoutError())
        result = ThreatIntelligenceAggregator([provider]).check("https://example.com")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["providers"][0]["status"], "error")
        self.assertEqual(result["providers"][0]["details"], {"reason": "provider_error"})

    def test_aggregator_mixed_statuses_and_invalid_input(self):
        positive = StaticProvider({
            "status": "matched", "checked": True, "matched": True,
            "category": "phishing", "details": {"source": "test"},
        })
        unavailable = OpenPhishCommunityFeedProvider(enabled=False)
        result = ThreatIntelligenceAggregator([positive, unavailable]).check("Example.com")
        self.assertEqual(positive.calls, ["http://example.com"])
        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["matched_providers"], ["test_provider"])
        self.assertEqual(result["categories"], ["phishing"])
        invalid = ThreatIntelligenceAggregator([positive]).check("http://")
        self.assertEqual(invalid["status"], "error")
        self.assertEqual(invalid["providers"], [])

    def test_backend_endpoint_survives_unavailable_threat_intelligence(self):
        unavailable = ThreatIntelligenceAggregator([OpenPhishCommunityFeedProvider(enabled=False)])
        with patch.object(backend_main, "threat_intelligence_aggregator", unavailable), TestClient(backend_main.app) as client:
            response = client.post("/api/v1/analyze/url", json={"url": "https://example.com/", "follow_redirects": False})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["threat_intelligence"]["status"], "unavailable")
        self.assertIn(response.json()["risk_decision"]["risk_level"], {"SAFE", "SUSPICIOUS"})
        self.assertEqual(response.json()["risk_decision"]["evidence_quality"], "limited")

    def test_backend_endpoint_includes_mocked_provider_evidence(self):
        provider = StaticProvider({
            "status": "matched", "checked": True, "matched": True,
            "category": "phishing", "details": {"source": "automated_test"},
        })
        with patch.object(backend_main, "threat_intelligence_aggregator", ThreatIntelligenceAggregator([provider])), TestClient(backend_main.app) as client:
            response = client.post("/api/v1/analyze/url", json={"url": "https://example.com/", "follow_redirects": False})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["threat_intelligence"]["providers"][0]["status"], "matched")
        self.assertEqual(response.json()["threat_intelligence"]["categories"], ["phishing"])
        self.assertEqual(response.json()["risk_decision"]["risk_level"], "MALICIOUS")
        self.assertEqual(response.json()["risk_decision"]["action"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
