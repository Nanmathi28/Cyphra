# Phase 3B — Threat Intelligence Integration

## 1. Purpose

This phase adds a provider interface and an aggregator that return threat-intelligence evidence as an independent section of `POST /api/v1/analyze/url`. It does not merge provider evidence with the saved model or URL-security evidence and does not produce a risk score or SAFE/SUSPICIOUS/MALICIOUS decision.

## 2. Providers considered

- **OpenPhish Community Feed:** the official feed page identifies a free text community feed with a 12-hour update frequency. Its feed link currently redirects to the public `openphish/public_feed` GitHub text file. The application downloads that official linked feed and compares the URL locally.
- **PhishTank:** its documented lookup accepts a URL and supports an optional registered `app_key`; no PhishTank key is configured here. This provider is not integrated.
- **URLhaus:** its community API requires an Auth-Key obtained through the abuse.ch Authentication Portal. No key is configured here. This provider is not integrated.
- **Google Safe Browsing:** the lookup API requires an enabled Google project and API key. No key is configured here. This provider is not integrated. Its Lookup API transmits the URL to Google, so it was not enabled without an explicit configuration and privacy decision.

## 3. Provider implemented and operational status

`OpenPhishCommunityFeedProvider` is implemented in `ml/security/threat_intelligence.py`. The Community Feed was reached successfully during implementation and returned HTTP 200, `text/plain`, and 300 URL entries. Runtime operation still depends on network/feed availability; a failed or invalid feed response produces `unavailable`, not a fabricated clean result. The other three services are documented but not implemented or queried.

## 4. Configuration

`.env.example` defines:

| Variable | Default | Meaning |
| --- | --- | --- |
| `THREAT_INTEL_OPENPHISH_ENABLED` | `true` | Enable or disable the OpenPhish feed provider. |
| `THREAT_INTEL_TIMEOUT_SECONDS` | `5` | HTTPS connection timeout for the feed download. |
| `THREAT_INTEL_CACHE_TTL_SECONDS` | `43200` | In-process feed cache lifetime (12 hours). |

No API keys are used by the implemented provider, so no key values or unused credential placeholders are added. Future API-backed integrations must obtain secrets only from environment variables and must not log or return them.

## 5. Response format

The endpoint's independent `threat_intelligence` section has this shape:

```json
{
  "status": "matched | not_matched | unavailable | error | partial",
  "providers": [
    {
      "provider": "openphish_community_feed",
      "status": "matched | not_matched | unavailable | error",
      "checked": true,
      "matched": true,
      "category": "phishing",
      "details": {"feed": "OpenPhish Community Feed"}
    }
  ],
  "matched_providers": ["openphish_community_feed"],
  "categories": ["phishing"]
}
```

Non-match results use `category: null` and `details: null`. When the feed is disabled or cannot be checked, the provider returns `checked: false`, `matched: false`, and a generic reason in `details`; transport exceptions and URLs are not exposed. `matched` means only that the provider listed the URL.

## 6. Aggregator behavior

`ThreatIntelligenceAggregator` validates and normalizes the input, queries each configured provider, normalizes each result, and aggregates matched provider names/categories. Any provider match yields overall `matched`; all successful non-matches yields `not_matched`; a mixture of checked evidence and unavailable/error providers yields `partial`; no checks yields `unavailable`; invalid input or exclusively provider errors yields `error`. It never assigns a risk score or application decision.

## 7. Error handling

Each feed/provider failure is returned as structured unavailable/error evidence. The backend also catches unexpected aggregator exceptions and returns an unavailable section while retaining its normal ML and URL-security response. The endpoint's `risk_decision` remains `null`.

## 8. Rate limiting and caching

The app downloads a static public feed, not one remote lookup per submitted URL. The parsed URL set is cached per backend process for 12 hours by default, matching the Community Feed's documented update cadence. The response size is capped at 2 MiB; the provider uses a timeout and does not retry continuously. Repeated URL checks against the cached feed are local set lookups.

After a feed retrieval/parse failure, the provider suppresses another download attempt for 60 seconds per process; checks during that cooldown return `unavailable`.

## 9. Privacy

The Community Feed download contains no submitted URL. URL comparison happens locally, and neither the submitted URL nor its domain is sent to OpenPhish/GitHub. The endpoint passes the URL analyzer's normalized, credential-redacted URL to the aggregator. No QR image, local file, user credential, or unrelated data is transmitted. The implementation does not log lookup URLs or credentials.

## 10. Current limitations

- Feed matches require an exact normalized URL match; feed coverage and freshness are bounded by the Community Feed.
- OpenPhish's community feed terms apply.
- PhishTank, URLhaus, and Google Safe Browsing are not active because their integrations were not configured; their provider responses are not fabricated.
- No combined risk decision exists in this phase.

## 11. Future Risk Fusion input

The future Risk Fusion layer can consume `threat_intelligence.status`, per-provider check/match evidence, matched provider names, and categories alongside ML and URL-security evidence. A threat-intelligence match remains an input signal, not a decision by itself.

## 12. Official provider references

- [OpenPhish Phishing Feeds](https://openphish.com/phishing_feeds.html)
- [PhishTank API Information](https://phishtank.org/api_info.php)
- [URLhaus Community API](https://urlhaus.abuse.ch/api/)
- [Google Safe Browsing Lookup API](https://developers.google.com/safe-browsing/v4/lookup-api)
