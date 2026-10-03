# Phase 3A — URL Security Analysis

## 1. Purpose

Phase 3A adds a URL evidence-collection layer to CYPHRA/NIVARA. It reports URL structure, domain data, existing Phase 2 features, and optional HTTP redirect observations. It does not convert those observations into a security verdict.

## 2. URL normalization

`ml/security/url_security_analyzer.py` accepts a URL string, trims surrounding whitespace, supplies `http://` when no scheme is present, lowercases the scheme and hostname, converts international hostnames to IDNA form, removes a trailing hostname dot, validates ports, and preserves path, query, and fragment. Control characters and inputs longer than 8,192 characters are rejected. Passwords in URL userinfo are redacted in returned display URLs; the analyzer reports only whether a password was present.

The analyzer uses `URLFeatureExtractor` for Phase 2 feature values such as path depth, query parameter count, URL character counts, protocol flags, and suspicious keyword count. It returns these under `phase2_ml_features`, allowing consumers to inspect the same calculations used by the feature-based pipeline.

## 3. URL structural analysis

The result includes the normalized URL, scheme, hostname, explicit port, path, query, fragment, userinfo presence and username, password-presence flag, raw and normalized URL lengths, and path depth. The fragment is reported but is not sent in an HTTP request.

## 4. Domain analysis

The analyzer identifies IPv4 and IPv6 literals with Python's `ipaddress` module. For hostnames it uses `tldextract` 5.3.2 with its bundled public-suffix snapshot; runtime public-suffix downloads are disabled. It reports registered domain, subdomain, public suffix, hostname label count, dots, digits, hyphens, special characters, and `www` presence. The existing Phase 2 `subdomain_count` convention is reused for consistency. For IP literals, registered-domain and public-suffix fields are `null`.

Public-suffix data is versioned with the dependency and can lag future registry changes. An empty/unrecognized suffix is surfaced in `suffix_source` instead of inventing a registered domain.

## 5. Security indicators

Evidence includes HTTP/HTTPS use, supported scheme, suspicious keyword count and matching keyword terms from the Phase 2 extractor, URL userinfo and `@`, IP-literal hostname, punycode hostname, many subdomain labels, unusual and commonly sensitive ports, and known URL-shortener domains. These are independent observations. They do not say that a URL is safe, suspicious, or malicious.

## 6. Redirect analysis

Redirect inspection uses manual HTTP requests with a four-second connect/read timeout, a maximum of five redirects, a byte-range request, and no response-body consumption. Only HTTP and HTTPS are followed; cookies, credentials, JavaScript, forms, and authentication are not used. Redirect targets are resolved and checked before each request. Loopback, private, link-local, reserved, and other non-global IP destinations are blocked. Requests connect to a checked IP address directly; HTTPS still verifies the certificate against the original hostname.

The result includes status (`reachable`, `unreachable`, `timeout`, `blocked`, or `error`), HTTP status when available, redirect chain/count, final URL and hostname, hostname/domain/scheme changes, whether any hop crossed registered domains, a shortener-expansion indicator, and an excessive-redirect indicator. Network failure remains a resolution status and is not translated into a threat verdict. System DNS resolution uses the operating system resolver; its lookup duration is not bounded by the Python socket API timeout.

## 7. Final destination analysis

When a final HTTP(S) response is reached, the analyzer runs the same structural and domain analysis on the final URL. The response exposes both original and final destination information so downstream components can compare them.

## 8. Backend endpoint

`POST /api/v1/analyze/url` accepts:

```json
{"url": "https://example.com", "follow_redirects": false}
```

`follow_redirects` defaults to `true`. The endpoint uses the saved Phase 2 Character-Level CNN + BiLSTM through `CNNBiLSTMURLPredictor` and returns its predicted class/probabilities alongside independent security evidence. Invalid URL inputs receive HTTP 422; a missing or unloadable saved model receives HTTP 503. The model is loaded once per backend process.

Response shape (model-dependent fields are placeholders here, not example predictions):

```json
{
  "url": "https://example.com",
  "normalized_url": "https://example.com",
  "url_structure": {},
  "domain_characteristics": {},
  "security_indicators": {},
  "phase2_ml_features": {},
  "redirect_analysis": {},
  "final_destination_features": null,
  "threat_intelligence": {"status": "not_integrated", "matches": []},
  "risk_decision": null,
  "ml": {
    "prediction": "<saved-model-output>",
    "probabilities": "<saved-model-output>"
  }
}
```

## 9. Safety limitations

- Redirect checks are safe HTTP header/status inspections, not page browsing. Sites that require JavaScript or client behavior can resolve differently in a browser.
- A destination may change after inspection; results are observations at request time.
- DNS lookups depend on the host resolver and may be affected by local network policy.
- URL shortener detection uses a small explicit domain list and is not exhaustive.
- Security indicators are evidence only and can have benign or malicious explanations.

## 10. Intentionally not implemented

- Phase 2 ML prediction is available and returned independently.
- Threat intelligence is not integrated; no external reputation lookups are made.
- Risk fusion is not implemented.
- No final SAFE / SUSPICIOUS / MALICIOUS decision is implemented.
- Mobile UI, OCR, redirect-based risk weighting, and broader threat-intelligence integration remain later work.
