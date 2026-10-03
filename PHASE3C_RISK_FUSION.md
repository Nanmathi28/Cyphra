# Phase 3C — Explainable Risk Fusion

## Objective and architecture

Phase 3C adds `ml/security/risk_fusion.py` and adds an explainable `risk_decision` to `POST /api/v1/analyze/url`. It consumes evidence from the saved Phase 2 Character CNN + BiLSTM, Phase 3A URL and redirect analysis, and Phase 3B threat intelligence. The original evidence fields remain in the response; the fusion summary does not replace or modify their source results.

**The fusion layer is an explainable decision layer over independently generated evidence. It does not claim that a URL is mathematically guaranteed safe or malicious.** Threat intelligence is independent from ML: an OpenPhish match is a provider finding, not an ML prediction.

## Evidence sources

- **ML:** `prediction`, `probabilities`, `confidence`, and `model` from `CNNBiLSTMURLPredictor`. The malicious probability is calculated only when the complete four-class map exists: `defacement + malware + phishing`. It is not computed from missing or partial values.
- **URL security:** actual Phase 3A structural indicators, including suspicious terms, IP literal, userinfo, punycode, HTTP, suspicious port, many hostname labels, and known shortener.
- **Redirect/destination:** actual status, redirect count, cross-registered-domain, excessive-chain, blocked-destination, and destination-change fields. A redirect or hostname change alone is not treated as proof of maliciousness.
- **Threat intelligence:** checked provider matches/status/categories from the Phase 3B aggregator. `not_matched` is not evidence that a URL is safe; unavailable providers add no malicious evidence.

## Decision rules

Rules are evaluated in this order:

1. Invalid URL input is `SUSPICIOUS / CAUTION` from the engine and reports that the URL could not be safely analyzed. The existing API continues to reject invalid inputs with HTTP 422.
2. A checked provider result with `status="matched"` and `matched=true` is `MALICIOUS / BLOCK`, with provider and category in the reason.
3. A predicted `defacement`, `malware`, or `phishing` class with confidence at least `STRONG_ML_CONFIDENCE_THRESHOLD` (`0.90`) is `MALICIOUS / BLOCK` only when structural or redirect evidence independently corroborates it. The threshold is centralized in the module. It is a deliberately strict operational gate for blocking, not a calibrated model probability or a threshold selected from validation optimization.
4. Any harmful ML prediction below the block gate, malicious probability mass above 0.50, detected structural risk signal, redirect warning, or missing analyzer/ML evidence results in `SUSPICIOUS / CAUTION` unless an earlier rule applies. Weak signals such as HTTP or a shortener do not independently produce `MALICIOUS`.
5. Otherwise, the result is `SAFE / PROCEED` only when ML, URL analysis, redirect inspection, and at least one configured threat-intelligence provider have completed checks and no significant findings remain. If an important check is unavailable, the result is `SUSPICIOUS / CAUTION` with `evidence_quality="limited"`; missing information is not treated as a clean finding.

The policy uses ordered evidence rules rather than arbitrary weighted risk percentages. The `0.90` model gate is the only numeric malicious blocking threshold and is documented above. A combined malicious probability above 0.50 means the classifier assigns a majority of its four-class probability mass to the three malicious classes; this creates a suspicious signal, never an independent block.

## Confidence and evidence quality

`decision_confidence` is calculated as:

```text
supporting observed evidence families / (supporting + opposing observed evidence families)
```

Evidence families are ML, URL security, redirect analysis, and threat intelligence; each family contributes at most one vote. For SAFE, a benign ML result and completed clean URL/redirect analysis support the decision. For SUSPICIOUS, positive findings support the decision while a benign ML result or available clean structural/redirect inspection counts as conflicting evidence. A MALICIOUS threat-feed match is supported by the checked matching provider; a contradictory benign ML prediction reduces its confidence. Unavailable or unknown evidence is excluded from both sides, so it cannot count as agreement; `evidence_quality` separately reports `limited` and incomplete analysis defaults to CAUTION. This ratio describes consistency among observed evidence, not a calibrated probability that a URL is safe or malicious.

## Reason codes

Reasons contain `code`, `severity`, `source`, and a human-readable `message`. Codes are emitted only when supported by the source response. Implemented codes include `URL_INVALID`, `ANALYZER_UNAVAILABLE`, `ML_UNAVAILABLE`, `THREAT_INTELLIGENCE_UNAVAILABLE`, `REDIRECT_ANALYSIS_UNAVAILABLE`, `ANALYSIS_INCOMPLETE`, `THREAT_INTELLIGENCE_MATCH`, `ML_MALWARE`, `ML_PHISHING`, `ML_DEFACEMENT`, `ML_HIGH_MALICIOUS_PROBABILITY`, `SUSPICIOUS_KEYWORDS`, `IP_LITERAL`, `USERINFO_PRESENT`, `PUNYCODE_HOSTNAME`, `HTTP_SCHEME`, `SUSPICIOUS_PORT`, `MANY_SUBDOMAINS`, `URL_SHORTENER`, `UNSUPPORTED_SCHEME`, `REDIRECT_PRESENT`, `CROSS_DOMAIN_REDIRECT`, `EXCESSIVE_REDIRECTS`, `DESTINATION_BLOCKED`, and `DESTINATION_CHANGED`.

## API response

All prior top-level fields remain. `risk_decision` is additive and has this shape (values below describe the schema, not an actual URL result):

```json
{
  "risk_decision": {
    "risk_level": "SAFE | SUSPICIOUS | MALICIOUS",
    "action": "PROCEED | CAUTION | BLOCK",
    "decision_confidence": 0.0,
    "evidence_quality": "complete | limited",
    "reasons": [],
    "evidence_summary": {
      "ml": {},
      "url_security": {},
      "redirect": {},
      "threat_intelligence": {}
    },
    "decision_policy_version": "3C-v1"
  }
}
```

The independent top-level `ml`, URL-security, redirect, and threat-intelligence outputs remain present. If the saved model is unavailable, the endpoint returns an unavailable ML section and fuses the remaining evidence. If URL-security analysis fails unexpectedly, the endpoint returns unavailable evidence and a limited `SUSPICIOUS / CAUTION` result without echoing the submitted URL. Invalid URL input retains the existing HTTP 422 behavior. Threat-intelligence failure remains non-fatal.

## Testing

Automated tests cover benign and malicious ML classes, the ML block threshold/corroboration rule, mocked checked threat-intelligence matches, unavailable sources, HTTP/IP/userinfo/punycode/shortener findings, redirect changes and failures, conflicting evidence, invalid input, and endpoint integration. Threat-intelligence mocks are test-only; no test relies on live OpenPhish access.

## Limitations and next improvements

- The ML probability outputs are not calibrated estimates of real-world URL risk.
- The 0.90 block gate is a conservative policy choice, not a validation-derived operating point.
- OpenPhish Community Feed matching is exact after the current URL normalization; feed non-match does not imply safety.
- Redirect checks are observations at analysis time; unreachable, blocked, or not-requested destinations remain unavailable evidence.
- Decision rules need review against a separately curated, representative validation set before production risk tuning. Do not change thresholds or train models without such data and an explicit evaluation plan.

## Validation

The implementation is validated with the repository test suite and endpoint checks described in the completion report. No model was retrained, and no dataset, label, probability, feed match, or redirect result was fabricated.
