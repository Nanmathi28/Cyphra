"""Explainable rule-based fusion of independently generated URL evidence."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any, Mapping

from ml.security.url_security_analyzer import URLInputError, normalize_url


DECISION_POLICY_VERSION = "3C-v1"
# A strict operational gate: an ML-only block requires a top-class harmful
# prediction at >=90% plus independent structural or redirect corroboration.
# This is a policy threshold, not a calibrated probability of maliciousness.
STRONG_ML_CONFIDENCE_THRESHOLD = 0.90
_MALICIOUS_CLASSES = {"defacement", "malware", "phishing"}
_CLASS_ORDER = ("benign", "defacement", "malware", "phishing")
_MALICIOUS_PROBABILITY_MAJORITY_THRESHOLD = 0.5


@dataclass(frozen=True)
class DecisionReason:
    code: str
    severity: str
    source: str
    message: str


class RiskFusionEngine:
    """Combine URL evidence without changing or retraining its source models."""

    def evaluate(
        self,
        url: str,
        ml_prediction: Mapping[str, Any] | None,
        security_analysis: Mapping[str, Any] | None,
        threat_intelligence: Mapping[str, Any] | None,
        redirect_analysis: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        reasons: list[DecisionReason] = []
        try:
            normalize_url(url)
        except (URLInputError, TypeError):
            reasons.append(DecisionReason(
                "URL_INVALID", "high", "url_security", "URL could not be safely analyzed."
            ))
            return _decision(
                "SUSPICIOUS", "CAUTION", _consensus_confidence(1, 0), reasons,
                {"ml": _ml_summary(ml_prediction), "url_security": {"status": "invalid"},
                 "redirect": _redirect_summary(redirect_analysis),
                 "threat_intelligence": _threat_summary(threat_intelligence)},
                "limited",
            )

        ml = _ml_summary(ml_prediction)
        security = _security_summary(security_analysis)
        redirects = _redirect_summary(
            redirect_analysis if redirect_analysis is not None
            else (security_analysis or {}).get("redirect_analysis")
        )
        threat = _threat_summary(threat_intelligence)

        if security["status"] != "available":
            reasons.append(DecisionReason(
                "ANALYZER_UNAVAILABLE", "high", "url_security",
                "URL security analysis was unavailable; the URL could not be fully assessed.",
            ))
        if ml["status"] != "available":
            reasons.append(DecisionReason(
                "ML_UNAVAILABLE", "medium", "ml", "The URL classifier result is unavailable."
            ))
        if not _threat_is_complete(threat):
            reasons.append(DecisionReason(
                "THREAT_INTELLIGENCE_UNAVAILABLE", "info", "threat_intelligence",
                "Threat-intelligence coverage was unavailable or incomplete.",
            ))
        if redirects["status"] in {"not_requested", "unavailable", "timeout", "unreachable", "error"}:
            reasons.append(DecisionReason(
                "REDIRECT_ANALYSIS_UNAVAILABLE", "info", "redirect",
                "Redirect and destination evidence was unavailable or not requested.",
            ))

        # URL-structure findings are evidence signals, not individual verdicts.
        flags = security["indicators"]
        if flags.get("suspicious_keywords"):
            keywords = ", ".join(flags["suspicious_keywords"])
            reasons.append(DecisionReason(
                "SUSPICIOUS_KEYWORDS", "medium", "url_security",
                f"The URL contains suspicious security-related keywords ({keywords}).",
            ))
        if flags.get("ip_literal"):
            reasons.append(DecisionReason("IP_LITERAL", "medium", "url_security", "The hostname is an IP address literal."))
        if flags.get("userinfo"):
            reasons.append(DecisionReason("USERINFO_PRESENT", "medium", "url_security", "The URL contains userinfo or an @-style authority marker."))
        if flags.get("punycode"):
            reasons.append(DecisionReason("PUNYCODE_HOSTNAME", "medium", "url_security", "The hostname contains an IDNA punycode label."))
        if flags.get("http"):
            reasons.append(DecisionReason("HTTP_SCHEME", "low", "url_security", "The URL uses HTTP rather than HTTPS."))
        if flags.get("suspicious_port"):
            reasons.append(DecisionReason("SUSPICIOUS_PORT", "medium", "url_security", "The URL uses a port identified by the analyzer as sensitive."))
        if flags.get("many_subdomains"):
            reasons.append(DecisionReason("MANY_SUBDOMAINS", "low", "url_security", "The analyzer identified many hostname labels."))
        if flags.get("url_shortener"):
            reasons.append(DecisionReason("URL_SHORTENER", "low", "url_security", "The hostname is a known URL shortener."))
        if flags.get("unsupported_scheme"):
            reasons.append(DecisionReason("UNSUPPORTED_SCHEME", "high", "url_security", "The URL uses a scheme outside HTTP and HTTPS."))

        ml_class = ml["predicted_class"]
        ml_confidence = ml["confidence"]
        malicious_probability = ml["malicious_probability"]
        harmful_prediction = ml_class in _MALICIOUS_CLASSES
        elevated_ml = harmful_prediction or (
            malicious_probability is not None
            and malicious_probability > _MALICIOUS_PROBABILITY_MAJORITY_THRESHOLD
        )
        if harmful_prediction:
            reason_code = {
                "malware": "ML_MALWARE",
                "phishing": "ML_PHISHING",
                "defacement": "ML_DEFACEMENT",
            }[ml_class]
            severity = "high" if ml_confidence is not None and ml_confidence >= STRONG_ML_CONFIDENCE_THRESHOLD else "medium"
            reasons.append(DecisionReason(
                reason_code, severity, "ml", f"The URL classifier predicted {ml_class}."
            ))
        if malicious_probability is not None and malicious_probability > _MALICIOUS_PROBABILITY_MAJORITY_THRESHOLD:
            reasons.append(DecisionReason(
                "ML_HIGH_MALICIOUS_PROBABILITY", "high", "ml",
                f"The classifier assigned {malicious_probability:.4f} combined probability to malicious classes.",
            ))

        redirect_flags = redirects["indicators"]
        if redirect_flags.get("redirect_count", 0) > 0:
            reasons.append(DecisionReason("REDIRECT_PRESENT", "low", "redirect", "The URL produced one or more HTTP redirects."))
        if redirect_flags.get("cross_domain"):
            reasons.append(DecisionReason("CROSS_DOMAIN_REDIRECT", "medium", "redirect", "A redirect crossed registered domains."))
        if redirect_flags.get("excessive_redirects"):
            reasons.append(DecisionReason("EXCESSIVE_REDIRECTS", "medium", "redirect", "The redirect chain exceeded the analyzer's threshold."))
        if redirect_flags.get("blocked_destination"):
            reasons.append(DecisionReason("DESTINATION_BLOCKED", "high", "redirect", "Destination inspection was blocked by the analyzer's network-safety checks."))
        if redirect_flags.get("destination_changed"):
            reasons.append(DecisionReason("DESTINATION_CHANGED", "low", "redirect", "The redirect changed the hostname, registered domain, or scheme."))

        confirmed_matches = [
            provider for provider in threat["providers"]
            if provider["status"] == "matched" and provider["checked"] and provider["matched"]
        ]
        if confirmed_matches:
            provider_names = ", ".join(item["provider"] for item in confirmed_matches)
            categories = sorted({item["category"] for item in confirmed_matches if item.get("category")})
            category_text = f" ({', '.join(categories)})" if categories else ""
            reasons.append(DecisionReason(
                "THREAT_INTELLIGENCE_MATCH", "critical", "threat_intelligence",
                f"URL matched an active threat-intelligence feed{category_text}: {provider_names}.",
            ))

        security_signals = any(flags.values())
        redirect_signals = any(
            redirect_flags.get(key) for key in
            ("redirect_count", "cross_domain", "excessive_redirects", "blocked_destination", "destination_changed")
        )
        corroborating_security = security_signals or redirect_signals
        strong_ml = (
            harmful_prediction
            and ml_confidence is not None
            and ml_confidence >= STRONG_ML_CONFIDENCE_THRESHOLD
        )
        evidence_quality = "complete" if all((
            ml["status"] == "available",
            security["status"] == "available",
            redirects["status"] == "reachable",
            _threat_is_complete(threat),
        )) else "limited"
        if evidence_quality == "limited":
            reasons.append(DecisionReason(
                "ANALYSIS_INCOMPLETE", "medium", "fusion",
                "One or more evidence sources could not be fully checked; proceed with caution.",
            ))

        if confirmed_matches:
            risk_level, action = "MALICIOUS", "BLOCK"
        elif strong_ml and corroborating_security:
            risk_level, action = "MALICIOUS", "BLOCK"
        elif (
            elevated_ml or security_signals or redirect_signals
            or evidence_quality == "limited"
        ):
            risk_level, action = "SUSPICIOUS", "CAUTION"
        else:
            risk_level, action = "SAFE", "PROCEED"
            reasons.append(DecisionReason(
                "NO_SIGNIFICANT_RISK_INDICATORS", "info", "fusion",
                "No significant risk indicators were detected in the available evidence.",
            ))

        supporting, opposing = _decision_votes(
            risk_level, ml, security, redirects, bool(confirmed_matches),
            security_signals, redirect_signals,
        )
        # Consensus among observed evidence families; unavailable inputs are not
        # counted as agreement. Coverage is reported separately below.
        confidence = _consensus_confidence(supporting, opposing)

        return _decision(
            risk_level,
            action,
            confidence,
            reasons,
            {"ml": ml, "url_security": security, "redirect": redirects, "threat_intelligence": threat},
            evidence_quality,
        )


def _ml_summary(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("status") == "unavailable":
        return {
            "status": "unavailable", "predicted_class": None, "class_probabilities": None,
            "malicious_probability": None, "confidence": None,
            "model": value.get("model") if isinstance(value, Mapping) else None,
        }
    predicted = value.get("prediction")
    if predicted is None:
        predicted = value.get("predicted_class")
    probabilities = _valid_probability_map(value.get("probabilities", value.get("class_probabilities")))
    malicious_probability = (
        sum(probabilities[label] for label in ("defacement", "malware", "phishing"))
        if probabilities is not None else None
    )
    confidence = _finite_probability(value.get("confidence"))
    return {
        "status": "available" if isinstance(predicted, str) and predicted in _CLASS_ORDER else "unavailable",
        "predicted_class": predicted if isinstance(predicted, str) and predicted else None,
        "class_probabilities": probabilities,
        "malicious_probability": malicious_probability,
        "confidence": confidence,
        "model": value.get("model"),
    }


def _security_summary(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("status") == "unavailable":
        return {"status": "unavailable", "scheme": None, "indicators": {}}
    indicators = value.get("security_indicators")
    if not isinstance(indicators, Mapping):
        return {"status": "unavailable", "scheme": None, "indicators": {}}
    patterns = indicators.get("suspicious_patterns")
    patterns = patterns if isinstance(patterns, Mapping) else {}
    domain = value.get("domain_characteristics")
    domain = domain if isinstance(domain, Mapping) else {}
    structure = value.get("url_structure")
    structure = structure if isinstance(structure, Mapping) else {}
    suspicious_keywords = indicators.get("suspicious_keywords")
    suspicious_keywords = suspicious_keywords if isinstance(suspicious_keywords, list) else []
    keyword_count = indicators.get("suspicious_keyword_count", len(suspicious_keywords))
    try:
        keyword_present = float(keyword_count) > 0 or bool(suspicious_keywords)
    except (TypeError, ValueError):
        keyword_present = bool(suspicious_keywords)
    scheme = structure.get("scheme", indicators.get("scheme"))
    flags = {
        "suspicious_keywords": [str(item) for item in suspicious_keywords] if keyword_present else [],
        "ip_literal": bool(domain.get("is_ip_address") or patterns.get("ip_literal_hostname")),
        "userinfo": bool(patterns.get("userinfo_present") or patterns.get("at_symbol_present") or
                          (isinstance(structure.get("userinfo"), Mapping) and structure["userinfo"].get("present"))),
        "punycode": bool(patterns.get("punycode_hostname") or "xn--" in str(domain.get("hostname", "")).lower()),
        "http": bool(scheme == "http" or indicators.get("http")),
        "suspicious_port": bool(patterns.get("suspicious_port") or indicators.get("suspicious_port")),
        "many_subdomains": bool(patterns.get("many_subdomain_labels")),
        "url_shortener": bool(patterns.get("known_url_shortener") or indicators.get("url_shortener")),
        "unsupported_scheme": bool(scheme and scheme not in {"http", "https"}),
    }
    return {"status": "available", "scheme": scheme, "indicators": flags}


def _redirect_summary(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {"status": "unavailable", "indicators": {}}
    status = value.get("resolution_status", "unavailable")
    count = value.get("redirect_count", 0)
    try:
        count = max(0, int(count or 0))
    except (TypeError, ValueError):
        count = 0
    hostname_changed = bool(value.get("hostname_changed"))
    domain_changed = bool(value.get("domain_changed"))
    scheme_changed = bool(value.get("https_changed"))
    indicators = {
        "redirect_count": count,
        "cross_domain": bool(value.get("crossed_registered_domains")),
        "excessive_redirects": bool(value.get("excessive_redirects")),
        "blocked_destination": status == "blocked",
        "destination_changed": hostname_changed or domain_changed or scheme_changed,
    }
    return {"status": status, "indicators": indicators}


def _threat_summary(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {"status": "unavailable", "providers": [], "matched_providers": [], "categories": []}
    providers = []
    for item in value.get("providers", []) if isinstance(value.get("providers", []), list) else []:
        if not isinstance(item, Mapping):
            continue
        providers.append({
            "provider": item.get("provider"),
            "status": item.get("status", "unavailable"),
            "checked": item.get("checked") is True,
            "matched": item.get("matched") is True,
            "category": item.get("category"),
        })
    status = value.get("status", "unavailable")
    if status == "not_matched" and not (
        providers and all(item["checked"] and item["status"] == "not_matched" and not item["matched"] for item in providers)
    ):
        status = "partial" if any(item["checked"] for item in providers) else "unavailable"
    if status == "matched" and not any(
        item["checked"] and item["status"] == "matched" and item["matched"] for item in providers
    ):
        status = "partial" if any(item["checked"] for item in providers) else "unavailable"
    return {
        "status": status,
        "providers": providers,
        "matched_providers": list(value.get("matched_providers", [])) if isinstance(value.get("matched_providers", []), list) else [],
        "categories": list(value.get("categories", [])) if isinstance(value.get("categories", []), list) else [],
    }


def _threat_is_complete(threat: Mapping[str, Any]) -> bool:
    providers = threat.get("providers", [])
    return (
        threat.get("status") == "matched"
        and bool(providers)
        and all(item["checked"] and item["status"] in {"matched", "not_matched"} for item in providers)
    ) or (
        threat.get("status") == "not_matched"
        and bool(providers)
        and all(item["checked"] and item["status"] == "not_matched" and not item["matched"] for item in providers)
    )


def _decision_votes(risk_level, ml, security, redirects, confirmed_matches, security_signals, redirect_signals):
    supporting = set()
    opposing = set()
    if risk_level == "SAFE":
        if ml["status"] == "available" and ml["predicted_class"] == "benign" and (
            ml["malicious_probability"] is None or ml["malicious_probability"] <= _MALICIOUS_PROBABILITY_MAJORITY_THRESHOLD
        ):
            supporting.add("ml")
        if security["status"] == "available":
            (opposing if security_signals else supporting).add("url_security")
        if redirects["status"] == "reachable":
            (opposing if redirect_signals else supporting).add("redirect")
    else:
        if confirmed_matches:
            supporting.add("threat_intelligence")
        if ml["status"] == "available":
            if ml["predicted_class"] in _MALICIOUS_CLASSES or (
                ml["malicious_probability"] is not None
                and ml["malicious_probability"] > _MALICIOUS_PROBABILITY_MAJORITY_THRESHOLD
            ):
                supporting.add("ml")
            elif ml["predicted_class"] == "benign":
                opposing.add("ml")
        if security["status"] == "available" and security_signals:
            supporting.add("url_security")
        elif security["status"] == "available" and risk_level == "SUSPICIOUS":
            opposing.add("url_security")
        if redirects["status"] == "reachable" and redirect_signals:
            supporting.add("redirect")
        elif redirects["status"] == "reachable" and risk_level == "SUSPICIOUS":
            opposing.add("redirect")
    return len(supporting), len(opposing)


def _consensus_confidence(supporting: int, opposing: int) -> float:
    """Share of observed evidence families that support the selected rule."""
    total = supporting + opposing
    return supporting / total if total else 0.0


def _valid_probability_map(value: Any) -> dict[str, float] | None:
    if not isinstance(value, Mapping) or not all(label in value for label in _CLASS_ORDER):
        return None
    result = {}
    for label in _CLASS_ORDER:
        probability = _finite_probability(value.get(label))
        if probability is None:
            return None
        result[label] = probability
    return result


def _finite_probability(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and 0.0 <= number <= 1.0 else None


def _decision(risk_level, action, confidence, reasons, evidence_summary, evidence_quality):
    return {
        "risk_level": risk_level,
        "action": action,
        "decision_confidence": min(1.0, max(0.0, float(confidence))),
        "evidence_quality": evidence_quality,
        "reasons": [asdict(reason) for reason in reasons],
        "evidence_summary": evidence_summary,
        "decision_policy_version": DECISION_POLICY_VERSION,
    }
