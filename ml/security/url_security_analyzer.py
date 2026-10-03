"""URL parsing, structural evidence, and bounded safe redirect inspection."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit, unquote

import tldextract

from ml.features.url_features import URLFeatureExtractor


_SUFFIX_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)
_SHORTENER_HOSTS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "ow.ly", "buff.ly",
    "tiny.cc", "shorturl.at", "cutt.ly", "rebrand.ly", "lnkd.in", "rb.gy",
}
_SUSPICIOUS_PORTS = {21, 22, 23, 25, 445, 3389, 5900}
_SUPPORTED_SCHEMES = {"http", "https"}


class URLInputError(ValueError):
    """Raised when an input cannot be interpreted as a URL."""


def normalize_url(raw_url: str) -> str:
    """Add an http scheme when absent and normalize scheme/hostname casing."""
    if not isinstance(raw_url, str):
        raise URLInputError("URL must be a string")
    value = raw_url.strip()
    if not value or len(value) > 8192:
        raise URLInputError("URL must contain between 1 and 8192 characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise URLInputError("URL cannot contain control characters")
    if value.startswith("//"):
        value = "http:" + value
    elif not _has_scheme(value):
        value = "http://" + value

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        # Accessing .port also validates malformed or out-of-range ports.
        port = parsed.port
    except ValueError as exc:
        raise URLInputError("URL authority or port is malformed") from exc
    if not parsed.scheme or not hostname:
        raise URLInputError("URL must include a hostname")

    try:
        ip = ipaddress.ip_address(hostname.split("%", 1)[0])
        normalized_hostname = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    except ValueError:
        try:
            normalized_hostname = hostname.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError as exc:
            raise URLInputError("Hostname cannot be converted to IDNA") from exc
        if not normalized_hostname:
            raise URLInputError("URL must include a hostname")

    userinfo = parsed.netloc.rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
    default_port = (parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443)
    authority = userinfo + normalized_hostname
    if port is not None and not default_port:
        authority += f":{port}"
    return urlunsplit((parsed.scheme.lower(), authority, parsed.path, parsed.query, parsed.fragment))


def _has_scheme(value: str) -> bool:
    prefix, separator, _ = value.partition("://")
    return bool(separator and prefix and prefix[0].isalpha() and all(
        char.isalnum() or char in "+-." for char in prefix
    ))


def _parse_url(value: str):
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise URLInputError("URL authority or port is malformed") from exc
    if not hostname:
        raise URLInputError("URL must include a hostname")
    try:
        ip_address = ipaddress.ip_address(hostname.split("%", 1)[0])
    except ValueError:
        ip_address = None
    return parsed, hostname.lower().rstrip("."), port, ip_address


def _redact_url_credentials(value: str) -> str:
    """Remove a password from display URLs while preserving the username marker."""
    try:
        had_scheme = _has_scheme(value)
        candidate = value if had_scheme or value.startswith("//") else "http://" + value
        parsed = urlsplit(candidate)
        if "@" not in parsed.netloc:
            return value
        userinfo, hostport = parsed.netloc.rsplit("@", 1)
        username, separator, password = userinfo.partition(":")
        safe_userinfo = username + (":[REDACTED]" if separator and password else ":" if separator else "")
        safe = urlunsplit((parsed.scheme, safe_userinfo + "@" + hostport, parsed.path, parsed.query, parsed.fragment))
        return safe if had_scheme or value.startswith("//") else safe.removeprefix("http://")
    except ValueError:
        return value


def _domain_details(hostname: str, ip_address: ipaddress._BaseAddress | None) -> dict[str, Any]:
    if ip_address is not None:
        return {
            "hostname": hostname,
            "registered_domain": None,
            "subdomain": None,
            "public_suffix": None,
            "suffix_source": "not_applicable_ip",
            "is_ip_address": True,
            "ip_version": ip_address.version,
        }

    extracted = _SUFFIX_EXTRACTOR(hostname)
    registered_domain = extracted.top_domain_under_public_suffix or None
    public_suffix = extracted.suffix or None
    subdomain = extracted.subdomain or None
    # Keep the existing Phase 2 feature's subdomain-count convention so these
    # features agree for ordinary hostnames; PSL-derived fields are also exposed.
    feature_domain = hostname.replace("www.", "")
    feature_subdomain_count = max(0, len(feature_domain.split(".")) - 2)
    return {
        "hostname": hostname,
        "registered_domain": registered_domain,
        "subdomain": subdomain,
        "subdomain_count": feature_subdomain_count,
        "public_suffix": public_suffix,
        "suffix_source": "tldextract_bundled_public_suffix_list" if public_suffix else "no_known_public_suffix",
        "is_ip_address": False,
        "ip_version": None,
    }


def _is_shortener(hostname: str, domain_info: dict[str, Any]) -> bool:
    return hostname in _SHORTENER_HOSTS or domain_info.get("registered_domain") in _SHORTENER_HOSTS


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to a checked public IP, with hostname TLS verification."""

    def __init__(self, ip: str, port: int, hostname: str, timeout: float):
        super().__init__(ip, port=port, timeout=timeout, context=ssl.create_default_context())
        self._tls_hostname = hostname

    def connect(self):
        raw_socket = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self._tls_hostname)


class URLSecurityAnalyzer:
    """Extract observable URL evidence and optionally inspect safe redirects."""

    def __init__(self, timeout_seconds: float = 4.0, max_redirects: int = 5):
        self.timeout_seconds = max(0.5, float(timeout_seconds))
        self.max_redirects = max(0, min(int(max_redirects), 10))
        self.feature_extractor = URLFeatureExtractor()

    def analyze_features(self, raw_url: str) -> dict[str, Any]:
        normalized = normalize_url(raw_url)
        parsed, hostname, port, ip_address = _parse_url(normalized)
        domain_info = _domain_details(hostname, ip_address)
        ml_features = self.feature_extractor.extract_features([raw_url]).iloc[0].to_dict()
        keyword_list = [
            keyword for keyword in self.feature_extractor.SUSPICIOUS_KEYWORDS
            if keyword in raw_url.lower()
        ]
        path_parts = [part for part in parsed.path.split("/") if part]
        userinfo = parsed.netloc.rsplit("@", 1)[0] if "@" in parsed.netloc else ""
        username, separator, password = userinfo.partition(":")
        host_label_count = len(hostname.split("."))
        special_hostname_chars = sum(not character.isalnum() and character not in ".-" for character in hostname)
        domain_info["subdomain_count"] = int(ml_features["subdomain_count"])
        shortener = _is_shortener(hostname, domain_info)
        suspicious_patterns = {
            "userinfo_present": bool(userinfo),
            "at_symbol_present": "@" in raw_url,
            "ip_literal_hostname": ip_address is not None,
            "punycode_hostname": "xn--" in hostname,
            "many_subdomain_labels": host_label_count > 5,
            "non_standard_port": port is not None and port not in ({80, 443} if parsed.scheme in _SUPPORTED_SCHEMES else set()),
            "suspicious_port": port in _SUSPICIOUS_PORTS,
            "known_url_shortener": shortener,
        }
        return {
            "normalized_url": _redact_url_credentials(normalized),
            "url_structure": {
                "scheme": parsed.scheme,
                "hostname": hostname,
                "port": port,
                "path": parsed.path,
                "query": parsed.query,
                "fragment": parsed.fragment,
                "userinfo": {
                    "present": bool(userinfo),
                    "username": unquote(username) if userinfo else None,
                    "password_present": bool(separator and password),
                    "password_value_exposed": False,
                },
                "url_length": len(raw_url),
                "normalized_url_length": len(normalized),
                "path_depth": int(ml_features["path_depth"]),
            },
            "domain_characteristics": {
                **domain_info,
                "hostname_label_count": host_label_count,
                "dot_count": hostname.count("."),
                "digit_count": sum(character.isdigit() for character in hostname),
                "hyphen_count": hostname.count("-"),
                "special_character_count": special_hostname_chars,
                "www_present": hostname.startswith("www."),
            },
            "security_indicators": {
                "https": parsed.scheme == "https",
                "http": parsed.scheme == "http",
                "supported_http_scheme": parsed.scheme in _SUPPORTED_SCHEMES,
                "suspicious_keyword_count": int(ml_features["suspicious_keyword_count"]),
                "suspicious_keywords": keyword_list,
                "suspicious_patterns": suspicious_patterns,
                "suspicious_port": port in _SUSPICIOUS_PORTS,
                "url_shortener": shortener,
            },
            "phase2_ml_features": {key: _json_value(value) for key, value in ml_features.items()},
        }

    def analyze_redirects(self, raw_url: str) -> dict[str, Any]:
        normalized = normalize_url(raw_url)
        original_parsed, original_hostname, _, _ = _parse_url(normalized)
        current_url = normalized
        visited = {current_url}
        chain = []
        status_code = None
        resolution_status = "reachable"
        reason = None

        for redirect_number in range(self.max_redirects + 1):
            parsed, hostname, port, ip_address = _parse_url(current_url)
            if parsed.scheme not in _SUPPORTED_SCHEMES:
                resolution_status, reason = "blocked", "unsupported_scheme"
                break
            try:
                addresses = _resolve_public_addresses(hostname, port or (443 if parsed.scheme == "https" else 80))
                response_status, location = self._fetch_once(current_url, parsed, hostname, port, ip_address, addresses)
                status_code = response_status
            except _BlockedDestination as exc:
                resolution_status, reason = "blocked", str(exc)
                break
            except (socket.timeout, TimeoutError) as exc:
                resolution_status, reason = "timeout", type(exc).__name__
                break
            except ssl.SSLError as exc:
                resolution_status, reason = "error", type(exc).__name__
                break
            except (socket.gaierror, ConnectionError, OSError) as exc:
                resolution_status, reason = "unreachable", type(exc).__name__
                break
            except Exception as exc:
                resolution_status, reason = "error", type(exc).__name__
                break

            if response_status not in {301, 302, 303, 307, 308} or not location:
                break
            if redirect_number >= self.max_redirects:
                resolution_status, reason = "blocked", "maximum_redirects_exceeded"
                break
            destination = normalize_url(urljoin(current_url, location))
            if destination in visited:
                resolution_status, reason = "blocked", "redirect_loop"
                break
            next_host = _parse_url(destination)[1]
            chain.append({
                "from_url": current_url,
                "status_code": response_status,
                "to_url": destination,
                "from_hostname": hostname,
                "to_hostname": next_host,
            })
            current_url = destination
            visited.add(current_url)

        try:
            final_parsed, final_hostname, _, final_ip = _parse_url(current_url)
            final_features = self.analyze_features(current_url)
            final_domain = final_features["domain_characteristics"].get("registered_domain")
        except URLInputError:
            final_parsed, final_hostname, final_ip, final_features, final_domain = None, None, None, None, None

        original_domain = self.analyze_features(normalized)["domain_characteristics"].get("registered_domain")
        final_domain_or_host_changed = (
            final_domain != original_domain if original_domain and final_domain
            else final_hostname != original_hostname if final_hostname else None
        )
        crossed_domains = False
        for hop in chain:
            source = _domain_details(hop["from_hostname"], _ip_or_none(hop["from_hostname"]))
            destination = _domain_details(hop["to_hostname"], _ip_or_none(hop["to_hostname"]))
            source_domain = source.get("registered_domain")
            destination_domain = destination.get("registered_domain")
            if source_domain and destination_domain:
                crossed_domains = crossed_domains or source_domain != destination_domain
            else:
                crossed_domains = crossed_domains or hop["from_hostname"] != hop["to_hostname"]
        return {
            "original_url": _redact_url_credentials(normalized),
            "resolution_status": resolution_status,
            "reason": reason,
            "http_status_code": status_code,
            "redirect_chain": [
                {**hop, "from_url": _redact_url_credentials(hop["from_url"]), "to_url": _redact_url_credentials(hop["to_url"])}
                for hop in chain
            ],
            "redirect_count": len(chain),
            "final_url": _redact_url_credentials(current_url) if final_hostname else None,
            "final_hostname": final_hostname,
            "final_destination_features": final_features,
            "hostname_changed": bool(final_hostname and final_hostname != original_hostname),
            "domain_changed": final_domain_or_host_changed,
            "crossed_registered_domains": crossed_domains,
            "https_changed": bool(final_parsed and (original_parsed.scheme == "https") != (final_parsed.scheme == "https")),
            "shortened_url_expanded": bool(
                len(chain) > 0
                and _is_shortener(original_hostname, self.analyze_features(normalized)["domain_characteristics"])
                and final_hostname != original_hostname
            ),
            "excessive_redirects": len(chain) > 3,
            "max_redirects": self.max_redirects,
        }

    def _fetch_once(self, url, parsed, hostname, port, ip_address, addresses):
        effective_port = port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        host_header = f"[{hostname}]" if ":" in hostname else hostname
        if port is not None and port != (443 if parsed.scheme == "https" else 80):
            host_header += f":{port}"
        last_error = None
        for address in addresses:
            try:
                if parsed.scheme == "https":
                    connection = _PinnedHTTPSConnection(address, effective_port, hostname, self.timeout_seconds)
                else:
                    connection = http.client.HTTPConnection(address, port=effective_port, timeout=self.timeout_seconds)
                connection.request(
                    "GET",
                    path,
                    headers={
                        "Host": host_header,
                        "User-Agent": "CYPHRA-Security-Analyzer/1.0",
                        "Accept": "*/*",
                        "Accept-Encoding": "identity",
                        "Range": "bytes=0-0",
                        "Connection": "close",
                    },
                )
                response = connection.getresponse()
                response_status = response.status
                location = response.getheader("Location")
                connection.close()
                return response_status, location
            except Exception as exc:
                last_error = exc
                try:
                    connection.close()
                except Exception:
                    pass
        if last_error is not None:
            raise last_error
        raise ConnectionError("No public address was available")

    def analyze(self, raw_url: str, follow_redirects: bool = True) -> dict[str, Any]:
        features = self.analyze_features(raw_url)
        redirect_data = self.analyze_redirects(raw_url) if follow_redirects else {
            "original_url": features["normalized_url"],
            "resolution_status": "not_requested",
            "reason": None,
            "http_status_code": None,
            "redirect_chain": [],
            "redirect_count": 0,
            "final_url": None,
            "final_hostname": None,
            "final_destination_features": None,
            "hostname_changed": False,
            "domain_changed": False,
            "crossed_registered_domains": False,
            "https_changed": False,
            "shortened_url_expanded": False,
            "excessive_redirects": False,
            "max_redirects": self.max_redirects,
        }
        return {
            "url": _redact_url_credentials(raw_url.strip()),
            "normalized_url": features.pop("normalized_url"),
            "url_structure": features["url_structure"],
            "domain_characteristics": features["domain_characteristics"],
            "security_indicators": features["security_indicators"],
            "phase2_ml_features": features["phase2_ml_features"],
            "redirect_analysis": redirect_data,
            "final_destination_features": redirect_data["final_destination_features"],
            "threat_intelligence": {"status": "not_integrated", "matches": []},
            "risk_decision": None,
        }


class _BlockedDestination(Exception):
    pass


def _ip_or_none(hostname: str):
    try:
        return ipaddress.ip_address(hostname.split("%", 1)[0])
    except ValueError:
        return None


def _resolve_public_addresses(hostname: str, port: int) -> list[str]:
    if hostname.lower() == "localhost" or hostname.lower().endswith((".localhost", ".local")):
        raise _BlockedDestination("local_hostname")
    try:
        address = ipaddress.ip_address(hostname.split("%", 1)[0])
        addresses = [address.compressed]
    except ValueError:
        try:
            records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror:
            raise
        addresses = sorted({record[4][0] for record in records})
    if not addresses:
        raise ConnectionError("Hostname did not resolve")
    for value in addresses:
        address = ipaddress.ip_address(value.split("%", 1)[0])
        if not address.is_global:
            raise _BlockedDestination("non_public_ip_address")
    return addresses


def _json_value(value):
    if hasattr(value, "item"):
        return value.item()
    return value
