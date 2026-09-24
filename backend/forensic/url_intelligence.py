"""
TARVEX26
URL Intelligence Engine
SIH26106 - Email Threat Detection, GeoLocation and Forensic Intelligence

Analyzes URLs extracted from email content for:
- Suspicious schemes
- Credential/login paths
- Verification/urgent language
- Raw IP destinations
- Obfuscation
- Suspicious domain patterns
- Redirect indicators
- Excessive URL length
"""

import re
from urllib.parse import urlparse


SUSPICIOUS_PATH_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "password",
    "credential",
    "secure",
    "security",
    "confirm",
    "update",
    "authenticate",
    "wallet",
    "payment",
}

SUSPICIOUS_DOMAIN_KEYWORDS = {
    "verify",
    "secure",
    "account",
    "login",
    "update",
    "security",
    "confirm",
    "support",
    "auth",
}

REDIRECT_PARAMETERS = {
    "url",
    "redirect",
    "redirect_url",
    "return",
    "return_url",
    "next",
    "continue",
    "target",
    "dest",
    "destination",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
}


def _unique(items):
    seen = set()
    result = []

    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)

    return result


def extract_urls_from_text(text):
    """
    Extract HTTP/HTTPS URLs from email text.
    """
    if not text:
        return []

    pattern = r'https?://[^\s<>"\']+'

    try:
        matches = re.findall(pattern, str(text), flags=re.IGNORECASE)

        cleaned = []

        for url in matches:
            url = url.strip()

            # Remove common trailing punctuation from prose.
            url = url.rstrip(".,;:!?)]}")

            if url:
                cleaned.append(url)

        return _unique(cleaned)

    except Exception:
        return []


def _is_ipv4(host):
    if not host:
        return False

    pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if not re.match(pattern, host):
        return False

    try:
        return all(0 <= int(part) <= 255 for part in host.split("."))
    except Exception:
        return False


def _analyze_single_url(url):
    findings = []
    risk_points = 0

    try:
        parsed = urlparse(url)

        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()

        full_lower = url.lower()

        # ---------------------------------------------------------
        # Scheme
        # ---------------------------------------------------------

        if scheme == "http":
            findings.append("URL uses unencrypted HTTP")
            risk_points += 1

        elif scheme != "https":
            findings.append(f"Unusual URL scheme: {scheme}")
            risk_points += 2

        # ---------------------------------------------------------
        # Raw IP destination
        # ---------------------------------------------------------

        raw_ip = _is_ipv4(hostname)

        if raw_ip:
            findings.append("URL points directly to an IP address")
            risk_points += 3

        # ---------------------------------------------------------
        # Suspicious path keywords
        # ---------------------------------------------------------

        matched_path_keywords = []

        for keyword in SUSPICIOUS_PATH_KEYWORDS:
            if keyword in path:
                matched_path_keywords.append(keyword)

        if matched_path_keywords:
            matched_path_keywords = sorted(set(matched_path_keywords))

            findings.append(
                "Credential/account-oriented URL path: "
                + ", ".join(matched_path_keywords)
            )

            risk_points += min(3, len(matched_path_keywords))

        # ---------------------------------------------------------
        # Suspicious domain keywords
        # ---------------------------------------------------------

        matched_domain_keywords = []

        for keyword in SUSPICIOUS_DOMAIN_KEYWORDS:
            if keyword in hostname:
                matched_domain_keywords.append(keyword)

        if matched_domain_keywords:
            matched_domain_keywords = sorted(set(matched_domain_keywords))

            findings.append(
                "Suspicious domain keyword pattern: "
                + ", ".join(matched_domain_keywords)
            )

            risk_points += 1

        # ---------------------------------------------------------
        # URL obfuscation
        # ---------------------------------------------------------

        obfuscation_patterns = [
            "%40",
            "%2f",
            "%2e",
            "%3a",
            "@",
        ]

        matched_obfuscation = [
            pattern
            for pattern in obfuscation_patterns
            if pattern in full_lower
        ]

        if matched_obfuscation:
            findings.append("Potential URL obfuscation detected")
            risk_points += 2

        # ---------------------------------------------------------
        # Excessive length
        # ---------------------------------------------------------

        if len(url) > 180:
            findings.append("Unusually long URL")
            risk_points += 1

        # ---------------------------------------------------------
        # Redirect indicators
        # ---------------------------------------------------------

        redirect_matches = []

        query_parts = query.split("&")

        for part in query_parts:
            if "=" not in part:
                continue

            key = part.split("=", 1)[0].strip().lower()

            if key in REDIRECT_PARAMETERS:
                redirect_matches.append(key)

        if redirect_matches:
            redirect_matches = sorted(set(redirect_matches))

            findings.append(
                "Redirect parameter detected: "
                + ", ".join(redirect_matches)
            )

            risk_points += 2

        # ---------------------------------------------------------
        # URL shortener
        # ---------------------------------------------------------

        is_shortener = hostname in SHORTENER_DOMAINS

        if is_shortener:
            findings.append("Known URL-shortener domain detected")
            risk_points += 2

        # ---------------------------------------------------------
        # Suspicious hostname structure
        # ---------------------------------------------------------

        hostname_parts = hostname.split(".") if hostname else []

        if len(hostname_parts) >= 4:
            findings.append("Deeply nested hostname")
            risk_points += 1

        # ---------------------------------------------------------
        # Risk classification
        # ---------------------------------------------------------

        if risk_points >= 6:
            risk_level = "HIGH"
        elif risk_points >= 3:
            risk_level = "MEDIUM"
        elif risk_points >= 1:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"

        return {
            "url": url,
            "scheme": scheme,
            "hostname": hostname,
            "path": parsed.path or "",
            "query": parsed.query or "",
            "is_ip_destination": raw_ip,
            "is_url_shortener": is_shortener,
            "suspicious": bool(findings),
            "risk_level": risk_level,
            "risk_score": risk_points,
            "findings": findings,
        }

    except Exception as error:
        return {
            "url": url,
            "scheme": "",
            "hostname": "",
            "path": "",
            "query": "",
            "is_ip_destination": False,
            "is_url_shortener": False,
            "suspicious": False,
            "risk_level": "UNKNOWN",
            "risk_score": 0,
            "findings": [
                f"URL parsing error: {str(error)}"
            ],
        }


def analyze_urls(urls):
    """
    Analyze a list of URLs.
    """

    if not urls:
        return {
            "total": 0,
            "suspicious_count": 0,
            "suspicious_urls": [],
            "risk_level": "NONE",
            "urls": [],
            "findings": [],
            "engine": {
                "name": "TARVEX26 URL Intelligence Engine",
                "version": "1.0",
                "analysis_type": "URL heuristic and structural analysis",
            },
        }

    if isinstance(urls, str):
        urls = extract_urls_from_text(urls)

    results = []

    for url in urls:
        if not isinstance(url, str):
            continue

        url = url.strip()

        if not url:
            continue

        results.append(_analyze_single_url(url))

    suspicious_results = [
        item
        for item in results
        if item.get("suspicious")
    ]

    findings = []

    for item in results:
        for finding in item.get("findings", []):
            findings.append(
                f"{item.get('url')}: {finding}"
            )

    if any(item.get("risk_level") == "HIGH" for item in results):
        overall_risk = "HIGH"
    elif any(item.get("risk_level") == "MEDIUM" for item in results):
        overall_risk = "MEDIUM"
    elif any(item.get("risk_level") == "LOW" for item in results):
        overall_risk = "LOW"
    elif results:
        overall_risk = "MINIMAL"
    else:
        overall_risk = "NONE"

    return {
        "total": len(results),
        "suspicious_count": len(suspicious_results),
        "suspicious_urls": [
            item.get("url")
            for item in suspicious_results
        ],
        "risk_level": overall_risk,
        "urls": results,
        "findings": _unique(findings),
        "engine": {
            "name": "TARVEX26 URL Intelligence Engine",
            "version": "1.0",
            "analysis_type": "URL heuristic and structural analysis",
            "capabilities": [
                "URL extraction",
                "Scheme analysis",
                "Credential-path detection",
                "Suspicious domain pattern detection",
                "Raw IP destination detection",
                "Obfuscation detection",
                "Redirect detection",
                "URL shortener detection",
                "Risk classification",
            ],
        },
    }