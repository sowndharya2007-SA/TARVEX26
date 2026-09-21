"""
TARVEX26
URL Intelligence Engine
SIH26106 - Email Forensics

Analyzes URLs found inside email content for:
- Suspicious domains
- Raw IP URLs
- HTTPS usage
- Phishing paths
- URL obfuscation
- Excessive URL length
- Suspicious keywords
- Embedded credentials
- URL shorteners
"""

import re
import ipaddress
from urllib.parse import urlparse, unquote


SUSPICIOUS_DOMAIN_KEYWORDS = [
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "login",
    "signin",
    "support",
    "update",
    "confirm",
    "payment",
    "invoice",
    "wallet",
    "password",
    "alert",
]

SUSPICIOUS_PATH_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "password",
    "payment",
    "invoice",
    "wallet",
    "confirm",
    "update",
    "security",
]

SHORTENER_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
]


def _safe_text(value):
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")

    return str(value)


def extract_urls(text):
    """
    Extract HTTP/HTTPS URLs from email content.
    """

    text = _safe_text(text)

    pattern = r"""https?://[^\s<>"']+"""

    urls = re.findall(
        pattern,
        text,
        re.IGNORECASE
    )

    cleaned = []

    for url in urls:

        url = url.rstrip(
            ".,;:!?)]}"
        )

        if url not in cleaned:
            cleaned.append(url)

    return cleaned


def _is_ip_address(host):

    try:
        ipaddress.ip_address(host)
        return True

    except ValueError:
        return False


def _domain_keywords(domain):

    domain = domain.lower()

    return [
        keyword
        for keyword in SUSPICIOUS_DOMAIN_KEYWORDS
        if keyword in domain
    ]


def _path_keywords(path):

    path = path.lower()

    return [
        keyword
        for keyword in SUSPICIOUS_PATH_KEYWORDS
        if keyword in path
    ]


def analyze_url(url):

    parsed = urlparse(url)

    host = parsed.hostname or ""
    host = host.lower()

    path = parsed.path or ""

    decoded_url = unquote(url)

    findings = []

    risk_score = 0

    # ---------------------------------------------
    # Raw IP address
    # ---------------------------------------------

    if _is_ip_address(host):

        risk_score += 30

        findings.append(
            "URL uses a raw IP address instead of a domain."
        )

    # ---------------------------------------------
    # Suspicious domain keywords
    # ---------------------------------------------

    domain_keywords = _domain_keywords(host)

    if domain_keywords:

        risk_score += min(
            25,
            len(domain_keywords) * 8
        )

        findings.append(
            "Suspicious domain keywords: "
            + ", ".join(domain_keywords)
        )

    # ---------------------------------------------
    # Suspicious path
    # ---------------------------------------------

    path_keywords = _path_keywords(path)

    if path_keywords:

        risk_score += min(
            30,
            len(path_keywords) * 7
        )

        findings.append(
            "Sensitive action path detected: "
            + ", ".join(path_keywords)
        )

    # ---------------------------------------------
    # HTTP instead of HTTPS
    # ---------------------------------------------

    if parsed.scheme.lower() == "http":

        risk_score += 15

        findings.append(
            "URL uses HTTP instead of HTTPS."
        )

    # ---------------------------------------------
    # Embedded credentials
    # ---------------------------------------------

    if parsed.username or parsed.password:

        risk_score += 25

        findings.append(
            "URL contains embedded credentials."
        )

    # ---------------------------------------------
    # Excessive URL length
    # ---------------------------------------------

    if len(url) > 150:

        risk_score += 10

        findings.append(
            "Unusually long URL detected."
        )

    # ---------------------------------------------
    # Percent encoding
    # ---------------------------------------------

    if "%" in url:

        risk_score += 8

        findings.append(
            "URL contains percent-encoded characters."
        )

    # ---------------------------------------------
    # @ symbol
    # ---------------------------------------------

    if "@" in url:

        risk_score += 15

        findings.append(
            "URL contains '@' character which may "
            "obscure the actual destination."
        )

    # ---------------------------------------------
    # URL shortener
    # ---------------------------------------------

    is_shortener = host in SHORTENER_DOMAINS

    if is_shortener:

        risk_score += 12

        findings.append(
            "URL uses a known URL-shortening service."
        )

    # ---------------------------------------------
    # Deep subdomain structure
    # ---------------------------------------------

    subdomain_count = max(
        0,
        len(host.split(".")) - 2
    )

    if subdomain_count >= 3:

        risk_score += 10

        findings.append(
            "URL contains an unusually deep "
            "subdomain structure."
        )

    # ---------------------------------------------
    # URL decoding difference
    # ---------------------------------------------

    if decoded_url != url:

        findings.append(
            "URL changes after decoding."
        )

    risk_score = min(
        100,
        risk_score
    )

    # ---------------------------------------------
    # Risk level
    # ---------------------------------------------

    if risk_score >= 70:

        risk_level = "HIGH"

    elif risk_score >= 40:

        risk_level = "MEDIUM"

    elif risk_score >= 15:

        risk_level = "LOW"

    else:

        risk_level = "MINIMAL"

    return {

        "url": url,

        "domain": host,

        "scheme": parsed.scheme,

        "path": path,

        "is_https": (
            parsed.scheme.lower() == "https"
        ),

        "is_ip_address": (
            _is_ip_address(host)
        ),

        "is_shortener": is_shortener,

        "domain_keywords": domain_keywords,

        "path_keywords": path_keywords,

        "risk_score": risk_score,

        "risk_level": risk_level,

        "findings": list(
            dict.fromkeys(findings)
        ),
    }


def analyze_urls(text):

    urls = extract_urls(text)

    results = []

    for url in urls:

        results.append(
            analyze_url(url)
        )

    suspicious = [
        item
        for item in results
        if item["risk_score"] >= 40
    ]

    if any(
        item["risk_score"] >= 70
        for item in results
    ):

        overall_risk = "HIGH"

    elif suspicious:

        overall_risk = "MEDIUM"

    elif results:

        overall_risk = "LOW"

    else:

        overall_risk = "NONE"

    return {

        "total_urls": len(urls),

        "suspicious_urls": len(
            suspicious
        ),

        "urls": results,

        "risk_level": overall_risk,

        "engine": {

            "name":
                "TARVEX26 URL Intelligence Engine",

            "version":
                "1.0",

            "analysis_type":
                "URL structural and phishing "
                "indicator analysis",

            "external_reputation":
                "PENDING THREAT INTELLIGENCE MODULE"
        }
    }