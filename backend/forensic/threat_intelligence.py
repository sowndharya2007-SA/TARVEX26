"""
TARVEX26
Threat Intelligence & External IOC Correlation Engine

SIH26106

External intelligence:
- ThreatFox malware IOC correlation

Internal intelligence:
- GeoIP / ASN
- Domain intelligence
- URL heuristic intelligence

Important:
ThreatFox is used for malware-related IOC correlation.
A ThreatFox "no match" does NOT mean an indicator is safe.
"""

import os
import ipaddress
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

ENGINE_NAME = "TARVEX26 Threat Intelligence Engine"
ENGINE_VERSION = "2.0"

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

THREATFOX_AUTH_KEY = os.getenv(
    "THREATFOX_AUTH_KEY",
    ""
).strip()

REQUEST_TIMEOUT = 12


# ============================================================
# BASIC HELPERS
# ============================================================

def utc_now():
    return datetime.now(timezone.utc).isoformat()


def clean(value):
    if value is None:
        return ""

    try:
        return str(value).strip()
    except Exception:
        return ""


def unique(values):
    result = []

    for value in values or []:
        value = clean(value)

        if value and value not in result:
            result.append(value)

    return result


def is_valid_ip(value):
    try:
        ipaddress.ip_address(clean(value))
        return True
    except Exception:
        return False


def normalize_ip(value):
    value = clean(value)

    if not value:
        return ""

    # Handle possible ip:port values.
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)

        if port.isdigit() and is_valid_ip(host):
            return host

    return value


# ============================================================
# THREATFOX CLIENT
# ============================================================

def threatfox_status():
    """
    Return configuration status without exposing the API key.
    """

    if not THREATFOX_AUTH_KEY:
        return {
            "status": "NOT_CONFIGURED",
            "configured": False,
            "source": "ThreatFox"
        }

    return {
        "status": "CONFIGURED",
        "configured": True,
        "source": "ThreatFox"
    }


def threatfox_search_ioc(ioc):
    """
    Search one IOC using ThreatFox exact-match search.

    ThreatFox API:
        POST https://threatfox-api.abuse.ch/api/v1/

    Required:
        Auth-Key header
        query=search_ioc
        search_term=<IOC>
        exact_match=true
    """

    ioc = clean(ioc)

    if not ioc:
        return {
            "status": "INVALID",
            "ioc": ioc,
            "matches": [],
            "source": "ThreatFox"
        }

    if not THREATFOX_AUTH_KEY:
        return {
            "status": "NOT_CONFIGURED",
            "ioc": ioc,
            "matches": [],
            "source": "ThreatFox"
        }

    headers = {
        "Auth-Key": THREATFOX_AUTH_KEY,
        "Content-Type": "application/json"
    }

    payload = {
        "query": "search_ioc",
        "search_term": ioc,
        "exact_match": True
    }

    try:

        response = requests.post(
            THREATFOX_API_URL,
            headers=headers,
            json=payload,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code != 200:
            return {
                "status": "ERROR",
                "ioc": ioc,
                "matches": [],
                "http_status": response.status_code,
                "source": "ThreatFox",
                "error": (
                    f"ThreatFox HTTP {response.status_code}"
                )
            }

        data = response.json()

        query_status = clean(
            data.get("query_status")
        ).lower()

        if query_status != "ok":
            return {
                "status": "NO_MATCH",
                "ioc": ioc,
                "matches": [],
                "source": "ThreatFox",
                "query_status": query_status
            }

        matches = data.get(
            "data",
            []
        )

        if not isinstance(matches, list):
            matches = []

        return {
            "status": (
                "MATCH"
                if matches
                else "NO_MATCH"
            ),
            "ioc": ioc,
            "matches": matches,
            "match_count": len(matches),
            "source": "ThreatFox",
            "queried_at": utc_now()
        }

    except requests.RequestException as error:

        return {
            "status": "ERROR",
            "ioc": ioc,
            "matches": [],
            "source": "ThreatFox",
            "error": (
                f"ThreatFox connection error: {str(error)}"
            )
        }

    except Exception as error:

        return {
            "status": "ERROR",
            "ioc": ioc,
            "matches": [],
            "source": "ThreatFox",
            "error": (
                f"ThreatFox processing error: {str(error)}"
            )
        }


# ============================================================
# THREATFOX RESULT NORMALIZATION
# ============================================================

def normalize_threatfox_match(match):
    """
    Convert ThreatFox response data into a stable TARVEX26 format.
    """

    if not isinstance(match, dict):
        return {}

    return {
        "id": match.get("id"),
        "ioc": clean(match.get("ioc")),
        "ioc_type": clean(match.get("ioc_type")),
        "ioc_type_description": clean(
            match.get("ioc_type_desc")
        ),
        "threat_type": clean(
            match.get("threat_type")
        ),
        "threat_type_description": clean(
            match.get("threat_type_desc")
        ),
        "malware": clean(
            match.get("malware")
        ),
        "malware_printable": clean(
            match.get("malware_printable")
        ),
        "confidence_level": match.get(
            "confidence_level"
        ),
        "first_seen": match.get(
            "first_seen"
        ),
        "last_seen": match.get(
            "last_seen"
        ),
        "reporter": clean(
            match.get("reporter")
        ),
        "reference": clean(
            match.get("reference")
        ),
        "tags": match.get(
            "tags"
        )
    }


# ============================================================
# EXTERNAL IOC CORRELATION
# ============================================================

def correlate_iocs(iocs):
    """
    Search unique IOCs against ThreatFox.
    """

    iocs = unique(iocs)

    results = []

    for ioc in iocs:

        result = threatfox_search_ioc(ioc)

        normalized_matches = []

        for match in result.get(
            "matches",
            []
        ):

            normalized = normalize_threatfox_match(
                match
            )

            if normalized:
                normalized_matches.append(
                    normalized
                )

        result["matches"] = normalized_matches

        results.append(result)

    return results


# ============================================================
# IP REPUTATION
# ============================================================

def analyze_ip_reputation(ip_result):

    if not isinstance(ip_result, dict):
        return None

    ip = normalize_ip(
        ip_result.get("ip")
        or ip_result.get("ip_address")
    )

    if not ip:
        return None

    existing_threat = clean(
        ip_result.get("threat_status")
        or ip_result.get("threat")
        or ip_result.get("reputation")
    ).upper()

    if existing_threat in {
        "MALICIOUS",
        "SUSPICIOUS"
    }:

        base_status = existing_threat

    elif existing_threat in {
        "NO_THREAT",
        "NO_INDICATORS"
    }:

        base_status = "NO_INDICATORS"

    else:
        base_status = "UNKNOWN"

    return {
        "indicator_type": "IP",
        "indicator": ip,
        "title": ip,
        "reputation_status": base_status,
        "source": "TARVEX26 GeoIP / IP Intelligence",
        "organization": clean(
            ip_result.get("organization")
            or ip_result.get("org")
        ),
        "isp": clean(
            ip_result.get("isp")
        ),
        "asn": clean(
            ip_result.get("asn")
        ),
        "country": clean(
            ip_result.get("country")
        ),
        "city": clean(
            ip_result.get("city")
        ),
        "reverse_dns": clean(
            ip_result.get("reverse_dns")
        )
    }


# ============================================================
# DOMAIN REPUTATION
# ============================================================

def analyze_domain_reputation(domain_result):

    if not isinstance(domain_result, dict):
        return None

    domain = clean(
        domain_result.get("domain")
        or domain_result.get("hostname")
    )

    if not domain:
        return None

    findings = domain_result.get(
        "findings",
        []
    )

    if not isinstance(findings, list):
        findings = []

    suspicious_words = [
        "malicious",
        "suspicious",
        "blacklist",
        "phishing",
        "fraud",
        "threat"
    ]

    suspicious = any(
        any(
            word in clean(finding).lower()
            for word in suspicious_words
        )
        for finding in findings
    )

    return {
        "indicator_type": "DOMAIN",
        "indicator": domain,
        "title": domain,
        "reputation_status": (
            "SUSPICIOUS"
            if suspicious
            else "UNKNOWN"
        ),
        "source": "TARVEX26 Domain Intelligence",
        "findings": findings
    }


# ============================================================
# URL REPUTATION
# ============================================================

def analyze_url_reputation(url_result):

    if not isinstance(url_result, dict):
        return None

    url = clean(
        url_result.get("url")
    )

    if not url:
        return None

    risk_score = url_result.get(
        "risk_score",
        0
    )

    try:
        risk_score = int(risk_score)
    except Exception:
        risk_score = 0

    if risk_score >= 7:
        status = "MALICIOUS"

    elif risk_score > 0:
        status = "SUSPICIOUS"

    else:
        status = "NO_INDICATORS"

    return {
        "indicator_type": "URL",
        "indicator": url,
        "title": url,
        "reputation_status": status,
        "source": "TARVEX26 URL Intelligence",
        "risk_score": risk_score,
        "findings": url_result.get(
            "findings",
            []
        )
    }


# ============================================================
# OVERALL VERDICT
# ============================================================

def calculate_overall_verdict(
    indicators,
    external_matches
):

    external_malicious = any(
        item.get("status") == "MATCH"
        and item.get("matches")
        for item in external_matches
    )

    if external_malicious:
        return {
            "status": "MALICIOUS",
            "confidence": 95
        }

    statuses = [
        clean(
            item.get("reputation_status")
        ).upper()
        for item in indicators
    ]

    if "MALICIOUS" in statuses:
        return {
            "status": "MALICIOUS",
            "confidence": 90
        }

    if "SUSPICIOUS" in statuses:
        return {
            "status": "SUSPICIOUS",
            "confidence": 75
        }

    if (
        statuses
        and all(
            status == "NO_INDICATORS"
            for status in statuses
        )
    ):
        return {
            "status": "NO_INDICATORS",
            "confidence": 70
        }

    return {
        "status": "UNKNOWN",
        "confidence": None
    }


# ============================================================
# MAIN THREAT INTELLIGENCE ENGINE
# ============================================================

def analyze_threat_intelligence(
    geoip_intelligence=None,
    domain_intelligence=None,
    url_intelligence=None
):

    indicators = []

    # --------------------------------------------------------
    # IP INDICATORS
    # --------------------------------------------------------

    geo_results = []

    if isinstance(
        geoip_intelligence,
        dict
    ):

        geo_results = geoip_intelligence.get(
            "results",
            []
        )

    if isinstance(
        geo_results,
        list
    ):

        for item in geo_results:

            indicator = analyze_ip_reputation(
                item
            )

            if indicator:
                indicators.append(
                    indicator
                )

    # --------------------------------------------------------
    # DOMAIN INDICATORS
    # --------------------------------------------------------

    domain_results = []

    if isinstance(
        domain_intelligence,
        dict
    ):

        domain_results = domain_intelligence.get(
            "results",
            []
        )

        # Support a single domain object.
        if not domain_results:
            if domain_intelligence.get(
                "domain"
            ):
                domain_results = [
                    domain_intelligence
                ]

    elif isinstance(
        domain_intelligence,
        list
    ):

        domain_results = domain_intelligence

    if isinstance(
        domain_results,
        list
    ):

        for item in domain_results:

            indicator = analyze_domain_reputation(
                item
            )

            if indicator:
                indicators.append(
                    indicator
                )

    # --------------------------------------------------------
    # URL INDICATORS
    # --------------------------------------------------------

    url_results = []

    if isinstance(
        url_intelligence,
        dict
    ):

        url_results = url_intelligence.get(
            "results",
            []
        )

    elif isinstance(
        url_intelligence,
        list
    ):

        url_results = url_intelligence

    if isinstance(
        url_results,
        list
    ):

        for item in url_results:

            indicator = analyze_url_reputation(
                item
            )

            if indicator:
                indicators.append(
                    indicator
                )

    # --------------------------------------------------------
    # EXTERNAL THREATFOX CORRELATION
    # --------------------------------------------------------

    external_iocs = unique([
        item.get("indicator")
        for item in indicators
        if item.get("indicator")
    ])

    external_results = correlate_iocs(
        external_iocs
    )

    # --------------------------------------------------------
    # ADD EXTERNAL RESULTS TO INDICATORS
    # --------------------------------------------------------

    external_by_ioc = {
        clean(item.get("ioc")): item
        for item in external_results
    }

    for indicator in indicators:

        ioc = clean(
            indicator.get("indicator")
        )

        external = external_by_ioc.get(
            ioc
        )

        if external:

            indicator[
                "external_intelligence"
            ] = {
                "source": "ThreatFox",
                "status": external.get(
                    "status"
                ),
                "match_count": external.get(
                    "match_count",
                    len(
                        external.get(
                            "matches",
                            []
                        )
                    )
                ),
                "matches": external.get(
                    "matches",
                    []
                ),
                "queried_at": external.get(
                    "queried_at"
                ),
                "error": external.get(
                    "error"
                )
            }

            if external.get(
                "status"
            ) == "MATCH":

                indicator[
                    "reputation_status"
                ] = "MALICIOUS"

    # --------------------------------------------------------
    # OVERALL VERDICT
    # --------------------------------------------------------

    verdict = calculate_overall_verdict(
        indicators,
        external_results
    )

    # --------------------------------------------------------
    # COUNTS
    # --------------------------------------------------------

    counts = {
        "malicious": 0,
        "suspicious": 0,
        "no_indicators": 0,
        "unknown": 0,
        "unavailable": 0
    }

    for indicator in indicators:

        status = clean(
            indicator.get(
                "reputation_status"
            )
        ).upper()

        if status == "MALICIOUS":
            counts["malicious"] += 1

        elif status == "SUSPICIOUS":
            counts["suspicious"] += 1

        elif status == "NO_INDICATORS":
            counts["no_indicators"] += 1

        elif status == "UNAVAILABLE":
            counts["unavailable"] += 1

        else:
            counts["unknown"] += 1

    # --------------------------------------------------------
    # FINDINGS
    # --------------------------------------------------------

    findings = []

    if not THREATFOX_AUTH_KEY:

        findings.append(
            "ThreatFox is not configured."
        )

    else:

        findings.append(
            "ThreatFox external IOC correlation is enabled."
        )

    match_count = sum(
        1
        for item in external_results
        if item.get("status") == "MATCH"
    )

    if match_count:

        findings.append(
            f"{match_count} indicator(s) matched "
            "ThreatFox malware IOC intelligence."
        )

    else:

        findings.append(
            "No analyzed indicator matched "
            "ThreatFox malware IOC intelligence."
        )

    findings.append(
        "ThreatFox no-match results do not prove "
        "that an indicator is benign."
    )

    # --------------------------------------------------------
    # ENGINE STATUS
    # --------------------------------------------------------

    if THREATFOX_AUTH_KEY:

        engine_status = "ACTIVE"

    else:

        engine_status = "PARTIAL"

    return {

        "overall_status":
            verdict["status"],

        "confidence":
            verdict["confidence"],

        "counts":
            counts,

        "indicators":
            indicators,

        "findings":
            findings,

        "external_sources": {

            "threatfox": {

                "status": (
                    "CONNECTED"
                    if THREATFOX_AUTH_KEY
                    else "NOT_CONFIGURED"
                ),

                "configured":
                    bool(THREATFOX_AUTH_KEY),

                "indicator_count":
                    len(external_results),

                "match_count":
                    match_count,

                "queried_at":
                    utc_now()
            }
        },

        "engine": {

            "name":
                ENGINE_NAME,

            "version":
                ENGINE_VERSION,

            "status":
                engine_status,

            "capabilities": [

                "ThreatFox IOC correlation",

                "IP reputation correlation",

                "Domain reputation correlation",

                "URL heuristic correlation",

                "External IOC normalization",

                "Explainable threat assessment"
            ]
        },

        "analyzed_at":
            utc_now()
    }