"""
TARVEX26
IP Intelligence & Reputation Engine
SIH26106 - Email Threat Detection and Forensic Intelligence

Capabilities:
- IPv4 / IPv6 validation
- Public/private/reserved classification
- Reverse DNS
- Network classification
- Documentation/test IP detection
- Basic infrastructure indicators
- Optional AbuseIPDB reputation lookup
- Explainable findings
- Confidence assessment
"""

import os
import ipaddress
import socket
from datetime import datetime, timezone

import requests


ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

REQUEST_TIMEOUT = 5


# ============================================================
# IP CLASSIFICATION
# ============================================================

def _classify_ip(ip_obj):
    """
    Classify an IP without assuming that every non-public IP
    is malicious.
    """

    if ip_obj.is_loopback:
        return "LOOPBACK"

    if ip_obj.is_private:
        return "PRIVATE"

    if ip_obj.is_link_local:
        return "LINK_LOCAL"

    if ip_obj.is_multicast:
        return "MULTICAST"

    if ip_obj.is_reserved:
        return "RESERVED"

    if ip_obj.is_unspecified:
        return "UNSPECIFIED"

    return "PUBLIC"


# ============================================================
# DOCUMENTATION / TEST NETWORKS
# ============================================================

def _is_documentation_ip(ip_obj):
    """
    RFC documentation/test ranges.

    These should not be treated as real geolocation targets.
    """

    documentation_networks = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("2001:db8::/32"),
    ]

    return any(ip_obj in network for network in documentation_networks)


# ============================================================
# REVERSE DNS
# ============================================================

def _reverse_dns(ip):
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)

        return {
            "status": "FOUND",
            "hostname": hostname,
            "aliases": aliases,
            "addresses": addresses,
        }

    except Exception as error:
        return {
            "status": "NOT_FOUND",
            "hostname": None,
            "aliases": [],
            "addresses": [],
            "error": str(error),
        }


# ============================================================
# INFRASTRUCTURE HEURISTICS
# ============================================================

def _infrastructure_indicator(hostname):
    if not hostname:
        return {
            "is_cloud": False,
            "is_hosting": False,
            "provider_hint": None,
        }

    value = hostname.lower()

    cloud_keywords = {
        "amazonaws": "AWS",
        "compute.amazonaws": "AWS",
        "cloudfront": "AWS",
        "googleusercontent": "Google Cloud",
        "googlehosted": "Google Cloud",
        "azure": "Microsoft Azure",
        "microsoft": "Microsoft",
        "digitalocean": "DigitalOcean",
        "linode": "Linode",
        "vultr": "Vultr",
        "oraclecloud": "Oracle Cloud",
        "cloudflare": "Cloudflare",
    }

    hosting_keywords = [
        "host",
        "server",
        "vps",
        "dedicated",
        "colo",
        "datacenter",
        "compute",
        "cloud",
    ]

    provider_hint = None

    for keyword, provider in cloud_keywords.items():
        if keyword in value:
            provider_hint = provider
            break

    return {
        "is_cloud": provider_hint is not None,
        "is_hosting": any(word in value for word in hosting_keywords),
        "provider_hint": provider_hint,
    }


# ============================================================
# ABUSEIPDB
# ============================================================

def _abuseipdb_lookup(ip):
    """
    Optional live reputation lookup.

    If no API key is configured, this deliberately returns
    UNKNOWN instead of pretending that the IP is clean.
    """

    if not ABUSEIPDB_API_KEY:
        return {
            "status": "UNAVAILABLE",
            "message": "AbuseIPDB API key not configured.",
            "abuse_confidence_score": None,
            "total_reports": None,
            "last_reported_at": None,
            "country_code": None,
            "isp": None,
            "domain": None,
        }

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
            },
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code != 200:
            return {
                "status": "UNAVAILABLE",
                "message": f"AbuseIPDB HTTP {response.status_code}",
                "abuse_confidence_score": None,
                "total_reports": None,
                "last_reported_at": None,
                "country_code": None,
                "isp": None,
                "domain": None,
            }

        data = response.json().get("data", {})

        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)

        if score >= 80:
            reputation = "MALICIOUS"
        elif score >= 30:
            reputation = "SUSPICIOUS"
        else:
            reputation = "LOW_RISK"

        return {
            "status": "FOUND",
            "reputation": reputation,
            "message": "Live AbuseIPDB reputation available.",
            "abuse_confidence_score": score,
            "total_reports": reports,
            "last_reported_at": data.get("lastReportedAt"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
        }

    except Exception as error:
        return {
            "status": "UNAVAILABLE",
            "message": str(error),
            "abuse_confidence_score": None,
            "total_reports": None,
            "last_reported_at": None,
            "country_code": None,
            "isp": None,
            "domain": None,
        }


# ============================================================
# SINGLE IP ANALYSIS
# ============================================================

def _analyze_single_ip(raw_ip):

    raw_ip = str(raw_ip).strip()

    result = {
        "ip": raw_ip,
        "version": None,
        "address_type": "UNKNOWN",
        "is_public": False,
        "is_private": False,
        "is_reserved": False,
        "is_documentation": False,
        "reverse_dns": None,
        "infrastructure": {
            "is_cloud": False,
            "is_hosting": False,
            "provider_hint": None,
        },
        "reputation": {
            "status": "UNKNOWN",
            "reputation": "UNKNOWN",
        },
        "findings": [],
        "confidence": "LOW",
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }

    # --------------------------------------------------------
    # VALIDATION
    # --------------------------------------------------------

    try:
        ip_obj = ipaddress.ip_address(raw_ip)

    except ValueError:
        result["address_type"] = "INVALID"
        result["findings"].append(
            f"Invalid IP address format: {raw_ip}"
        )
        return result

    # --------------------------------------------------------
    # BASIC INFORMATION
    # --------------------------------------------------------

    result["version"] = f"IPv{ip_obj.version}"

    address_type = _classify_ip(ip_obj)

    result["address_type"] = address_type
    result["is_public"] = address_type == "PUBLIC"
    result["is_private"] = ip_obj.is_private
    result["is_reserved"] = ip_obj.is_reserved

    # --------------------------------------------------------
    # DOCUMENTATION IP
    # --------------------------------------------------------

    if _is_documentation_ip(ip_obj):

        result["is_documentation"] = True
        result["address_type"] = "DOCUMENTATION"

        result["findings"].append(
            "Documentation/test IP detected. "
            "This address should not be used for real-world geolocation."
        )

        result["reputation"] = {
            "status": "NOT_APPLICABLE",
            "reputation": "TEST_ADDRESS",
        }

        result["confidence"] = "HIGH"

        return result

    # --------------------------------------------------------
    # NON-PUBLIC ADDRESS
    # --------------------------------------------------------

    if not result["is_public"]:

        result["findings"].append(
            f"Address classified as {address_type.lower()} network infrastructure."
        )

        result["reputation"] = {
            "status": "NOT_APPLICABLE",
            "reputation": "NOT_PUBLIC",
        }

        result["confidence"] = "HIGH"

        return result

    # --------------------------------------------------------
    # REVERSE DNS
    # --------------------------------------------------------

    reverse_dns = _reverse_dns(raw_ip)

    result["reverse_dns"] = reverse_dns

    if reverse_dns.get("status") == "FOUND":

        hostname = reverse_dns.get("hostname")

        result["infrastructure"] = _infrastructure_indicator(
            hostname
        )

        result["findings"].append(
            f"Reverse DNS hostname identified: {hostname}"
        )

    else:

        result["findings"].append(
            "No reverse DNS hostname identified."
        )

    # --------------------------------------------------------
    # ABUSEIPDB
    # --------------------------------------------------------

    abuse_data = _abuseipdb_lookup(raw_ip)

    result["reputation"] = abuse_data

    if abuse_data.get("reputation") == "MALICIOUS":

        result["findings"].append(
            "IP has a high abuse confidence score."
        )

    elif abuse_data.get("reputation") == "SUSPICIOUS":

        result["findings"].append(
            "IP has reported abuse activity."
        )

    elif abuse_data.get("status") == "UNAVAILABLE":

        result["findings"].append(
            "Live IP reputation unavailable."
        )

    # --------------------------------------------------------
    # CONFIDENCE
    # --------------------------------------------------------

    if abuse_data.get("status") == "FOUND":
        result["confidence"] = "HIGH"

    elif reverse_dns.get("status") == "FOUND":
        result["confidence"] = "MEDIUM"

    else:
        result["confidence"] = "LOW"

    return result


# ============================================================
# MAIN ENGINE
# ============================================================

def analyze_ips(ip_addresses):

    if not ip_addresses:
        return {
            "status": "NO_IPS",
            "total": 0,
            "public_count": 0,
            "private_count": 0,
            "documentation_count": 0,
            "suspicious_count": 0,
            "results": [],
            "findings": [
                "No IP addresses were extracted from the email."
            ],
            "engine": {
                "name": "TARVEX26 IP Intelligence Engine",
                "version": "1.0",
                "reputation_source": (
                    "AbuseIPDB"
                    if ABUSEIPDB_API_KEY
                    else "Not configured"
                ),
            },
        }

    # Remove duplicates while preserving order
    unique_ips = []

    for ip in ip_addresses:

        ip = str(ip).strip()

        if ip and ip not in unique_ips:
            unique_ips.append(ip)

    results = []

    for ip in unique_ips:

        results.append(
            _analyze_single_ip(ip)
        )

    public_count = sum(
        1 for item in results
        if item["is_public"]
    )

    private_count = sum(
        1 for item in results
        if item["is_private"]
    )

    documentation_count = sum(
        1 for item in results
        if item["is_documentation"]
    )

    suspicious_count = sum(
        1
        for item in results
        if item.get("reputation", {}).get("reputation")
        in {"MALICIOUS", "SUSPICIOUS"}
    )

    findings = []

    for item in results:

        for finding in item.get("findings", []):

            findings.append(
                f"{item['ip']}: {finding}"
            )

    return {
        "status": "ANALYZED",
        "total": len(results),
        "public_count": public_count,
        "private_count": private_count,
        "documentation_count": documentation_count,
        "suspicious_count": suspicious_count,
        "results": results,
        "findings": list(dict.fromkeys(findings)),
        "engine": {
            "name": "TARVEX26 IP Intelligence Engine",
            "version": "1.0",
            "capabilities": [
                "IPv4/IPv6 validation",
                "Public/private classification",
                "Reserved address detection",
                "Documentation/test network detection",
                "Reverse DNS analysis",
                "Infrastructure heuristics",
                "Optional live reputation lookup",
            ],
            "reputation_source": (
                "AbuseIPDB"
                if ABUSEIPDB_API_KEY
                else "Not configured"
            ),
            "note": (
                "Reputation is marked UNKNOWN/UNAVAILABLE when "
                "a live reputation source is not configured."
            ),
        },
    }