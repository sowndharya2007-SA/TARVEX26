"""
TARVEX26
IP Intelligence & Origin Analysis Engine
SIH26106 - Email Threat Detection and Forensic Intelligence

Capabilities:
- IPv4 / IPv6 validation
- Public / private / reserved classification
- Reverse DNS / PTR lookup
- IP geolocation
- Country / region / city
- ISP / organization
- ASN
- Latitude / longitude
- Hosting / cloud indicators
- Optional AbuseIPDB reputation lookup
- Confidence and forensic findings
"""

import ipaddress
import os
import socket
import requests


IP_GEOLOCATION_API = "https://ipwho.is/{}"
ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"


CLOUD_KEYWORDS = [
    "amazon",
    "aws",
    "google cloud",
    "microsoft",
    "azure",
    "digitalocean",
    "oracle cloud",
    "cloudflare",
    "ovh",
    "linode",
    "vultr",
    "akamai",
]


def reverse_dns(ip):
    """
    Perform reverse DNS / PTR lookup.
    """

    try:
        hostname = socket.gethostbyaddr(ip)[0]

        return hostname

    except Exception:
        return None


def get_geolocation(ip):
    """
    Retrieve public IP geolocation and network information.
    Uses ipwho.is.
    """

    try:
        response = requests.get(
            IP_GEOLOCATION_API.format(ip),
            timeout=5
        )

        if response.status_code != 200:
            return {}

        data = response.json()

        if not data.get("success", False):
            return {}

        connection = data.get("connection", {})

        return {
            "country": data.get("country"),
            "country_code": data.get("country_code"),
            "region": data.get("region"),
            "city": data.get("city"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "timezone": data.get("timezone", {}).get("id")
            if isinstance(data.get("timezone"), dict)
            else None,
            "isp": connection.get("isp"),
            "organization": connection.get("org"),
            "asn": connection.get("asn"),
            "domain": connection.get("domain"),
        }

    except Exception:
        return {}


def check_abuseipdb(ip):
    """
    Optional AbuseIPDB reputation lookup.

    Requires:

        ABUSEIPDB_API_KEY

    environment variable.

    If no API key is configured, the result remains UNKNOWN.
    """

    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        return {
            "status": "UNKNOWN",
            "available": False,
            "message": "AbuseIPDB API key not configured"
        }

    try:
        response = requests.get(
            ABUSEIPDB_API,
            headers={
                "Key": api_key,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90
            },
            timeout=5
        )

        if response.status_code != 200:
            return {
                "status": "UNAVAILABLE",
                "available": False,
                "message": f"AbuseIPDB HTTP {response.status_code}"
            }

        data = response.json().get("data", {})

        abuse_score = data.get("abuseConfidenceScore", 0)

        if abuse_score >= 75:
            status = "MALICIOUS"

        elif abuse_score >= 25:
            status = "SUSPICIOUS"

        else:
            status = "CLEAN"

        return {
            "status": status,
            "available": True,
            "abuse_confidence_score": abuse_score,
            "total_reports": data.get("totalReports", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain")
        }

    except Exception as error:

        return {
            "status": "UNAVAILABLE",
            "available": False,
            "message": str(error)
        }


def detect_cloud_or_hosting(organization, isp, hostname):
    """
    Detect possible cloud / hosting infrastructure using
    organization, ISP and hostname keywords.

    This is an indicator, NOT proof of malicious activity.
    """

    combined = " ".join([
        str(organization or ""),
        str(isp or ""),
        str(hostname or "")
    ]).lower()

    matches = [
        keyword
        for keyword in CLOUD_KEYWORDS
        if keyword in combined
    ]

    return {
        "detected": len(matches) > 0,
        "providers": list(dict.fromkeys(matches))
    }


def analyze_ip(ip):
    """
    Perform complete intelligence analysis on one IP address.
    """

    original_ip = str(ip).strip()

    try:
        ip_obj = ipaddress.ip_address(original_ip)

    except ValueError:

        return {
            "ip": original_ip,
            "version": None,
            "type": "Invalid IP",
            "is_global": False,
            "is_private": False,
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "organization": "Unknown",
            "isp": "Unknown",
            "asn": "Unknown",
            "hostname": None,
            "latitude": None,
            "longitude": None,
            "reputation": {
                "status": "UNKNOWN"
            },
            "hosting": {
                "detected": False,
                "providers": []
            },
            "confidence": 0,
            "findings": [
                "Invalid IP address"
            ]
        }

    # ---------------------------------------
    # IP CLASSIFICATION
    # ---------------------------------------

    if ip_obj.is_loopback:

        ip_type = "Loopback IP"

    elif ip_obj.is_private:

        ip_type = "Private IP"

    elif ip_obj.is_reserved:

        ip_type = "Reserved IP"

    elif ip_obj.is_multicast:

        ip_type = "Multicast IP"

    elif ip_obj.is_global:

        ip_type = "Public IP"

    else:

        ip_type = "Special-use IP"


    result = {
        "ip": original_ip,
        "version": ip_obj.version,
        "type": ip_type,
        "is_global": ip_obj.is_global,
        "is_private": ip_obj.is_private,

        "country": "Unknown",
        "country_code": None,
        "region": "Unknown",
        "city": "Unknown",

        "organization": "Unknown",
        "isp": "Unknown",
        "asn": "Unknown",

        "hostname": None,

        "latitude": None,
        "longitude": None,

        "timezone": None,

        "reputation": {
            "status": "UNKNOWN",
            "available": False
        },

        "hosting": {
            "detected": False,
            "providers": []
        },

        "confidence": 50,

        "findings": []
    }


    # ---------------------------------------
    # PRIVATE / SPECIAL IP
    # ---------------------------------------

    if not ip_obj.is_global:

        result["confidence"] = 100

        if ip_obj.is_private:

            result["findings"].append(
                "Private IP address detected"
            )

        elif ip_obj.is_loopback:

            result["findings"].append(
                "Loopback IP address detected"
            )

        elif ip_obj.is_reserved:

            result["findings"].append(
                "Reserved IP address detected"
            )

        elif ip_obj.is_multicast:

            result["findings"].append(
                "Multicast IP address detected"
            )

        return result


    # ---------------------------------------
    # REVERSE DNS
    # ---------------------------------------

    hostname = reverse_dns(original_ip)

    result["hostname"] = hostname


    if hostname:

        result["findings"].append(
            f"Reverse DNS hostname resolved: {hostname}"
        )


    # ---------------------------------------
    # GEOLOCATION
    # ---------------------------------------

    geo = get_geolocation(original_ip)


    if geo:

        result["country"] = geo.get(
            "country"
        ) or "Unknown"

        result["country_code"] = geo.get(
            "country_code"
        )

        result["region"] = geo.get(
            "region"
        ) or "Unknown"

        result["city"] = geo.get(
            "city"
        ) or "Unknown"

        result["latitude"] = geo.get(
            "latitude"
        )

        result["longitude"] = geo.get(
            "longitude"
        )

        result["timezone"] = geo.get(
            "timezone"
        )

        result["organization"] = geo.get(
            "organization"
        ) or "Unknown"

        result["isp"] = geo.get(
            "isp"
        ) or "Unknown"

        result["asn"] = geo.get(
            "asn"
        ) or "Unknown"

        result["confidence"] += 20

    else:

        result["findings"].append(
            "Geolocation information unavailable"
        )


    # ---------------------------------------
    # CLOUD / HOSTING DETECTION
    # ---------------------------------------

    hosting = detect_cloud_or_hosting(
        result["organization"],
        result["isp"],
        result["hostname"]
    )

    result["hosting"] = hosting


    if hosting["detected"]:

        providers = ", ".join(
            hosting["providers"]
        )

        result["findings"].append(
            f"Possible cloud/hosting infrastructure: {providers}"
        )


    # ---------------------------------------
    # ABUSEIPDB REPUTATION
    # ---------------------------------------

    reputation = check_abuseipdb(
        original_ip
    )

    result["reputation"] = reputation


    if reputation.get("status") == "MALICIOUS":

        result["findings"].append(
            "IP has a high malicious reputation score"
        )

        result["confidence"] += 20

    elif reputation.get("status") == "SUSPICIOUS":

        result["findings"].append(
            "IP has suspicious reputation indicators"
        )

        result["confidence"] += 10


    # ---------------------------------------
    # CONFIDENCE LIMIT
    # ---------------------------------------

    result["confidence"] = min(
        result["confidence"],
        100
    )


    return result


def analyze_ips(ip_addresses):
    """
    Analyze multiple IP addresses extracted
    from the email headers.
    """

    results = []

    seen = set()

    for ip in ip_addresses:

        ip = str(ip).strip()

        if not ip:
            continue

        if ip in seen:
            continue

        seen.add(ip)

        results.append(
            analyze_ip(ip)
        )


    return {
        "total_ips": len(results),
        "results": results,

        "public_ip_count": sum(
            1
            for item in results
            if item.get("is_global")
        ),

        "private_ip_count": sum(
            1
            for item in results
            if item.get("is_private")
        ),

        "suspicious_ip_count": sum(
            1
            for item in results
            if item.get("reputation", {}).get("status")
            in ["MALICIOUS", "SUSPICIOUS"]
        ),

        "engine": {
            "name": "TARVEX26 IP Intelligence Engine",
            "version": "2.0",
            "capabilities": [
                "IP classification",
                "Reverse DNS",
                "Geolocation",
                "ISP identification",
                "Organization identification",
                "ASN identification",
                "Cloud/hosting detection",
                "IP reputation analysis"
            ]
        }
    }