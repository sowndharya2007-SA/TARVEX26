"""
TARVEX26
Origin Intelligence & Email Trace Analysis
SIH26106 - Email Threat Detection and Forensic Intelligence

Purpose:
- Identify public and non-routable IPs
- Geolocate public IPs
- Identify earliest usable origin candidate
- Collect ISP / organization / ASN
- Resolve reverse DNS
- Detect hosting/cloud indicators
- Calculate origin confidence
- Produce forensic findings
"""

import json
import urllib.request
import urllib.error
import ipaddress
import socket


GEOLOCATION_API = "https://ipwho.is/{}"


HOSTING_KEYWORDS = [
    "amazon",
    "aws",
    "google cloud",
    "microsoft",
    "azure",
    "cloudflare",
    "digitalocean",
    "oracle cloud",
    "ovh",
    "linode",
    "vultr",
    "akamai",
]


def is_public_ip(ip):
    """
    Check whether an IP address is globally routable.
    """

    try:

        address = ipaddress.ip_address(
            str(ip).strip()
        )

        return address.is_global

    except ValueError:

        return False


def classify_ip(ip):
    """
    Classify an IP address for forensic origin analysis.
    """

    try:

        address = ipaddress.ip_address(
            str(ip).strip()
        )

    except ValueError:

        return "Invalid IP"

    if address.is_loopback:
        return "Loopback IP"

    if address.is_private:
        return "Private IP"

    if address.is_link_local:
        return "Link-Local IP"

    if address.is_reserved:
        return "Reserved IP"

    if address.is_multicast:
        return "Multicast IP"

    if address.is_global:
        return "Public IP"

    return "Special-use IP"


def reverse_dns(ip):
    """
    Resolve PTR / reverse DNS information.
    """

    try:

        hostname = socket.gethostbyaddr(
            ip
        )[0]

        return hostname

    except Exception:

        return None


def detect_hosting(
    organization,
    isp,
    hostname
):
    """
    Detect possible cloud or hosting infrastructure.

    This is an infrastructure indicator,
    not a maliciousness verdict.
    """

    combined = " ".join(
        [
            str(organization or ""),
            str(isp or ""),
            str(hostname or "")
        ]
    ).lower()

    matches = []

    for keyword in HOSTING_KEYWORDS:

        if keyword in combined:

            matches.append(
                keyword
            )

    matches = list(
        dict.fromkeys(matches)
    )

    return {
        "detected": len(matches) > 0,
        "providers": matches
    }


def geolocate_ip(ip):
    """
    Retrieve geolocation and network intelligence
    for a public IP.
    """

    ip = str(ip).strip()

    ip_type = classify_ip(ip)

    if not is_public_ip(ip):

        return {
            "ip": ip,
            "status": "unavailable",
            "ip_type": ip_type,
            "reason": "Private or non-routable IP address",
            "confidence": 100,
            "findings": [
                f"{ip_type} cannot provide public internet geolocation"
            ]
        }

    try:

        url = GEOLOCATION_API.format(
            ip
        )

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent":
                    "TARVEX26-Email-Forensics/2.0"
            }
        )

        with urllib.request.urlopen(
            request,
            timeout=5
        ) as response:

            data = json.loads(
                response.read().decode(
                    "utf-8"
                )
            )

        if not data.get(
            "success",
            False
        ):

            return {
                "ip": ip,
                "status": "unavailable",
                "ip_type": ip_type,
                "reason": data.get(
                    "message",
                    "Geolocation lookup failed"
                ),
                "confidence": 0,
                "findings": [
                    "Geolocation lookup failed"
                ]
            }

        connection = data.get(
            "connection",
            {}
        )

        timezone_data = data.get(
            "timezone",
            {}
        )

        organization = connection.get(
            "org"
        )

        isp = connection.get(
            "isp"
        )

        asn = connection.get(
            "asn"
        )

        hostname = reverse_dns(
            ip
        )

        hosting = detect_hosting(
            organization,
            isp,
            hostname
        )

        findings = []

        if hostname:

            findings.append(
                f"Reverse DNS resolved: {hostname}"
            )

        if hosting["detected"]:

            providers = ", ".join(
                hosting["providers"]
            )

            findings.append(
                f"Possible hosting/cloud infrastructure: {providers}"
            )

        confidence = 70

        if data.get("country"):
            confidence += 5

        if data.get("city"):
            confidence += 5

        if isp:
            confidence += 5

        if asn:
            confidence += 5

        confidence = min(
            confidence,
            100
        )

        return {
            "ip": ip,
            "status": "success",
            "ip_type": ip_type,

            "country": data.get(
                "country"
            ),

            "country_code": data.get(
                "country_code"
            ),

            "region": data.get(
                "region"
            ),

            "city": data.get(
                "city"
            ),

            "latitude": data.get(
                "latitude"
            ),

            "longitude": data.get(
                "longitude"
            ),

            "timezone": timezone_data.get(
                "id"
            ) if isinstance(
                timezone_data,
                dict
            ) else None,

            "isp": isp,

            "organization": organization,

            "asn": asn,

            "hostname": hostname,

            "hosting": hosting,

            "confidence": confidence,

            "findings": findings
        }

    except urllib.error.URLError:

        return {
            "ip": ip,
            "status": "unavailable",
            "ip_type": ip_type,
            "reason": "Geolocation service unreachable",
            "confidence": 0,
            "findings": [
                "Geolocation service unavailable"
            ]
        }

    except Exception as error:

        return {
            "ip": ip,
            "status": "unavailable",
            "ip_type": ip_type,
            "reason": str(error),
            "confidence": 0,
            "findings": [
                "Unexpected geolocation error"
            ]
        }


def determine_origin(results):
    """
    Select the first usable public IP as the
    origin candidate.

    This is a candidate origin, not absolute attribution.
    """

    for result in results:

        if result.get(
            "status"
        ) == "success":

            return {
                "ip": result.get("ip"),
                "country": result.get("country"),
                "country_code": result.get(
                    "country_code"
                ),
                "region": result.get(
                    "region"
                ),
                "city": result.get(
                    "city"
                ),
                "isp": result.get(
                    "isp"
                ),
                "organization": result.get(
                    "organization"
                ),
                "asn": result.get(
                    "asn"
                ),
                "hostname": result.get(
                    "hostname"
                ),
                "latitude": result.get(
                    "latitude"
                ),
                "longitude": result.get(
                    "longitude"
                ),
                "confidence": result.get(
                    "confidence",
                    0
                ),
                "assessment": (
                    "CANDIDATE_ORIGIN"
                )
            }

    return {
        "ip": None,
        "country": None,
        "country_code": None,
        "region": None,
        "city": None,
        "isp": None,
        "organization": None,
        "asn": None,
        "hostname": None,
        "latitude": None,
        "longitude": None,
        "confidence": 0,
        "assessment": "UNKNOWN"
    }


def analyze_origin(ip_addresses):
    """
    Complete origin analysis for extracted
    email IP addresses.
    """

    unique_ips = []

    for ip in ip_addresses:

        ip = str(ip).strip()

        if ip and ip not in unique_ips:

            unique_ips.append(
                ip
            )

    results = []

    for ip in unique_ips:

        results.append(
            geolocate_ip(ip)
        )

    public_results = [
        result
        for result in results
        if result.get(
            "status"
        ) == "success"
    ]

    origin = determine_origin(
        results
    )

    findings = []

    if origin["ip"]:

        findings.append(
            "A public IP was identified as a candidate origin."
        )

        findings.append(
            f"Candidate origin IP: {origin['ip']}"
        )

        if origin["country"]:

            findings.append(
                f"Geographic location: "
                f"{origin['city']}, "
                f"{origin['region']}, "
                f"{origin['country']}"
            )

    else:

        findings.append(
            "No reliable public origin IP was identified."
        )

    hosting_count = sum(
        1
        for result in public_results
        if result.get(
            "hosting",
            {}
        ).get(
            "detected",
            False
        )
    )

    if hosting_count:

        findings.append(
            f"{hosting_count} public IP(s) show "
            "possible hosting/cloud infrastructure indicators."
        )

    return {
        "total_ips": len(
            unique_ips
        ),

        "public_ip_count": len(
            public_results
        ),

        "public_ips": public_results,

        "results": results,

        "origin": origin,

        "findings": list(
            dict.fromkeys(
                findings
            )
        ),

        "engine": {
            "name":
                "TARVEX26 Origin Intelligence Engine",

            "version":
                "2.0",

            "capabilities": [
                "Public IP identification",
                "IP classification",
                "Geolocation",
                "Country identification",
                "Region identification",
                "City identification",
                "ISP identification",
                "Organization identification",
                "ASN identification",
                "Reverse DNS",
                "Hosting/cloud detection",
                "Candidate origin assessment",
                "Origin confidence scoring"
            ]
        }
    }