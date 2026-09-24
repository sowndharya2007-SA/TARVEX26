"""
TARVEX26
GeoIP Intelligence Engine v3.0

SIH26106
AI-Powered Email Threat Detection, GeoLocation
and Forensic Intelligence Platform
"""

import ipaddress
import socket
from datetime import datetime, timezone

import requests


# ============================================================
# CONFIGURATION
# ============================================================

PROVIDER_NAME = "ipwho.is"
PROVIDER_VERSION = "3.0"

REQUEST_TIMEOUT = 6


# ============================================================
# TIME
# ============================================================

def utc_now():
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# SAFE HELPERS
# ============================================================

def value_or(value, fallback="Unavailable"):
    if value is None:
        return fallback

    if isinstance(value, str) and not value.strip():
        return fallback

    return value


def unique(items):
    result = []

    for item in items:
        if item and item not in result:
            result.append(item)

    return result


# ============================================================
# IP VALIDATION
# ============================================================

def parse_ip(value):
    """
    Strictly validate an IPv4/IPv6 address.

    Prevents timestamps such as:
        09:29:40

    from being treated as IP addresses.
    """

    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    # Remove common surrounding characters
    value = value.strip("[]()<>\"'")

    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


# ============================================================
# 6TO4 ANALYSIS
# ============================================================

def analyze_6to4(ip_obj):
    """
    Detect IPv6 6to4 addresses.

    6to4 format:
        2002:WWXX:YYZZ::/48

    The first 32 bits after 2002 represent an embedded IPv4 address.
    """

    if ip_obj.version != 6:
        return None

    if not ip_obj.exploded.startswith("2002:"):
        return None

    packed = ip_obj.packed

    embedded_ipv4 = ".".join(
        str(byte)
        for byte in packed[2:6]
    )

    try:
        embedded = ipaddress.ip_address(embedded_ipv4)
    except ValueError:
        return {
            "detected": True,
            "embedded_ipv4": embedded_ipv4,
            "embedded_public": False,
            "embedded_private": False,
        }

    return {
        "detected": True,
        "embedded_ipv4": embedded_ipv4,
        "embedded_public": embedded.is_global,
        "embedded_private": embedded.is_private,
    }


# ============================================================
# ADDRESS CLASSIFICATION
# ============================================================

def classify_ip(ip_obj):
    """
    Return a forensic classification for the address.
    """

    six_to_four = analyze_6to4(ip_obj)

    # --------------------------------------------------------
    # 6to4 IPv6
    # --------------------------------------------------------

    if six_to_four:

        embedded = six_to_four["embedded_ipv4"]

        if six_to_four["embedded_private"]:

            return {
                "type": "6to4 / Non-Routable Derived",
                "status": "NON_ROUTABLE",
                "confidence": "HIGH",
                "classification": "6TO4_PRIVATE",
                "six_to_four": six_to_four,
                "findings": [
                    "6to4 IPv6 address detected.",
                    f"Embedded IPv4 address: {embedded}.",
                    "Embedded IPv4 address is private/non-routable.",
                    "Public geolocation is not applicable.",
                    "No geographic attribution was made."
                ]
            }

        if six_to_four["embedded_public"]:

            return {
                "type": "6to4 / Derived IPv6",
                "status": "DERIVED_PUBLIC",
                "confidence": "MEDIUM",
                "classification": "6TO4_PUBLIC",
                "six_to_four": six_to_four,
                "findings": [
                    "6to4 IPv6 address detected.",
                    f"Embedded IPv4 address: {embedded}.",
                    "Geolocation may be evaluated using the embedded public IPv4."
                ]
            }

    # --------------------------------------------------------
    # Private
    # --------------------------------------------------------

    if ip_obj.is_private:

        return {
            "type": "Private / Non-Routable",
            "status": "NON_ROUTABLE",
            "confidence": "HIGH",
            "classification": "PRIVATE",
            "six_to_four": None,
            "findings": [
                "Private IP address detected.",
                "Public Internet geolocation is not applicable.",
                "No geographic attribution was made."
            ]
        }

    # --------------------------------------------------------
    # Loopback
    # --------------------------------------------------------

    if ip_obj.is_loopback:

        return {
            "type": "Loopback",
            "status": "NON_ROUTABLE",
            "confidence": "HIGH",
            "classification": "LOOPBACK",
            "six_to_four": None,
            "findings": [
                "Loopback address detected.",
                "The address does not identify a public Internet host."
            ]
        }

    # --------------------------------------------------------
    # Link Local
    # --------------------------------------------------------

    if ip_obj.is_link_local:

        return {
            "type": "Link-Local",
            "status": "NON_ROUTABLE",
            "confidence": "HIGH",
            "classification": "LINK_LOCAL",
            "six_to_four": None,
            "findings": [
                "Link-local address detected.",
                "Public Internet geolocation is not applicable."
            ]
        }

    # --------------------------------------------------------
    # Multicast
    # --------------------------------------------------------

    if ip_obj.is_multicast:

        return {
            "type": "Multicast",
            "status": "NON_ROUTABLE",
            "confidence": "HIGH",
            "classification": "MULTICAST",
            "six_to_four": None,
            "findings": [
                "Multicast address detected.",
                "The address does not identify a single public Internet host."
            ]
        }

    # --------------------------------------------------------
    # Reserved
    # --------------------------------------------------------

    if ip_obj.is_reserved:

        return {
            "type": "Reserved",
            "status": "NON_ROUTABLE",
            "confidence": "HIGH",
            "classification": "RESERVED",
            "six_to_four": None,
            "findings": [
                "Reserved IP address detected.",
                "Public geographic attribution is not applicable."
            ]
        }

    # --------------------------------------------------------
    # Global
    # --------------------------------------------------------

    if ip_obj.is_global:

        return {
            "type": "Public",
            "status": "FOUND",
            "confidence": "MEDIUM",
            "classification": "PUBLIC",
            "six_to_four": None,
            "findings": [
                "Globally routable public IP address detected."
            ]
        }

    # --------------------------------------------------------
    # Unknown
    # --------------------------------------------------------

    return {
        "type": "Special / Non-Global",
        "status": "NON_ROUTABLE",
        "confidence": "HIGH",
        "classification": "SPECIAL",
        "six_to_four": None,
        "findings": [
            "IP address is not globally routable.",
            "Public geolocation is not applicable."
        ]
    }


# ============================================================
# REVERSE DNS
# ============================================================

def reverse_dns(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)

        if hostname:
            return hostname

    except Exception:
        pass

    return None


# ============================================================
# IPWHO LOOKUP
# ============================================================

def lookup_ipwho(ip):
    """
    Query ipwho.is for public/global IPs.
    """

    url = f"https://ipwho.is/{ip}"

    try:

        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={
                "User-Agent": "TARVEX26-GeoIP/3.0"
            }
        )

        if response.status_code != 200:
            return {
                "success": False,
                "error": f"Provider HTTP {response.status_code}"
            }

        data = response.json()

        if not data.get("success", False):
            return {
                "success": False,
                "error": data.get(
                    "message",
                    "GeoIP provider did not return a successful result."
                )
            }

        return data

    except requests.RequestException as error:

        return {
            "success": False,
            "error": f"GeoIP provider unavailable: {str(error)}"
        }

    except Exception as error:

        return {
            "success": False,
            "error": f"GeoIP lookup error: {str(error)}"
        }


# ============================================================
# NORMALIZE PROVIDER RESULT
# ============================================================

def normalize_provider_result(
    ip,
    data,
    classification,
    reverse_dns_value=None
):

    connection = data.get("connection") or {}
    security = data.get("security") or {}
    timezone = data.get("timezone") or {}

    provider_reverse = (
        connection.get("domain")
        or data.get("reverse")
        or reverse_dns_value
    )

    findings = list(
        classification.get("findings", [])
    )

    # --------------------------------------------------------
    # Security indicators
    # --------------------------------------------------------

    vpn = bool(security.get("vpn"))
    proxy = bool(security.get("proxy"))
    tor = bool(security.get("tor"))
    hosting = bool(security.get("hosting"))

    if vpn:
        findings.append(
            "VPN indicator reported by GeoIP security intelligence."
        )

    if proxy:
        findings.append(
            "Proxy indicator reported by GeoIP security intelligence."
        )

    if tor:
        findings.append(
            "Tor indicator reported by GeoIP security intelligence."
        )

    if hosting:
        findings.append(
            "Hosting infrastructure indicator reported."
        )

    # --------------------------------------------------------
    # Reputation
    # --------------------------------------------------------

    threat = security.get("threat")

    if threat is True:
        reputation = "THREAT INDICATED"

    elif threat is False:
        reputation = "NO THREAT INDICATED"

    else:
        reputation = "UNKNOWN"

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    confidence = classification.get(
        "confidence",
        "MEDIUM"
    )

    if (
        data.get("country")
        and data.get("city")
        and connection.get("asn")
    ):
        confidence = "HIGH"

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    return {
        "ip": ip,
        "ip_version": f"IPv{ipaddress.ip_address(ip).version}",

        "type": "Public",

        "status": "FOUND",

        "confidence": confidence,

        "country": value_or(
            data.get("country")
        ),

        "country_code": value_or(
            data.get("country_code"),
            "N/A"
        ),

        "region": value_or(
            data.get("region")
        ),

        "city": value_or(
            data.get("city")
        ),

        "postal": value_or(
            data.get("postal")
        ),

        "latitude": data.get("latitude"),

        "longitude": data.get("longitude"),

        "timezone": value_or(
            timezone.get("id")
        ),

        "organization": value_or(
            connection.get("org")
        ),

        "isp": value_or(
            connection.get("isp")
        ),

        "asn": value_or(
            connection.get("asn"),
            "N/A"
        ),

        "reverse_dns": value_or(
            provider_reverse
        ),

        "domain": value_or(
            connection.get("domain")
        ),

        "reputation": reputation,

        "security": {
            "vpn": vpn,
            "proxy": proxy,
            "tor": tor,
            "hosting": hosting,
            "threat": threat
        },

        "findings": unique(findings),

        "analyzed_at": utc_now(),

        "provider": PROVIDER_NAME
    }


# ============================================================
# NON-ROUTABLE RESULT
# ============================================================

def build_non_routable_result(
    ip,
    classification
):

    six_to_four = classification.get(
        "six_to_four"
    )

    findings = list(
        classification.get("findings", [])
    )

    if six_to_four:

        embedded = six_to_four.get(
            "embedded_ipv4"
        )

        embedded_private = six_to_four.get(
            "embedded_private",
            False
        )

        if embedded_private:

            result_type = "6to4 / Non-Routable Derived"

        else:

            result_type = "6to4 / Derived IPv6"

    else:

        result_type = classification.get(
            "type",
            "Non-Routable"
        )

    return {

        "ip": ip,

        "ip_version": f"IPv{ipaddress.ip_address(ip).version}",

        "type": result_type,

        "status": classification.get(
            "status",
            "NON_ROUTABLE"
        ),

        "confidence": classification.get(
            "confidence",
            "HIGH"
        ),

        "country": "Not applicable",

        "country_code": "N/A",

        "region": "Not applicable",

        "city": "Not applicable",

        "postal": "N/A",

        "latitude": None,

        "longitude": None,

        "timezone": "N/A",

        "organization": "Not applicable",

        "isp": "Not applicable",

        "asn": "N/A",

        "reverse_dns": "N/A",

        "domain": "N/A",

        "reputation": "NOT_APPLICABLE",

        "security": {
            "vpn": False,
            "proxy": False,
            "tor": False,
            "hosting": False,
            "threat": None
        },

        "findings": unique(findings),

        "analyzed_at": utc_now(),

        "provider": PROVIDER_NAME
    }


# ============================================================
# MAIN ANALYZER
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
                "No IP addresses were supplied."
            ],
            "engine": {
                "name": "TARVEX26 GeoIP Intelligence Engine",
                "version": PROVIDER_VERSION,
                "provider": PROVIDER_NAME,
                "capabilities": [
                    "IPv4 geolocation",
                    "IPv6 geolocation",
                    "Country identification",
                    "Region identification",
                    "City identification",
                    "Latitude/longitude",
                    "ISP identification",
                    "Organization identification",
                    "ASN identification",
                    "Timezone identification",
                    "Reverse DNS",
                    "6to4 detection",
                    "Private IP detection",
                    "Documentation IP detection",
                    "VPN indicator detection",
                    "Proxy indicator detection",
                    "Tor indicator detection",
                    "Hosting indicator detection",
                    "False attribution prevention"
                ],
                "note": (
                    "Non-routable, private, reserved and "
                    "documentation addresses are not assigned "
                    "real-world geographic locations."
                )
            }
        }

    # --------------------------------------------------------
    # Strict validation
    # --------------------------------------------------------

    valid_ips = []

    rejected = []

    for value in ip_addresses:

        ip_obj = parse_ip(value)

        if ip_obj is None:

            rejected.append(
                str(value)
            )

            continue

        normalized = str(ip_obj)

        if normalized not in valid_ips:

            valid_ips.append(normalized)

    results = []

    findings = []

    public_count = 0
    private_count = 0
    documentation_count = 0
    suspicious_count = 0

    # --------------------------------------------------------
    # Analyze every valid IP
    # --------------------------------------------------------

    for ip in valid_ips:

        ip_obj = ipaddress.ip_address(ip)

        classification = classify_ip(
            ip_obj
        )

        # ----------------------------------------------------
        # Documentation/test addresses
        # ----------------------------------------------------

        if (
            ip_obj.is_private
            and (
                ip_obj.is_reserved
                or ip.startswith("192.0.2.")
                or ip.startswith("198.51.100.")
                or ip.startswith("203.0.113.")
            )
        ):

            documentation_count += 1

            result = build_non_routable_result(
                ip,
                {
                    **classification,
                    "type": "Documentation / Test",
                    "status": "DOCUMENTATION",
                    "confidence": "HIGH",
                    "findings": [
                        "Documentation/test IP detected.",
                        "Real-world geographic attribution is not applicable.",
                        "This address should not be used to infer an attacker's location."
                    ]
                }
            )

            result["organization"] = "Documentation Network"
            result["isp"] = "Documentation Network"
            result["reputation"] = "TEST_ADDRESS"

            results.append(result)

            findings.extend(
                result["findings"]
            )

            continue

        # ----------------------------------------------------
        # Non-routable addresses
        # ----------------------------------------------------

        if classification["status"] == "NON_ROUTABLE":

            private_count += 1

            result = build_non_routable_result(
                ip,
                classification
            )

            results.append(result)

            findings.extend(
                result["findings"]
            )

            continue

        # ----------------------------------------------------
        # Public IP
        # ----------------------------------------------------

        public_count += 1

        lookup_ip = ip

        six_to_four = classification.get(
            "six_to_four"
        )

        # For public 6to4, use embedded IPv4
        # as an additional lookup source.
        if (
            six_to_four
            and six_to_four.get("embedded_public")
        ):

            lookup_ip = six_to_four[
                "embedded_ipv4"
            ]

        reverse = reverse_dns(
            lookup_ip
        )

        data = lookup_ipwho(
            lookup_ip
        )

        if data.get("success"):

            result = normalize_provider_result(
                ip=ip,
                data=data,
                classification=classification,
                reverse_dns_value=reverse
            )

            # Preserve original IPv6 classification
            if six_to_four:

                result["type"] = (
                    "6to4 / Derived IPv6"
                )

                result["findings"] = unique(
                    result.get("findings", [])
                    + [
                        "GeoIP information was obtained using the embedded public IPv4."
                    ]
                )

                result["derived_ipv4"] = lookup_ip

        else:

            result = {
                "ip": ip,

                "ip_version":
                    f"IPv{ip_obj.version}",

                "type":
                    classification.get(
                        "type",
                        "Public"
                    ),

                "status":
                    "GEOIP_UNAVAILABLE",

                "confidence":
                    "LOW",

                "country":
                    "Unavailable",

                "country_code":
                    "N/A",

                "region":
                    "Unavailable",

                "city":
                    "Unavailable",

                "postal":
                    "Unavailable",

                "latitude":
                    None,

                "longitude":
                    None,

                "timezone":
                    "Unavailable",

                "organization":
                    "Unavailable",

                "isp":
                    "Unavailable",

                "asn":
                    "Unavailable",

                "reverse_dns":
                    reverse or "Unavailable",

                "domain":
                    "Unavailable",

                "reputation":
                    "UNKNOWN",

                "security": {
                    "vpn": False,
                    "proxy": False,
                    "tor": False,
                    "hosting": False,
                    "threat": None
                },

                "findings": [
                    "Public IP detected.",
                    "GeoIP provider did not return location data.",
                    f"Provider message: {data.get('error', 'Unknown error')}."
                ],

                "analyzed_at":
                    utc_now(),

                "provider":
                    PROVIDER_NAME
            }

        results.append(result)

        findings.extend(
            result.get(
                "findings",
                []
            )
        )

        security = result.get(
            "security",
            {}
        )

        if (
            security.get("threat")
            or security.get("tor")
            or security.get("proxy")
            or security.get("vpn")
        ):

            suspicious_count += 1

    # --------------------------------------------------------
    # Invalid inputs
    # --------------------------------------------------------

    for rejected_ip in rejected:

        findings.append(
            f"Rejected invalid IP candidate: {rejected_ip}"
        )

    # --------------------------------------------------------
    # Final response
    # --------------------------------------------------------

    return {

        "status": "ANALYZED",

        "total": len(results),

        "public_count": public_count,

        "private_count": private_count,

        "documentation_count":
            documentation_count,

        "suspicious_count":
            suspicious_count,

        "results": results,

        "findings":
            unique(findings),

        "engine": {

            "name":
                "TARVEX26 GeoIP Intelligence Engine",

            "version":
                PROVIDER_VERSION,

            "provider":
                PROVIDER_NAME,

            "capabilities": [

                "IPv4 geolocation",

                "IPv6 geolocation",

                "Country identification",

                "Region identification",

                "City identification",

                "Latitude/longitude",

                "ISP identification",

                "Organization identification",

                "ASN identification",

                "Timezone identification",

                "Reverse DNS",

                "6to4 detection",

                "Private IP detection",

                "Documentation IP detection",

                "VPN indicator detection",

                "Proxy indicator detection",

                "Tor indicator detection",

                "Hosting indicator detection",

                "False attribution prevention"

            ],

            "note": (
                "TARVEX26 does not assign geographic "
                "locations to private, reserved, "
                "documentation or non-routable addresses."
            )
        },

        "analyzed_at":
            utc_now()
    }