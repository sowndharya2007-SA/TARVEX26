"""
TARVEX26
GeoIP Intelligence Engine
SIH26106 - Email Threat Detection and Forensic Intelligence

Purpose:
- Geolocate public IP addresses
- Identify country / region / city
- Identify ISP / organization
- Identify ASN
- Identify latitude / longitude
- Identify timezone
- Detect private and documentation/test addresses
- Perform reverse DNS
- Avoid false geographic attribution

External GeoIP provider:
ipwho.is

No API key is required for basic lookups.
"""

import ipaddress
import socket
from datetime import datetime, timezone

import requests


# ============================================================
# CONFIGURATION
# ============================================================

GEOIP_API_URL = "https://ipwho.is/{ip}"

REQUEST_TIMEOUT = 6


# ============================================================
# HELPERS
# ============================================================

def _unique(values):

    result = []
    seen = set()

    for value in values:

        if value is None:
            continue

        value = str(value).strip()

        if not value:
            continue

        if value not in seen:
            seen.add(value)
            result.append(value)

    return result


def _extract_ip_values(ip_input):

    """
    Accepts:

    [
        "8.8.8.8",
        "1.1.1.1"
    ]

    OR

    {
        "ip_addresses": [...]
    }

    OR a single string.
    """

    if ip_input is None:
        return []

    if isinstance(ip_input, dict):

        possible = (
            ip_input.get("ip_addresses")
            or ip_input.get("ips")
            or ip_input.get("results")
            or []
        )

        if isinstance(possible, list):
            return _unique(possible)

        if isinstance(possible, str):
            return [possible]

        return []

    if isinstance(ip_input, (list, tuple, set)):

        return _unique(ip_input)

    if isinstance(ip_input, str):

        return [ip_input.strip()]

    return []


def _classify_ip(ip):

    try:

        address = ipaddress.ip_address(ip)

    except ValueError:

        return {
            "valid": False,
            "type": "INVALID",
            "is_private": False,
            "is_documentation": False,
            "is_public": False,
            "version": "UNKNOWN"
        }

    is_documentation = address.is_private and (
        ip.startswith("192.0.2.")
        or ip.startswith("198.51.100.")
        or ip.startswith("203.0.113.")
    )

    if is_documentation:

        address_type = "DOCUMENTATION"

    elif address.is_loopback:

        address_type = "LOOPBACK"

    elif address.is_link_local:

        address_type = "LINK_LOCAL"

    elif address.is_multicast:

        address_type = "MULTICAST"

    elif address.is_private:

        address_type = "PRIVATE"

    elif address.is_reserved:

        address_type = "RESERVED"

    elif address.is_global:

        address_type = "PUBLIC"

    else:

        address_type = "SPECIAL"

    return {

        "valid": True,

        "type": address_type,

        "is_private": address.is_private,

        "is_documentation": is_documentation,

        "is_public": address.is_global,

        "version": (
            "IPv4"
            if address.version == 4
            else "IPv6"
        )
    }


# ============================================================
# REVERSE DNS
# ============================================================

def _reverse_dns(ip):

    try:

        hostname, aliases, addresses = socket.gethostbyaddr(ip)

        return {

            "status": "FOUND",

            "hostname": hostname,

            "aliases": aliases or [],

            "addresses": addresses or []
        }

    except Exception as error:

        return {

            "status": "NOT_FOUND",

            "hostname": None,

            "aliases": [],

            "addresses": [],

            "error": str(error)
        }


# ============================================================
# GEOIP LOOKUP
# ============================================================

def _lookup_geoip(ip):

    url = GEOIP_API_URL.format(
        ip=ip
    )

    try:

        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={
                "User-Agent":
                    "TARVEX26-SIH26106-Forensics"
            }
        )

        if response.status_code != 200:

            return {

                "status": "UNAVAILABLE",

                "error":
                    f"GeoIP provider returned HTTP {response.status_code}"
            }

        data = response.json()

        if not data.get("success", False):

            return {

                "status": "UNAVAILABLE",

                "error":
                    data.get(
                        "message",
                        "GeoIP lookup failed."
                    )
            }


        connection = data.get(
            "connection"
        ) or {}


        timezone_data = data.get(
            "timezone"
        ) or {}


        return {

            "status": "FOUND",

            "country":
                data.get(
                    "country"
                ) or "Unavailable",

            "country_code":
                data.get(
                    "country_code"
                ) or "Unavailable",

            "region":
                data.get(
                    "region"
                ) or "Unavailable",

            "city":
                data.get(
                    "city"
                ) or "Unavailable",

            "postal":
                data.get(
                    "postal"
                ) or "Unavailable",

            "latitude":
                data.get(
                    "latitude"
                ),

            "longitude":
                data.get(
                    "longitude"
                ),

            "isp":
                connection.get(
                    "isp"
                ) or "Unavailable",

            "organization":
                connection.get(
                    "org"
                ) or "Unavailable",

            "asn":
                connection.get(
                    "asn"
                ) or "Unavailable",

            "domain":
                connection.get(
                    "domain"
                ) or "Unavailable",

            "timezone":
                timezone_data.get(
                    "id"
                ) or "Unavailable",

            "utc_offset":
                timezone_data.get(
                    "utc"
                ) or "Unavailable"
        }


    except requests.RequestException as error:

        return {

            "status": "UNAVAILABLE",

            "error":
                f"GeoIP network error: {str(error)}"
        }

    except Exception as error:

        return {

            "status": "UNAVAILABLE",

            "error":
                f"GeoIP analysis error: {str(error)}"
        }


# ============================================================
# SINGLE IP ANALYSIS
# ============================================================

def _analyze_single_ip(ip):

    ip = str(ip).strip()

    classification = _classify_ip(ip)

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()


    # --------------------------------------------------------
    # INVALID IP
    # --------------------------------------------------------

    if not classification["valid"]:

        return {

            "ip": ip,

            "type": "Invalid",

            "ip_version": "N/A",

            "country": "Unavailable",

            "country_code": "N/A",

            "region": "Unavailable",

            "city": "Unavailable",

            "postal": "Unavailable",

            "latitude": None,

            "longitude": None,

            "organization": "Unavailable",

            "isp": "Unavailable",

            "asn": "Unavailable",

            "domain": "Unavailable",

            "timezone": "Unavailable",

            "reverse_dns": "Unavailable",

            "reputation": "UNKNOWN",

            "status": "INVALID",

            "findings": [
                "Invalid IP address supplied."
            ],

            "confidence": "HIGH",

            "analyzed_at": timestamp
        }


    # --------------------------------------------------------
    # DOCUMENTATION IP
    # --------------------------------------------------------

    if classification["is_documentation"]:

        return {

            "ip": ip,

            "type": "Documentation/Test",

            "ip_version":
                classification["version"],

            "country":
                "Not applicable",

            "country_code":
                "N/A",

            "region":
                "Not applicable",

            "city":
                "Not applicable",

            "postal":
                "N/A",

            "latitude":
                None,

            "longitude":
                None,

            "organization":
                "Documentation Network",

            "isp":
                "Documentation Network",

            "asn":
                "N/A",

            "domain":
                "N/A",

            "timezone":
                "N/A",

            "reverse_dns":
                "N/A",

            "reputation":
                "TEST_ADDRESS",

            "status":
                "DOCUMENTATION",

            "findings": [

                "Documentation/test IP detected.",

                "Real-world geographic attribution is not applicable.",

                "This address should not be used to infer an attacker's location."
            ],

            "confidence":
                "HIGH",

            "analyzed_at":
                timestamp
        }


    # --------------------------------------------------------
    # PRIVATE / SPECIAL IP
    # --------------------------------------------------------

    if not classification["is_public"]:

        reverse = _reverse_dns(ip)

        return {

            "ip": ip,

            "type":
                classification["type"],

            "ip_version":
                classification["version"],

            "country":
                "Private Network",

            "country_code":
                "N/A",

            "region":
                "N/A",

            "city":
                "N/A",

            "postal":
                "N/A",

            "latitude":
                None,

            "longitude":
                None,

            "organization":
                "Private Network",

            "isp":
                "N/A",

            "asn":
                "N/A",

            "domain":
                "N/A",

            "timezone":
                "N/A",

            "reverse_dns":
                reverse.get(
                    "hostname"
                ) or "Unavailable",

            "reputation":
                "NOT_APPLICABLE",

            "status":
                "PRIVATE",

            "findings": [

                f"{classification['type']} IP detected.",

                "Public internet geolocation is not applicable."
            ],

            "confidence":
                "HIGH",

            "analyzed_at":
                timestamp
        }


    # --------------------------------------------------------
    # PUBLIC IP
    # --------------------------------------------------------

    reverse = _reverse_dns(ip)

    geo = _lookup_geoip(ip)


    findings = []


    if reverse.get("hostname"):

        findings.append(
            "Reverse DNS hostname identified: "
            + reverse["hostname"]
        )


    if geo.get("status") == "FOUND":

        findings.append(
            "Public IP successfully geolocated."
        )

        confidence = "HIGH"

    else:

        findings.append(
            "Public IP geolocation unavailable."
        )

        confidence = "LOW"


    return {

        "ip": ip,

        "type": "Public",

        "ip_version":
            classification["version"],

        "country":
            geo.get(
                "country",
                "Unavailable"
            ),

        "country_code":
            geo.get(
                "country_code",
                "Unavailable"
            ),

        "region":
            geo.get(
                "region",
                "Unavailable"
            ),

        "city":
            geo.get(
                "city",
                "Unavailable"
            ),

        "postal":
            geo.get(
                "postal",
                "Unavailable"
            ),

        "latitude":
            geo.get(
                "latitude"
            ),

        "longitude":
            geo.get(
                "longitude"
            ),

        "organization":
            geo.get(
                "organization",
                "Unavailable"
            ),

        "isp":
            geo.get(
                "isp",
                "Unavailable"
            ),

        "asn":
            geo.get(
                "asn",
                "Unavailable"
            ),

        "domain":
            geo.get(
                "domain",
                "Unavailable"
            ),

        "timezone":
            geo.get(
                "timezone",
                "Unavailable"
            ),

        "reverse_dns":
            reverse.get(
                "hostname"
            ) or "Unavailable",

        "reputation":
            "UNKNOWN",

        "status":
            geo.get(
                "status",
                "UNAVAILABLE"
            ),

        "findings":
            findings,

        "confidence":
            confidence,

        "analyzed_at":
            timestamp,

        "provider":
            "ipwho.is"
    }


# ============================================================
# MAIN FUNCTION
# ============================================================

def analyze_ips(ip_input):

    ip_addresses = _extract_ip_values(
        ip_input
    )

    results = []

    findings = []

    public_count = 0

    private_count = 0

    documentation_count = 0


    for ip in ip_addresses:

        result = _analyze_single_ip(
            ip
        )

        results.append(
            result
        )


        if result["type"] == "Public":

            public_count += 1

        elif result["type"] == "Documentation/Test":

            documentation_count += 1

        else:

            private_count += 1


        for finding in result.get(
            "findings",
            []
        ):

            findings.append(
                f"{ip}: {finding}"
            )


    # ========================================================
    # FINAL RESPONSE
    # ========================================================

    return {

        "status":
            (
                "ANALYZED"
                if results
                else "NO_IPS"
            ),

        "total":
            len(results),

        "public_count":
            public_count,

        "private_count":
            private_count,

        "documentation_count":
            documentation_count,

        "suspicious_count":
            0,

        "results":
            results,

        "findings":
            _unique(findings),

        "engine": {

            "name":
                "TARVEX26 GeoIP Intelligence Engine",

            "version":
                "2.0",

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

                "Private IP detection",

                "Documentation IP detection",

                "False attribution prevention"
            ],

            "provider":
                "ipwho.is",

            "note":
                "Documentation and private addresses are never assigned real-world geographic locations."
        },

        "analyzed_at":
            datetime.now(
                timezone.utc
            ).isoformat()
    }