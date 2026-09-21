"""
TARVEX26
Network Anonymization & Infrastructure Intelligence
SIH26106 - Email Threat Detection and Forensic Intelligence

Detects indicators associated with:
- VPN infrastructure
- TOR exit nodes
- Proxy infrastructure
- Cloud / hosting providers
- Datacenter networks
- Suspicious infrastructure naming

Important:
These are indicators, not proof of malicious activity.
"""

import ipaddress
import socket
from datetime import datetime, timezone

import requests


REQUEST_TIMEOUT = 6

TOR_CHECK_URL = "https://check.torproject.org/torbulkexitlist"

CLOUD_KEYWORDS = [
    "amazon",
    "aws",
    "amazon technologies",
    "google cloud",
    "google llc",
    "microsoft azure",
    "azure",
    "digitalocean",
    "linode",
    "vultr",
    "oracle cloud",
    "ibm cloud",
    "cloudflare",
    "ovh",
    "hetzner",
    "rackspace",
]

VPN_KEYWORDS = [
    "nordvpn",
    "expressvpn",
    "surfshark",
    "protonvpn",
    "private internet access",
    "pia",
    "cyberghost",
    "mullvad",
    "vpn",
]

PROXY_KEYWORDS = [
    "proxy",
    "anonymous proxy",
    "forward proxy",
    "web proxy",
    "squid",
]

HOSTING_KEYWORDS = [
    "hosting",
    "datacenter",
    "data center",
    "server",
    "dedicated",
    "vps",
    "virtual private server",
]


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


def _safe_text(value):

    if value is None:
        return ""

    return str(value).strip().lower()


def _is_valid_ip(ip):

    try:

        ipaddress.ip_address(ip)

        return True

    except ValueError:

        return False


def _reverse_dns(ip):

    try:

        hostname, aliases, addresses = socket.gethostbyaddr(ip)

        return {
            "status": "FOUND",
            "hostname": hostname,
            "aliases": aliases or [],
            "addresses": addresses or []
        }

    except Exception:

        return {
            "status": "NOT_FOUND",
            "hostname": None,
            "aliases": [],
            "addresses": []
        }


def _keyword_matches(text, keywords):

    matches = []

    text = _safe_text(text)

    for keyword in keywords:

        if keyword in text:

            matches.append(keyword)

    return _unique(matches)


def _check_tor(ip):

    """
    Checks the official Tor bulk exit list.

    If the service is unavailable, the result is UNKNOWN.
    """

    try:

        response = requests.get(
            TOR_CHECK_URL,
            timeout=REQUEST_TIMEOUT,
            headers={
                "User-Agent":
                    "TARVEX26-SIH26106-Forensics"
            }
        )

        if response.status_code != 200:

            return {
                "status": "UNKNOWN",
                "is_tor_exit": False,
                "message":
                    "Tor exit list unavailable."
            }

        tor_ips = set(
            line.strip()
            for line in response.text.splitlines()
            if line.strip()
            and not line.startswith("#")
        )

        if ip in tor_ips:

            return {
                "status": "DETECTED",
                "is_tor_exit": True,
                "message":
                    "IP address appears in the Tor exit-node list."
            }

        return {
            "status": "NOT_DETECTED",
            "is_tor_exit": False,
            "message":
                "IP address not found in the current Tor exit-node list."
        }

    except Exception as error:

        return {
            "status": "UNKNOWN",
            "is_tor_exit": False,
            "message":
                f"Tor intelligence unavailable: {str(error)}"
        }


def analyze_network(ip, geoip_data=None):

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    ip = str(ip).strip()

    if not _is_valid_ip(ip):

        return {
            "ip": ip,
            "status": "INVALID",
            "network_type": "UNKNOWN",
            "vpn": {
                "status": "UNKNOWN",
                "detected": False
            },
            "tor": {
                "status": "UNKNOWN",
                "detected": False
            },
            "proxy": {
                "status": "UNKNOWN",
                "detected": False
            },
            "hosting": {
                "status": "UNKNOWN",
                "detected": False
            },
            "cloud": {
                "status": "UNKNOWN",
                "detected": False
            },
            "findings": [
                "Invalid IP address."
            ],
            "confidence": "HIGH",
            "analyzed_at": timestamp
        }

    address = ipaddress.ip_address(ip)

    if address.is_private:

        return {
            "ip": ip,
            "status": "PRIVATE",
            "network_type": "PRIVATE_NETWORK",
            "vpn": {
                "status": "NOT_APPLICABLE",
                "detected": False
            },
            "tor": {
                "status": "NOT_APPLICABLE",
                "detected": False
            },
            "proxy": {
                "status": "NOT_APPLICABLE",
                "detected": False
            },
            "hosting": {
                "status": "NOT_APPLICABLE",
                "detected": False
            },
            "cloud": {
                "status": "NOT_APPLICABLE",
                "detected": False
            },
            "findings": [
                "Private IP address detected.",
                "Internet infrastructure attribution is not applicable."
            ],
            "confidence": "HIGH",
            "analyzed_at": timestamp
        }

    reverse_dns = _reverse_dns(ip)

    hostname = reverse_dns.get(
        "hostname"
    ) or ""

    isp = ""

    organization = ""

    asn = ""

    if isinstance(geoip_data, dict):

        isp = geoip_data.get(
            "isp",
            ""
        )

        organization = geoip_data.get(
            "organization",
            ""
        )

        asn = str(
            geoip_data.get(
                "asn",
                ""
            )
        )

    intelligence_text = " ".join(
        [
            hostname,
            isp,
            organization,
            asn
        ]
    ).lower()

    cloud_matches = _keyword_matches(
        intelligence_text,
        CLOUD_KEYWORDS
    )

    vpn_matches = _keyword_matches(
        intelligence_text,
        VPN_KEYWORDS
    )

    proxy_matches = _keyword_matches(
        intelligence_text,
        PROXY_KEYWORDS
    )

    hosting_matches = _keyword_matches(
        intelligence_text,
        HOSTING_KEYWORDS
    )

    tor_result = _check_tor(ip)

    findings = []

    if reverse_dns.get("hostname"):

        findings.append(
            "Reverse DNS identified: "
            + reverse_dns["hostname"]
        )

    if cloud_matches:

        findings.append(
            "Cloud infrastructure indicators detected: "
            + ", ".join(cloud_matches)
        )

    if hosting_matches:

        findings.append(
            "Hosting/datacenter indicators detected: "
            + ", ".join(hosting_matches)
        )

    if vpn_matches:

        findings.append(
            "VPN-related infrastructure indicators detected."
        )

    if proxy_matches:

        findings.append(
            "Proxy-related infrastructure indicators detected."
        )

    if tor_result.get("is_tor_exit"):

        findings.append(
            "IP identified as a Tor exit-node indicator."
        )

    if not findings:

        findings.append(
            "No strong anonymization or hosting indicators identified."
        )

    if tor_result.get("is_tor_exit"):

        network_type = "TOR_EXIT"

    elif vpn_matches:

        network_type = "VPN_INDICATOR"

    elif proxy_matches:

        network_type = "PROXY_INDICATOR"

    elif cloud_matches:

        network_type = "CLOUD"

    elif hosting_matches:

        network_type = "HOSTING"

    else:

        network_type = "PUBLIC_NETWORK"

    return {

        "ip": ip,

        "status": "ANALYZED",

        "network_type":
            network_type,

        "reverse_dns":
            reverse_dns,

        "vpn": {

            "status":
                "DETECTED"
                if vpn_matches
                else "NOT_DETECTED",

            "detected":
                bool(vpn_matches),

            "indicators":
                vpn_matches
        },

        "tor": {

            "status":
                tor_result.get(
                    "status",
                    "UNKNOWN"
                ),

            "detected":
                tor_result.get(
                    "is_tor_exit",
                    False
                ),

            "message":
                tor_result.get(
                    "message"
                )
        },

        "proxy": {

            "status":
                "DETECTED"
                if proxy_matches
                else "NOT_DETECTED",

            "detected":
                bool(proxy_matches),

            "indicators":
                proxy_matches
        },

        "hosting": {

            "status":
                "DETECTED"
                if hosting_matches
                else "NOT_DETECTED",

            "detected":
                bool(hosting_matches),

            "indicators":
                hosting_matches
        },

        "cloud": {

            "status":
                "DETECTED"
                if cloud_matches
                else "NOT_DETECTED",

            "detected":
                bool(cloud_matches),

            "indicators":
                cloud_matches
        },

        "provider_context": {

            "isp":
                isp or "Unavailable",

            "organization":
                organization or "Unavailable",

            "asn":
                asn or "Unavailable"
        },

        "findings":
            findings,

        "confidence":
            "HIGH"
            if tor_result.get("is_tor_exit")
            else "MEDIUM",

        "analyzed_at":
            timestamp
    }


def analyze_ips(ip_addresses, geoip_results=None):

    if not isinstance(
        ip_addresses,
        list
    ):

        ip_addresses = []

    geoip_results = (
        geoip_results
        if isinstance(
            geoip_results,
            list
        )
        else []
    )

    geoip_map = {}

    for item in geoip_results:

        if isinstance(item, dict):

            item_ip = item.get(
                "ip"
            )

            if item_ip:

                geoip_map[
                    str(item_ip)
                ] = item

    results = []

    findings = []

    for ip in _unique(
        ip_addresses
    ):

        result = analyze_network(
            ip,
            geoip_map.get(
                str(ip)
            )
        )

        results.append(
            result
        )

        for finding in result.get(
            "findings",
            []
        ):

            findings.append(
                f"{ip}: {finding}"
            )

    return {

        "status":
            "ANALYZED"
            if results
            else "NO_IPS",

        "total_ips":
            len(results),

        "tor_count":
            sum(
                1
                for item in results
                if item.get("tor", {}).get("detected")
            ),

        "vpn_count":
            sum(
                1
                for item in results
                if item.get("vpn", {}).get("detected")
            ),

        "proxy_count":
            sum(
                1
                for item in results
                if item.get("proxy", {}).get("detected")
            ),

        "hosting_count":
            sum(
                1
                for item in results
                if item.get("hosting", {}).get("detected")
            ),

        "cloud_count":
            sum(
                1
                for item in results
                if item.get("cloud", {}).get("detected")
            ),

        "results":
            results,

        "findings":
            _unique(findings),

        "engine": {

            "name":
                "TARVEX26 Network Anonymization Intelligence",

            "version":
                "1.0",

            "capabilities": [

                "TOR exit-node detection",

                "VPN infrastructure indicators",

                "Proxy infrastructure indicators",

                "Cloud infrastructure detection",

                "Hosting/datacenter detection",

                "Reverse DNS correlation",

                "ISP correlation",

                "ASN correlation"
            ],

            "note":
                "Network indicators provide forensic evidence and should not be treated as definitive proof of user identity."
        },

        "analyzed_at":
            datetime.now(
                timezone.utc
            ).isoformat()
    }