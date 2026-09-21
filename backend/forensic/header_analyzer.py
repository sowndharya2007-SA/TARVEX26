"""
TARVEX26
Header Forensics Engine
SIH26106 - Email Threat Detection and Forensic Intelligence

Responsible for:
- From / To / Reply-To analysis
- Return-Path analysis
- Message-ID analysis
- Received header analysis
- IP extraction
- Domain extraction
- SPF / DKIM / DMARC result parsing
- Sender / Reply-To mismatch detection
- Relay analysis
- Header anomalies
"""

import re
import ipaddress
from email.utils import parseaddr


# ============================================================
# REGEX PATTERNS
# ============================================================

IP_PATTERN = re.compile(
    r"(?<![\w.])"
    r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?![\w.])"
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\b"
)


# ============================================================
# BASIC HELPERS
# ============================================================

def _safe(value):
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value.decode(
            "utf-8",
            errors="replace"
        )

    return str(value)


def _unique(values):
    result = []
    seen = set()

    for value in values:

        value = _safe(value).strip()

        if not value:
            continue

        if value not in seen:
            seen.add(value)
            result.append(value)

    return result


def _extract_ips(text):
    """
    Extract valid IPv4 addresses from text.
    """

    text = _safe(text)

    candidates = IP_PATTERN.findall(text)

    valid = []

    for candidate in candidates:

        try:

            ipaddress.ip_address(candidate)

            valid.append(candidate)

        except ValueError:
            continue

    return _unique(valid)


def _extract_domains(text):
    """
    Extract domain names from text.
    """

    text = _safe(text)

    domains = DOMAIN_PATTERN.findall(text)

    cleaned = []

    for domain in domains:

        domain = domain.lower().strip(".,;:()[]<>")

        if domain not in cleaned:
            cleaned.append(domain)

    return cleaned


def _extract_email_domain(value):
    """
    Extract domain from:
        Name <user@example.com>
        user@example.com
    """

    value = _safe(value)

    _, address = parseaddr(value)

    if "@" not in address:
        return None

    domain = address.split("@", 1)[1]

    domain = domain.strip().lower()

    return domain if domain else None


# ============================================================
# AUTHENTICATION PARSER
# ============================================================

def _authentication_result(
    authentication_results,
    received_spf,
    dkim_signature
):

    text = " ".join([
        _safe(authentication_results),
        _safe(received_spf)
    ]).lower()

    results = {}

    # --------------------------------------------------------
    # SPF
    # --------------------------------------------------------

    if "spf=pass" in text:
        results["spf"] = "PASS"

    elif "spf=fail" in text:
        results["spf"] = "FAIL"

    elif "spf=softfail" in text:
        results["spf"] = "SOFTFAIL"

    elif "spf=neutral" in text:
        results["spf"] = "NEUTRAL"

    elif "spf=none" in text:
        results["spf"] = "NONE"

    else:
        results["spf"] = "NOT PRESENT"


    # --------------------------------------------------------
    # DKIM
    # --------------------------------------------------------

    if "dkim=pass" in text:
        results["dkim"] = "PASS"

    elif "dkim=fail" in text:
        results["dkim"] = "FAIL"

    elif "dkim=none" in text:
        results["dkim"] = "NONE"

    elif dkim_signature:
        results["dkim"] = "PRESENT"

    else:
        results["dkim"] = "NOT PRESENT"


    # --------------------------------------------------------
    # DMARC
    # --------------------------------------------------------

    if "dmarc=pass" in text:
        results["dmarc"] = "PASS"

    elif "dmarc=fail" in text:
        results["dmarc"] = "FAIL"

    elif "dmarc=none" in text:
        results["dmarc"] = "NONE"

    else:
        results["dmarc"] = "NOT PRESENT"


    return results


# ============================================================
# RELAY ANALYSIS
# ============================================================

def _analyze_relays(
    received_headers,
    ip_addresses
):

    domains = []

    for header in received_headers:

        domains.extend(
            _extract_domains(header)
        )

    domains = _unique(domains)

    relay_count = len(
        received_headers
    )

    return {

        "received_count":
            relay_count,

        "domains":
            domains,

        "ip_addresses":
            ip_addresses,

        "relay_sequence":
            received_headers,

        "status":
            (
                "AVAILABLE"
                if relay_count > 0
                else "NO_RECEIVED_HEADERS"
            )
    }


# ============================================================
# MAIN ANALYZER
# ============================================================

def analyze_headers(headers):

    # ========================================================
    # NORMALIZE INPUT
    # ========================================================

    if headers is None:
        headers = {}

    if not isinstance(headers, dict):

        try:
            headers = dict(headers)

        except Exception:

            headers = {}


    # ========================================================
    # BASIC HEADERS
    # ========================================================

    sender = _safe(
        headers.get("from")
    )

    reply_to = _safe(
        headers.get("reply_to")
    )

    return_path = _safe(
        headers.get("return_path")
    )

    message_id = _safe(
        headers.get("message_id")
    )

    authentication_results = _safe(
        headers.get("authentication_results")
    )

    received_spf = _safe(
        headers.get("received_spf")
    )

    dkim_signature = _safe(
        headers.get("dkim_signature")
    )


    # ========================================================
    # RECEIVED HEADERS
    #
    # app.py can provide these under:
    #
    # received_headers
    #
    # received
    #
    # or Received
    # ========================================================

    received_headers = (
        headers.get("received_headers")
        or headers.get("received")
        or headers.get("Received")
        or []
    )

    if isinstance(
        received_headers,
        str
    ):

        received_headers = [
            received_headers
        ]

    if not isinstance(
        received_headers,
        list
    ):

        received_headers = list(
            received_headers
        )


    received_headers = [

        _safe(value).strip()

        for value in received_headers

        if _safe(value).strip()
    ]


    # ========================================================
    # IP EXTRACTION
    # ========================================================

    ip_addresses = []


    # Search Received headers FIRST.
    # This is the most important source.

    for received in received_headers:

        ip_addresses.extend(
            _extract_ips(received)
        )


    # Search all header values as a secondary source.

    for key, value in headers.items():

        if key in (
            "received_headers",
            "received",
            "Received"
        ):
            continue

        if isinstance(
            value,
            (list, tuple)
        ):

            for item in value:

                ip_addresses.extend(
                    _extract_ips(item)
                )

        else:

            ip_addresses.extend(
                _extract_ips(value)
            )


    ip_addresses = _unique(
        ip_addresses
    )


    # ========================================================
    # DOMAIN EXTRACTION
    # ========================================================

    domains = []


    for key, value in headers.items():

        if isinstance(
            value,
            (list, tuple)
        ):

            for item in value:

                domains.extend(
                    _extract_domains(item)
                )

        else:

            domains.extend(
                _extract_domains(value)
            )


    # ========================================================
    # IMPORTANT EMAIL DOMAINS
    # ========================================================

    sender_domain = (
        _extract_email_domain(
            sender
        )
    )

    reply_to_domain = (
        _extract_email_domain(
            reply_to
        )
    )

    return_path_domain = (
        _extract_email_domain(
            return_path
        )
    )

    message_id_domain = None

    if "@" in message_id:

        message_id_domain = (
            message_id
            .split("@", 1)[1]
            .replace(">", "")
            .strip()
            .lower()
        )


    if sender_domain:
        domains.append(
            sender_domain
        )

    if reply_to_domain:
        domains.append(
            reply_to_domain
        )

    if return_path_domain:
        domains.append(
            return_path_domain
        )

    if message_id_domain:
        domains.append(
            message_id_domain
        )


    domains = _unique(
        domains
    )


    # ========================================================
    # AUTHENTICATION
    # ========================================================

    authentication = _authentication_result(

        authentication_results,

        received_spf,

        dkim_signature
    )


    # ========================================================
    # FORENSIC FINDINGS
    # ========================================================

    findings = []


    # --------------------------------------------------------
    # Received headers
    # --------------------------------------------------------

    if not received_headers:

        findings.append(
            "No Received headers found."
        )

    else:

        findings.append(
            f"{len(received_headers)} Received header(s) analyzed."
        )


    # --------------------------------------------------------
    # Sender / Reply-To
    # --------------------------------------------------------

    if (
        sender_domain
        and reply_to_domain
        and sender_domain != reply_to_domain
    ):

        findings.append(
            "Sender and Reply-To domains do not match."
        )

    elif (
        sender_domain
        and not reply_to_domain
    ):

        findings.append(
            "Reply-To header is not present."
        )


    # --------------------------------------------------------
    # Return-Path
    # --------------------------------------------------------

    if (
        sender_domain
        and return_path_domain
        and sender_domain != return_path_domain
    ):

        findings.append(
            "From and Return-Path domains do not align."
        )


    # --------------------------------------------------------
    # SPF
    # --------------------------------------------------------

    if authentication["spf"] == "FAIL":

        findings.append(
            "SPF authentication result: FAIL."
        )

    elif authentication["spf"] == "SOFTFAIL":

        findings.append(
            "SPF authentication result: SOFTFAIL."
        )


    # --------------------------------------------------------
    # DKIM
    # --------------------------------------------------------

    if authentication["dkim"] == "FAIL":

        findings.append(
            "DKIM authentication result: FAIL."
        )


    # --------------------------------------------------------
    # DMARC
    # --------------------------------------------------------

    if authentication["dmarc"] == "FAIL":

        findings.append(
            "DMARC authentication result: FAIL."
        )


    # --------------------------------------------------------
    # IP findings
    # --------------------------------------------------------

    if ip_addresses:

        findings.append(
            f"{len(ip_addresses)} valid IP address(es) extracted."
        )

    else:

        findings.append(
            "No valid IP addresses extracted from analyzed headers."
        )


    # ========================================================
    # RELAY ANALYSIS
    # ========================================================

    relay_analysis = _analyze_relays(

        received_headers,

        ip_addresses
    )


    # ========================================================
    # AUTHENTICATION RESULTS LIST
    # ========================================================

    authentication_results_list = [

        f"SPF = {authentication['spf']}",

        f"DKIM = {authentication['dkim']}",

        f"DMARC = {authentication['dmarc']}"
    ]


    # ========================================================
    # HEADER SUMMARY
    # ========================================================

    summary = {

        "from":
            sender,

        "reply_to":
            reply_to,

        "return_path":
            return_path,

        "message_id":
            message_id,

        "sender_domain":
            sender_domain,

        "reply_to_domain":
            reply_to_domain,

        "return_path_domain":
            return_path_domain,

        "message_id_domain":
            message_id_domain
    }


    # ========================================================
    # FINAL RESULT
    # ========================================================

    return {

        "status":
            "ANALYZED",

        "from":
            sender,

        "reply_to":
            reply_to,

        "return_path":
            return_path,

        "message_id":
            message_id,

        "sender_domain":
            sender_domain,

        "reply_to_domain":
            reply_to_domain,

        "return_path_domain":
            return_path_domain,

        "message_id_domain":
            message_id_domain,

        "ip_addresses":
            ip_addresses,

        "domains":
            domains,

        "received_headers":
            received_headers,

        "received_count":
            len(received_headers),

        "relay_analysis":
            relay_analysis,

        "authentication_results":
            authentication_results_list,

        "authentication":
            authentication,

        "spf":
            authentication["spf"],

        "dkim":
            authentication["dkim"],

        "dmarc":
            authentication["dmarc"],

        "header_summary":
            summary,

        "findings":
            _unique(findings),

        "engine": {

            "name":
                "TARVEX26 Header Forensics Engine",

            "version":
                "2.0",

            "capabilities": [

                "Email header parsing",

                "Received header analysis",

                "IPv4 extraction",

                "Domain extraction",

                "Sender analysis",

                "Reply-To analysis",

                "Return-Path analysis",

                "Message-ID analysis",

                "SPF result parsing",

                "DKIM result parsing",

                "DMARC result parsing",

                "Relay path analysis",

                "Header anomaly detection"
            ]
        }
    }