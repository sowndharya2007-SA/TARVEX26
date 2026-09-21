"""
TARVEX26
Header Forensics & Authentication Intelligence Engine
SIH26106 - Email Threat Detection, GeoLocation and Forensic Intelligence

Analyzes:
- From
- Return-Path
- Reply-To
- Message-ID
- Received headers
- Authentication-Results
- SPF
- DKIM
- DMARC
- SPF alignment
- DKIM alignment
- Sender spoofing indicators
- Relay infrastructure
- IP addresses
- Domains
- Header anomalies

IMPORTANT:
This module analyzes authentication evidence present in the email.
Actual DNS-backed SPF/DKIM/DMARC verification is handled separately
by the domain intelligence layer.
"""

import re
import ipaddress
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr


# ============================================================
# BASIC HELPERS
# ============================================================

def _safe_text(value):
    """
    Convert any supported value safely into text.
    """

    if value is None:
        return ""

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")

    if isinstance(value, str):
        return value

    return str(value)


def _extract_email(value):
    """
    Extract email address from:

    Security Team <alerts@example.com>
    alerts@example.com
    """

    text = _safe_text(value)

    if not text:
        return None

    try:
        _, address = parseaddr(text)

        if address and "@" in address:
            return address.lower().strip()

    except Exception:
        pass

    match = re.search(
        r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",
        text
    )

    if match:
        return match.group(0).lower()

    return None


def _extract_domain(value):
    """
    Extract domain from an email address.
    """

    email_address = _extract_email(value)

    if not email_address:
        return None

    try:
        return email_address.split("@", 1)[1].lower().strip()
    except Exception:
        return None


def _is_private_ip(ip):
    """
    Determine whether an IP is private/reserved.
    """

    try:
        address = ipaddress.ip_address(ip)

        return (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
        )

    except Exception:
        return False


def _extract_ips(text):
    """
    Extract IPv4 and IPv6 addresses.
    """

    text = _safe_text(text)

    candidates = re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        text
    )

    valid_ips = []

    for candidate in candidates:

        try:

            ipaddress.ip_address(candidate)

            if candidate not in valid_ips:
                valid_ips.append(candidate)

        except Exception:
            continue

    return valid_ips


def _extract_domains(text):
    """
    Extract domain names from header text.
    """

    text = _safe_text(text)

    matches = re.findall(
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b",
        text
    )

    domains = []

    for domain in matches:

        domain = domain.lower().strip(".")

        if domain not in domains:
            domains.append(domain)

    return domains


# ============================================================
# NORMALIZE HEADERS
# ============================================================

def _normalize_headers(headers):
    """
    Accept either:

    1. Flask/app.py headers dictionary
    2. email.message.Message
    3. raw email bytes

    and convert everything into a safe dictionary.
    """

    # --------------------------------------------------------
    # Raw bytes
    # --------------------------------------------------------

    if isinstance(headers, bytes):

        try:

            message = BytesParser(
                policy=policy.default
            ).parsebytes(headers)

            return _message_to_dict(message)

        except Exception:

            return {}

    # --------------------------------------------------------
    # Email Message
    # --------------------------------------------------------

    if hasattr(headers, "items") and not isinstance(headers, dict):

        try:

            return _message_to_dict(headers)

        except Exception:

            pass

    # --------------------------------------------------------
    # Dictionary
    # --------------------------------------------------------

    if isinstance(headers, dict):

        normalized = {}

        for key, value in headers.items():

            normalized_key = (
                str(key)
                .strip()
                .lower()
                .replace("-", "_")
            )

            normalized[normalized_key] = value

        return normalized

    return {}


def _message_to_dict(message):

    result = {}

    header_names = [
        "From",
        "To",
        "Subject",
        "Date",
        "Reply-To",
        "Return-Path",
        "Message-ID",
        "Authentication-Results",
        "Received-SPF",
        "DKIM-Signature",
    ]

    for name in header_names:

        values = message.get_all(name, [])

        if not values:
            continue

        if len(values) == 1:
            result[
                name.lower().replace("-", "_")
            ] = _safe_text(values[0])

        else:
            result[
                name.lower().replace("-", "_")
            ] = [
                _safe_text(value)
                for value in values
            ]

    received = message.get_all(
        "Received",
        []
    )

    result["received"] = [
        _safe_text(value)
        for value in received
    ]

    return result


# ============================================================
# HEADER VALUE HELPERS
# ============================================================

def _get_header(headers, name):

    key = (
        name
        .lower()
        .replace("-", "_")
    )

    value = headers.get(key)

    if isinstance(value, list):

        return value[0] if value else ""

    return _safe_text(value)

def _get_header_list(headers, name):
    """
    Safely retrieve one or more header values.

    Supports both:
        received
        received_headers

    This is important because app.py may already provide
    Received headers using the explicit 'received_headers' key.
    """

    key = (
        name
        .lower()
        .replace("-", "_")
    )

    # Normal key
    value = headers.get(key)

    # Compatibility with app.py
    if value is None and key == "received":
        value = headers.get("received_headers")

    if value is None:
        return []

    if isinstance(value, list):
        return [
            _safe_text(item)
            for item in value
            if item is not None
        ]

    return [_safe_text(value)]


# ============================================================
# AUTHENTICATION RESULTS
# ============================================================

def _parse_authentication_results(headers):

    values = _get_header_list(
        headers,
        "Authentication-Results"
    )

    combined = "\n".join(values)

    result = {
        "spf": "NOT_PRESENT",
        "dkim": "NOT_PRESENT",
        "dmarc": "NOT_PRESENT",
        "spf_domain": None,
        "dkim_domain": None,
        "dmarc_domain": None,
        "raw": values,
    }

    # SPF
    match = re.search(
        r"\bspf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
        combined,
        re.IGNORECASE
    )

    if match:
        result["spf"] = match.group(1).upper()

    # DKIM
    match = re.search(
        r"\bdkim\s*=\s*(pass|fail|neutral|none|temperror|permerror)\b",
        combined,
        re.IGNORECASE
    )

    if match:
        result["dkim"] = match.group(1).upper()

    # DMARC
    match = re.search(
        r"\bdmarc\s*=\s*(pass|fail|bestguesspass|none|temperror|permerror)\b",
        combined,
        re.IGNORECASE
    )

    if match:
        result["dmarc"] = match.group(1).upper()

    # smtp.mailfrom
    match = re.search(
        r"smtp\.mailfrom\s*=\s*([^\s;]+)",
        combined,
        re.IGNORECASE
    )

    if match:

        result["spf_domain"] = (
            _extract_domain(
                match.group(1)
            )
            or match.group(1).lower()
        )

    # header.d
    dkim_domains = re.findall(
        r"header\.d\s*=\s*([^\s;]+)",
        combined,
        re.IGNORECASE
    )

    if dkim_domains:

        result["dkim_domain"] = (
            dkim_domains[0]
            .lower()
            .strip()
        )

    # header.from
    dmarc_domains = re.findall(
        r"header\.from\s*=\s*([^\s;]+)",
        combined,
        re.IGNORECASE
    )

    if dmarc_domains:

        result["dmarc_domain"] = (
            dmarc_domains[0]
            .lower()
            .strip()
        )

    return result


# ============================================================
# RECEIVED HEADER ANALYSIS
# ============================================================

def _analyze_received_headers(received_headers):

    all_ips = []
    all_domains = []

    relay_records = []

    anomalies = []

    for index, received in enumerate(
        received_headers
    ):

        text = _safe_text(received)

        ips = _extract_ips(text)

        domains = _extract_domains(text)

        for ip in ips:

            if ip not in all_ips:
                all_ips.append(ip)

        for domain in domains:

            if domain not in all_domains:
                all_domains.append(domain)

        relay_records.append(
            {
                "hop": index + 1,
                "raw": text,
                "ips": ips,
                "domains": domains,
                "private_ips": [
                    ip
                    for ip in ips
                    if _is_private_ip(ip)
                ],
            }
        )

        # Missing "from"
        if " from " not in (
            " " + text.lower() + " "
        ):

            anomalies.append(
                f"Received hop {index + 1}: missing 'from' field"
            )

        # Missing "by"
        if " by " not in (
            " " + text.lower() + " "
        ):

            anomalies.append(
                f"Received hop {index + 1}: missing 'by' field"
            )

    return {
        "count": len(received_headers),
        "records": relay_records,
        "ips": all_ips,
        "domains": all_domains,
        "anomalies": list(
            dict.fromkeys(anomalies)
        ),
    }


# ============================================================
# DKIM SIGNATURE ANALYSIS
# ============================================================

def _analyze_dkim_signature(headers):

    signature = _get_header(
        headers,
        "DKIM-Signature"
    )

    result = {
        "present": bool(signature),
        "version": None,
        "algorithm": None,
        "domain": None,
        "selector": None,
        "signed_headers": [],
        "body_hash_present": False,
        "signature_present": False,
        "verification": "UNVERIFIED",
    }

    if not signature:

        result["verification"] = "NOT_PRESENT"

        return result

    # v=
    match = re.search(
        r"(?:^|;)\s*v=([^;]+)",
        signature,
        re.IGNORECASE
    )

    if match:
        result["version"] = match.group(1).strip()

    # a=
    match = re.search(
        r"(?:^|;)\s*a=([^;]+)",
        signature,
        re.IGNORECASE
    )

    if match:
        result["algorithm"] = match.group(1).strip()

    # d=
    match = re.search(
        r"(?:^|;)\s*d=([^;]+)",
        signature,
        re.IGNORECASE
    )

    if match:
        result["domain"] = match.group(1).strip().lower()

    # s=
    match = re.search(
        r"(?:^|;)\s*s=([^;]+)",
        signature,
        re.IGNORECASE
    )

    if match:
        result["selector"] = match.group(1).strip()

    # h=
    match = re.search(
        r"(?:^|;)\s*h=([^;]+)",
        signature,
        re.IGNORECASE
    )

    if match:

        result["signed_headers"] = [
            item.strip().lower()
            for item in match.group(1).split(":")
            if item.strip()
        ]

    # bh=
    match = re.search(
        r"(?:^|;)\s*bh=([^;]+)",
        signature,
        re.IGNORECASE
    )

    result["body_hash_present"] = bool(match)

    # b=
    match = re.search(
        r"(?:^|;)\s*b=([^;]+)",
        signature,
        re.IGNORECASE
    )

    result["signature_present"] = bool(match)

    # IMPORTANT:
    # Presence of a DKIM signature does NOT mean it is valid.
    result["verification"] = "UNVERIFIED"

    return result


# ============================================================
# ALIGNMENT
# ============================================================

def _domain_aligns(domain_a, domain_b):

    if not domain_a or not domain_b:
        return False

    a = domain_a.lower().strip(".")
    b = domain_b.lower().strip(".")

    return (
        a == b
        or a.endswith("." + b)
        or b.endswith("." + a)
    )


def _calculate_alignment(
    from_domain,
    return_path_domain,
    dkim_domain
):

    spf_alignment = None
    dkim_alignment = None

    if from_domain and return_path_domain:

        spf_alignment = _domain_aligns(
            from_domain,
            return_path_domain
        )

    if from_domain and dkim_domain:

        dkim_alignment = _domain_aligns(
            from_domain,
            dkim_domain
        )

    return {
        "spf_alignment": spf_alignment,
        "dkim_alignment": dkim_alignment,
    }


# ============================================================
# SPOOFING ANALYSIS
# ============================================================

def _analyze_spoofing(
    from_domain,
    return_path_domain,
    reply_to_domain,
    message_id_domain,
    authentication,
    alignment
):

    indicators = []
    score = 0

    # Return-Path mismatch
    if (
        from_domain
        and return_path_domain
        and not _domain_aligns(
            from_domain,
            return_path_domain
        )
    ):

        indicators.append(
            "From and Return-Path domains do not align"
        )

        score += 25

    # Reply-To mismatch
    if (
        from_domain
        and reply_to_domain
        and not _domain_aligns(
            from_domain,
            reply_to_domain
        )
    ):

        indicators.append(
            "From and Reply-To domains do not align"
        )

        score += 20

    # Message-ID mismatch
    if (
        from_domain
        and message_id_domain
        and not _domain_aligns(
            from_domain,
            message_id_domain
        )
    ):

        indicators.append(
            "Message-ID domain does not align with From domain"
        )

        score += 15

    # SPF
    if authentication["spf"] in {
        "FAIL",
        "SOFTFAIL",
        "PERMERROR",
    }:

        indicators.append(
            f"SPF authentication result: {authentication['spf']}"
        )

        score += 20

    # DKIM
    if authentication["dkim"] in {
        "FAIL",
        "PERMERROR",
    }:

        indicators.append(
            f"DKIM authentication result: {authentication['dkim']}"
        )

        score += 20

    # DMARC
    if authentication["dmarc"] in {
        "FAIL",
        "PERMERROR",
    }:

        indicators.append(
            f"DMARC authentication result: {authentication['dmarc']}"
        )

        score += 25

    # Alignment
    if alignment["spf_alignment"] is False:

        indicators.append(
            "SPF identity is not aligned with the visible From domain"
        )

        score += 15

    if alignment["dkim_alignment"] is False:

        indicators.append(
            "DKIM signing domain is not aligned with the visible From domain"
        )

        score += 15

    score = min(
        100,
        score
    )

    if score >= 70:

        risk = "HIGH"

    elif score >= 35:

        risk = "MEDIUM"

    elif score > 0:

        risk = "LOW"

    else:

        risk = "MINIMAL"

    return {
        "score": score,
        "risk_level": risk,
        "indicators": list(
            dict.fromkeys(indicators)
        ),
    }


# ============================================================
# MAIN ANALYZER
# ============================================================

def analyze_headers(headers):

    try:

        # ----------------------------------------------------
        # Normalize safely
        # ----------------------------------------------------

        normalized = _normalize_headers(
            headers
        )

        # ----------------------------------------------------
        # Core headers
        # ----------------------------------------------------

        sender = _get_header(
            normalized,
            "From"
        )

        return_path = _get_header(
            normalized,
            "Return-Path"
        )

        reply_to = _get_header(
            normalized,
            "Reply-To"
        )

        message_id = _get_header(
            normalized,
            "Message-ID"
        )

        date = _get_header(
            normalized,
            "Date"
        )

        subject = _get_header(
            normalized,
            "Subject"
        )

        # ----------------------------------------------------
        # Domains
        # ----------------------------------------------------

        from_domain = _extract_domain(
            sender
        )

        return_path_domain = _extract_domain(
            return_path
        )

        reply_to_domain = _extract_domain(
            reply_to
        )

        # Message-ID domain
        message_id_domain = None

        if message_id:

            match = re.search(
                r"@([A-Za-z0-9.-]+)",
                message_id
            )

            if match:

                message_id_domain = (
                    match.group(1)
                    .lower()
                    .strip(">")
                )

        # ----------------------------------------------------
        # Authentication
        # ----------------------------------------------------

        authentication = (
            _parse_authentication_results(
                normalized
            )
        )

        # ----------------------------------------------------
        # DKIM
        # ----------------------------------------------------

        dkim_signature = (
            _analyze_dkim_signature(
                normalized
            )
        )

        if (
            dkim_signature["domain"]
            and not authentication["dkim_domain"]
        ):

            authentication[
                "dkim_domain"
            ] = dkim_signature[
                "domain"
            ]

        # ----------------------------------------------------
        # Received headers
        # ----------------------------------------------------

        received_headers = (
            _get_header_list(
                normalized,
                "Received"
            )
        )

        relay_analysis = (
            _analyze_received_headers(
                received_headers
            )
        )

        # ----------------------------------------------------
        # IPs
        # ----------------------------------------------------

        ip_addresses = (
            relay_analysis["ips"]
        )

        # Also search all important headers
        header_text = "\n".join(
            [
                _safe_text(sender),
                _safe_text(return_path),
                _safe_text(reply_to),
                _safe_text(message_id),
                "\n".join(received_headers),
                "\n".join(
                    authentication["raw"]
                ),
            ]
        )

        for ip in _extract_ips(
            header_text
        ):

            if ip not in ip_addresses:

                ip_addresses.append(ip)

        # ----------------------------------------------------
        # Domains
        # ----------------------------------------------------

        domains = []

        for domain in [
            from_domain,
            return_path_domain,
            reply_to_domain,
            message_id_domain,
            authentication["spf_domain"],
            authentication["dkim_domain"],
            authentication["dmarc_domain"],
        ]:

            if domain and domain not in domains:

                domains.append(domain)

        for domain in relay_analysis[
            "domains"
        ]:

            if domain not in domains:

                domains.append(domain)

        for domain in _extract_domains(
            header_text
        ):

            if domain not in domains:

                domains.append(domain)

        # ----------------------------------------------------
        # Alignment
        # ----------------------------------------------------

        alignment = _calculate_alignment(
            from_domain,
            return_path_domain,
            authentication["dkim_domain"]
        )

        # ----------------------------------------------------
        # Spoofing
        # ----------------------------------------------------

        spoofing = _analyze_spoofing(
            from_domain,
            return_path_domain,
            reply_to_domain,
            message_id_domain,
            authentication,
            alignment
        )

        # ----------------------------------------------------
        # Findings
        # ----------------------------------------------------

        findings = []

        if not date:

            findings.append(
                "Date header is missing"
            )

        if not message_id:

            findings.append(
                "Message-ID header is missing"
            )

        if not received_headers:

            findings.append(
                "No Received headers found"
            )

        if not sender:

            findings.append(
                "From header is missing"
            )

        if not return_path:

            findings.append(
                "Return-Path header is missing"
            )

        if not reply_to:

            findings.append(
                "Reply-To header is missing"
            )

        if (
            from_domain
            and reply_to_domain
            and not _domain_aligns(
                from_domain,
                reply_to_domain
            )
        ):

            findings.append(
                "Sender and Reply-To domains do not match"
            )

        if (
            from_domain
            and return_path_domain
            and not _domain_aligns(
                from_domain,
                return_path_domain
            )
        ):

            findings.append(
                "Sender and Return-Path domains do not align"
            )

        findings.extend(
            relay_analysis["anomalies"]
        )

        findings.extend(
            spoofing["indicators"]
        )

        findings = list(
            dict.fromkeys(findings)
        )

        # ----------------------------------------------------
        # Authentication result display
        # ----------------------------------------------------

        authentication_results = []

        for mechanism in [
            "spf",
            "dkim",
            "dmarc",
        ]:

            status = authentication[
                mechanism
            ]

            if status != "NOT_PRESENT":

                authentication_results.append(
                    f"{mechanism.upper()} = {status}"
                )

        if not authentication_results:

            authentication_results.append(
                "No Authentication-Results header found"
            )

        # ----------------------------------------------------
        # Header completeness
        # ----------------------------------------------------

        expected_headers = [
            "from",
            "return_path",
            "reply_to",
            "message_id",
            "date",
        ]

        present_count = sum(
            bool(
                normalized.get(
                    key
                )
            )
            for key in expected_headers
        )

        completeness = round(
            (
                present_count
                / len(expected_headers)
            ) * 100
        )

        # ----------------------------------------------------
        # Return
        # ----------------------------------------------------

        return {

            "sender": sender,

            "from": sender,

            "to": _get_header(
                normalized,
                "To"
            ),

            "subject": subject,

            "date": date,

            "return_path": return_path,

            "reply_to": reply_to,

            "message_id": message_id,

            "sender_domain":
                from_domain,

            "return_path_domain":
                return_path_domain,

            "reply_to_domain":
                reply_to_domain,

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
                authentication_results,

            "authentication":
                authentication,

            "spf":
                authentication["spf"],

            "dkim":
                authentication["dkim"],

            "dmarc":
                authentication["dmarc"],

            "dkim_signature":
                dkim_signature,

            "alignment":
                alignment,

            "spoofing":
                spoofing,

            "spoofing_risk":
                spoofing["risk_level"],

            "spoofing_score":
                spoofing["score"],

            "findings":
                findings,

            "header_completeness":
                completeness,

            "engine": {

                "name":
                    "TARVEX26 Header Forensics Engine",

                "version":
                    "2.0",

                "analysis_type":
                    "Header parsing, authentication evidence, alignment and spoofing analysis",

                "dns_validation":
                    "Handled by Domain Intelligence Engine",

                "dkim_cryptographic_verification":
                    "UNVERIFIED",

                "explainable":
                    True,
            },
        }

    except Exception as error:

        # Never allow header analysis to destroy
        # the complete forensic pipeline.

        return {

            "sender": "",
            "from": "",
            "to": "",
            "subject": "",
            "date": "",
            "return_path": "",
            "reply_to": "",
            "message_id": "",

            "sender_domain": None,
            "return_path_domain": None,
            "reply_to_domain": None,
            "message_id_domain": None,

            "ip_addresses": [],
            "domains": [],
            "received_headers": [],
            "received_count": 0,

            "relay_analysis": {
                "count": 0,
                "records": [],
                "ips": [],
                "domains": [],
                "anomalies": [],
            },

            "authentication_results": [
                "Header analysis failed"
            ],

            "authentication": {
                "spf": "UNVERIFIED",
                "dkim": "UNVERIFIED",
                "dmarc": "UNVERIFIED",
                "spf_domain": None,
                "dkim_domain": None,
                "dmarc_domain": None,
                "raw": [],
            },

            "spf": "UNVERIFIED",
            "dkim": "UNVERIFIED",
            "dmarc": "UNVERIFIED",

            "dkim_signature": {
                "present": False,
                "verification": "UNVERIFIED",
            },

            "alignment": {
                "spf_alignment": None,
                "dkim_alignment": None,
            },

            "spoofing": {
                "score": 0,
                "risk_level": "UNVERIFIED",
                "indicators": [],
            },

            "spoofing_risk":
                "UNVERIFIED",

            "spoofing_score":
                0,

            "findings": [
                f"Header analysis error: {str(error)}"
            ],

            "header_completeness":
                0,

            "engine": {
                "name":
                    "TARVEX26 Header Forensics Engine",

                "version":
                    "2.0",

                "analysis_type":
                    "Header parsing, authentication evidence, alignment and spoofing analysis",

                "error":
                    str(error),
            },
        }