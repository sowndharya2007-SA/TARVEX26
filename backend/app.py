"""
TARVEX26
AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

SIH26106
Blockchain & Cybersecurity

Flask backend for:
- Email ingestion
- Header forensics
- Threat/NLP analysis
- IP intelligence
- GeoIP analysis
- Network anonymization analysis
- Origin intelligence
- Domain intelligence
- URL intelligence
- Attachment analysis
- Correlation analysis
- Infrastructure graph
- Evidence preservation
- Chain of custody
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

import hashlib
import inspect
import re
import uuid
from datetime import datetime, timezone


# ============================================================
# FORENSIC MODULE IMPORTS
# ============================================================

from forensic.header_analyzer import analyze_headers
from forensic.ip_intelligence import analyze_ips as analyze_ip_intelligence
from forensic.threat_analyzer import analyze_threat
from forensic.origin_intelligence import analyze_origin
from forensic.geoip_analyzer import analyze_ips as analyze_geoip
from forensic.correlation_analyzer import analyze_correlation
from forensic.infrastructure_correlator import build_infrastructure_graph
from forensic.url_intelligence import analyze_urls
from forensic.attachment_analyzer import analyze_attachments
from forensic.domain_intelligence import analyze_domain

from forensic.report_generator import (
    generate_forensic_report,
    generate_report_filename
)

# Optional network intelligence module
try:
    from forensic.network_anonymization import analyze_ips as analyze_network
    NETWORK_ANONYMIZATION_AVAILABLE = True
except Exception:
    analyze_network = None
    NETWORK_ANONYMIZATION_AVAILABLE = False

# Chain of custody
from forensic.chain_of_custody import (
    create_chain_of_custody,
    complete_analysis_event,
    verify_evidence_integrity,
    generate_custody_summary,
)


# ============================================================
# FLASK CONFIGURATION
# ============================================================

app = Flask(
    __name__,
    template_folder="templates"
)

CORS(app)

app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024


# ============================================================
# CONSTANTS
# ============================================================

PLATFORM_NAME = "TARVEX26"
PROBLEM_STATEMENT = "SIH26106"
PROJECT_NAME = (
    "AI-Powered Email Threat Detection, "
    "GeoLocation and Forensic Intelligence Platform"
)

ALLOWED_EXTENSION = ".eml"


# ============================================================
# BASIC HELPERS
# ============================================================

def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data):
    if data is None:
        data = b""

    return hashlib.sha256(data).hexdigest()


def safe_text(value):
    if value is None:
        return ""

    try:
        return str(value)
    except Exception:
        return ""


def unique_list(values):
    """
    Preserve order while removing duplicates.
    """

    result = []

    if not values:
        return result

    for value in values:
        value = safe_text(value).strip()

        if value and value not in result:
            result.append(value)

    return result


def extract_email_address(value):
    """
    Extract email address from a header such as:

    Security Team <security@example.com>
    """

    if not value:
        return None

    try:
        name, address = parseaddr(str(value))

        if address and "@" in address:
            return address.strip()

    except Exception:
        pass

    return None


def extract_domain(value):
    """
    Extract domain from an email address/header.
    """

    address = extract_email_address(value)

    if not address:
        return None

    try:
        return address.split("@", 1)[1].lower().strip()
    except Exception:
        return None


def extract_domains_from_text(text):
    """
    Extract domain-like values from text.
    """

    if not text:
        return []

    pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"

    try:
        matches = re.findall(pattern, str(text))
        return unique_list([item.lower() for item in matches])
    except Exception:
        return []


def extract_ips_from_text(text):
    """
    Extract IPv4 addresses from arbitrary text.
    """

    if not text:
        return []

    pattern = (
        r"\b"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        r"(?:\."
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}"
        r"\b"
    )

    try:
        return unique_list(re.findall(pattern, str(text)))
    except Exception:
        return []


def extract_urls_from_text(text):
    """
    Extract HTTP/HTTPS URLs from email body.
    """

    if not text:
        return []

    pattern = r"https?://[^\s<>\"]+"

    try:
        return unique_list(re.findall(pattern, str(text)))
    except Exception:
        return []


# ============================================================
# EMAIL EXTRACTION
# ============================================================

def extract_email_headers(message):
    """
    Convert EmailMessage headers into a clean dictionary.
    """

    def get_header(name):
        try:
            value = message.get(name)
            return safe_text(value).strip()
        except Exception:
            return ""

    headers = {
        "from": get_header("From"),
        "to": get_header("To"),
        "cc": get_header("Cc"),
        "subject": get_header("Subject"),
        "date": get_header("Date"),
        "return_path": get_header("Return-Path"),
        "reply_to": get_header("Reply-To"),
        "message_id": get_header("Message-ID"),
        "sender": get_header("Sender"),
        "received": message.get_all("Received", []),
        "authentication_results": get_header("Authentication-Results"),
        "received_spf": get_header("Received-SPF"),
        "dkim_signature": get_header("DKIM-Signature"),
        "arc_authentication_results": get_header(
            "ARC-Authentication-Results"
        ),
        "arc_seal": get_header("ARC-Seal"),
        "arc_message_signature": get_header("ARC-Message-Signature"),
        "x_originating_ip": get_header("X-Originating-IP"),
        "x_forwarded_for": get_header("X-Forwarded-For"),
    }

    return headers


def extract_body(message):
    """
    Extract readable text from the email.
    """

    plain_parts = []
    html_parts = []

    try:
        if message.is_multipart():

            for part in message.walk():

                content_type = part.get_content_type()

                if content_type == "text/plain":

                    try:
                        payload = part.get_content()

                        if payload:
                            plain_parts.append(str(payload))

                    except Exception:
                        payload = part.get_payload(
                            decode=True
                        )

                        if payload:
                            plain_parts.append(
                                payload.decode(
                                    "utf-8",
                                    errors="replace"
                                )
                            )

                elif content_type == "text/html":

                    try:
                        payload = part.get_content()

                        if payload:
                            html_parts.append(str(payload))

                    except Exception:
                        payload = part.get_payload(
                            decode=True
                        )

                        if payload:
                            html_parts.append(
                                payload.decode(
                                    "utf-8",
                                    errors="replace"
                                )
                            )

        else:

            content_type = message.get_content_type()

            try:
                payload = message.get_content()
            except Exception:
                payload = message.get_payload(
                    decode=True
                )

                if isinstance(payload, bytes):
                    payload = payload.decode(
                        "utf-8",
                        errors="replace"
                    )

            if payload:

                if content_type == "text/html":
                    html_parts.append(str(payload))
                else:
                    plain_parts.append(str(payload))

    except Exception:
        pass

    plain_text = "\n".join(plain_parts).strip()
    html_text = "\n".join(html_parts).strip()

    return {
        "plain": plain_text,
        "html": html_text,
        "combined": (
            plain_text + "\n" + html_text
        ).strip()
    }


# ============================================================
# RECEIVED HEADER / RELAY ANALYSIS
# ============================================================

def build_received_analysis(headers):
    """
    Build a lightweight relay analysis directly from Received headers.
    """

    received_headers = headers.get("received", [])

    if not isinstance(received_headers, list):
        received_headers = [received_headers]

    received_headers = [
        safe_text(item).strip()
        for item in received_headers
        if safe_text(item).strip()
    ]

    ip_addresses = []
    domains = []

    for header in received_headers:

        ip_addresses.extend(
            extract_ips_from_text(header)
        )

        domains.extend(
            extract_domains_from_text(header)
        )

    ip_addresses = unique_list(ip_addresses)
    domains = unique_list(domains)

    findings = []

    if not received_headers:
        findings.append(
            "No Received headers were available for relay reconstruction."
        )

    else:
        findings.append(
            f"{len(received_headers)} Received header(s) analyzed."
        )

    if len(received_headers) > 1:
        findings.append(
            "Multiple relay hops identified."
        )

    return {
        "received_headers": received_headers,
        "received_count": len(received_headers),
        "ip_addresses": ip_addresses,
        "domains": domains,
        "findings": findings,
    }


# ============================================================
# HEADER ANALYZER WRAPPER
# ============================================================

def run_header_analysis(message, headers):
    """
    Try the existing header analyzer using the formats commonly
    used by TARVEX26 versions.

    This prevents one module's expected input type from crashing
    the entire forensic pipeline.
    """

    attempts = [
        lambda: analyze_headers(message),
        lambda: analyze_headers(headers),
        lambda: analyze_headers(
            {
                "headers": headers,
                "message": message
            }
        ),
    ]

    last_error = None

    for attempt in attempts:

        try:
            result = attempt()

            if result is not None:
                return result

        except Exception as error:
            last_error = error

    return {
        "status": "ERROR",
        "findings": [
            f"Header analysis error: {str(last_error)}"
        ],
        "ip_addresses": [],
        "domains": [],
        "received_headers": headers.get(
            "received",
            []
        ),
        "received_count": len(
            headers.get("received", [])
        ),
        "authentication_results": {},
    }


# ============================================================
# THREAT ANALYZER WRAPPER
# ============================================================

def run_threat_analysis(
    subject,
    body,
    headers,
    urls,
    attachments
):
    """
    Run the existing threat analyzer while supporting
    different argument styles.
    """

    attempts = [
        lambda: analyze_threat(
            subject=subject,
            body=body,
            headers=headers,
            urls=urls,
            attachments=attachments
        ),

        lambda: analyze_threat(
            subject,
            body,
            headers,
            urls,
            attachments
        ),

        lambda: analyze_threat(
            subject,
            body
        ),

        lambda: analyze_threat(
            body
        ),
    ]

    last_error = None

    for attempt in attempts:

        try:
            result = attempt()

            if result is not None:
                return result

        except Exception as error:
            last_error = error

    return {
        "classification": "UNKNOWN",
        "threat_score": 0,
        "fraud_score": 0,
        "score": 0,
        "risk_level": "UNKNOWN",
        "confidence": "LOW",
        "summary": "Threat analysis could not be completed.",
        "indicators": [
            f"Threat analyzer error: {str(last_error)}"
        ],
        "engine": {
            "name": "TARVEX26 Threat Analysis Engine",
            "status": "ERROR"
        }
    }


# ============================================================
# ORIGIN INTELLIGENCE WRAPPER
# ============================================================

def run_origin_analysis(headers, forensic_data):

    attempts = [
        lambda: analyze_origin(
            headers,
            forensic_data
        ),

        lambda: analyze_origin(
            headers
        ),

        lambda: analyze_origin(
            forensic_data
        ),
    ]

    last_error = None

    for attempt in attempts:

        try:
            result = attempt()

            if result is not None:
                return result

        except Exception as error:
            last_error = error

    return {
        "status": "ERROR",
        "findings": [
            f"Origin analysis error: {str(last_error)}"
        ]
    }


# ============================================================
# CORRELATION WRAPPER
# ============================================================

def run_correlation_analysis(
    headers,
    forensic_data,
    ip_intelligence,
    origin_intelligence
):

    attempts = [
        lambda: analyze_correlation(
            headers,
            forensic_data,
            ip_intelligence,
            origin_intelligence
        ),

        lambda: analyze_correlation(
            forensic_data,
            ip_intelligence,
            origin_intelligence
        ),

        lambda: analyze_correlation(
            forensic_data
        ),
    ]

    last_error = None

    for attempt in attempts:

        try:
            result = attempt()

            if result is not None:
                return result

        except Exception as error:
            last_error = error

    return {
        "status": "ERROR",
        "findings": [
            f"Correlation analysis error: {str(last_error)}"
        ]
    }


# ============================================================
# DOMAIN INTELLIGENCE
# ============================================================

def run_domain_intelligence(domain):

    if not domain:
        return {
            "status": "NO_DOMAIN",
            "domain": None,
            "findings": [
                "No sender domain available."
            ]
        }

    try:
        return analyze_domain(domain)

    except Exception as error:

        return {
            "status": "ERROR",
            "domain": domain,
            "findings": [
                f"Domain analysis error: {str(error)}"
            ]
        }


# ============================================================
# URL INTELLIGENCE
# ============================================================

def run_url_intelligence(body):

    urls = extract_urls_from_text(body)

    if not urls:

        try:
            result = analyze_urls(body)

            if result is not None:
                return result

        except Exception:
            pass

        return {
            "status": "NO_URLS",
            "total": 0,
            "results": [],
            "findings": []
        }

    attempts = [
        lambda: analyze_urls(body),
        lambda: analyze_urls(urls),
    ]

    for attempt in attempts:

        try:
            result = attempt()

            if result is not None:
                return result

        except Exception:
            continue

    return {
        "status": "ANALYZED",
        "total": len(urls),
        "results": [
            {
                "url": url,
                "status": "EXTRACTED"
            }
            for url in urls
        ],
        "findings": []
    }


# ============================================================
# IP INTELLIGENCE
# ============================================================

def run_ip_intelligence(ip_addresses):

    try:

        result = analyze_ip_intelligence(
            ip_addresses
        )

        if result is not None:
            return result

    except Exception as error:

        return {
            "status": "ERROR",
            "total": len(ip_addresses),
            "public_count": 0,
            "private_count": 0,
            "documentation_count": 0,
            "suspicious_count": 0,
            "results": [],
            "findings": [
                f"IP intelligence error: {str(error)}"
            ]
        }

    return {
        "status": "NO_IPS" if not ip_addresses else "ANALYZED",
        "total": len(ip_addresses),
        "public_count": 0,
        "private_count": 0,
        "documentation_count": 0,
        "suspicious_count": 0,
        "results": [],
        "findings": []
    }


# ============================================================
# GEOIP
# ============================================================

def run_geoip(ip_addresses):

    try:

        result = analyze_geoip(
            ip_addresses
        )

        if result is not None:
            return result

    except Exception as error:

        return {
            "status": "ERROR",
            "total_ips": len(ip_addresses),
            "results": [],
            "findings": [
                f"GeoIP analysis error: {str(error)}"
            ]
        }

    return {
        "status": "NO_IPS",
        "total_ips": 0,
        "results": []
    }


# ============================================================
# NETWORK ANONYMIZATION
# ============================================================

def run_network_anonymization(
    ip_addresses,
    geoip_results
):

    if not NETWORK_ANONYMIZATION_AVAILABLE:

        return {
            "status": "UNAVAILABLE",
            "total_ips": len(ip_addresses),
            "tor_count": 0,
            "vpn_count": 0,
            "proxy_count": 0,
            "hosting_count": 0,
            "cloud_count": 0,
            "results": [],
            "findings": [
                "Network anonymization module is unavailable."
            ]
        }

    try:

        result = analyze_network(
            ip_addresses,
            geoip_results
        )

        if result is not None:
            return result

    except TypeError:

        try:

            result = analyze_network(
                ip_addresses
            )

            if result is not None:
                return result

        except Exception as error:

            return {
                "status": "ERROR",
                "total_ips": len(ip_addresses),
                "tor_count": 0,
                "vpn_count": 0,
                "proxy_count": 0,
                "hosting_count": 0,
                "cloud_count": 0,
                "results": [],
                "findings": [
                    f"Network analysis error: {str(error)}"
                ]
            }

    except Exception as error:

        return {
            "status": "ERROR",
            "total_ips": len(ip_addresses),
            "tor_count": 0,
            "vpn_count": 0,
            "proxy_count": 0,
            "hosting_count": 0,
            "cloud_count": 0,
            "results": [],
            "findings": [
                f"Network analysis error: {str(error)}"
            ]
        }

    return {
        "status": "NO_IPS",
        "total_ips": 0,
        "tor_count": 0,
        "vpn_count": 0,
        "proxy_count": 0,
        "hosting_count": 0,
        "cloud_count": 0,
        "results": [],
        "findings": []
    }


# ============================================================
# ATTACHMENT ANALYSIS
# ============================================================

def run_attachment_analysis(message):

    try:

        result = analyze_attachments(
            message
        )

        if result is not None:
            return result

    except Exception as error:

        return {
            "total": 0,
            "attachments": [],
            "suspicious_count": 0,
            "suspicious_files": [],
            "findings": [
                f"Attachment analysis error: {str(error)}"
            ],
            "risk_level": "UNKNOWN"
        }

    return {
        "total": 0,
        "attachments": [],
        "suspicious_count": 0,
        "suspicious_files": [],
        "findings": [],
        "risk_level": "NONE"
    }


# ============================================================
# INFRASTRUCTURE GRAPH
# ============================================================

def run_infrastructure_graph(
    headers,
    forensic_data,
    ip_intelligence,
    origin_intelligence
):

    try:

        result = build_infrastructure_graph(
            headers,
            forensic_data,
            ip_intelligence,
            origin_intelligence
        )

        if result is not None:
            return result

    except Exception as error:

        return {
            "nodes": [],
            "relationships": [],
            "node_count": 0,
            "relationship_count": 0,
            "status": "ERROR",
            "findings": [
                f"Infrastructure graph error: {str(error)}"
            ]
        }

    return {
        "nodes": [],
        "relationships": [],
        "node_count": 0,
        "relationship_count": 0,
        "status": "NO_DATA"
    }


# ============================================================
# FORENSIC DATA BUILDER
# ============================================================

def build_forensic_data(
    headers,
    header_analysis,
    ip_addresses,
    received_analysis
):

    sender = headers.get("from")
    return_path = headers.get("return_path")
    reply_to = headers.get("reply_to")
    message_id = headers.get("message_id")

    sender_domain = extract_domain(sender)
    return_path_domain = extract_domain(return_path)
    reply_to_domain = extract_domain(reply_to)

    message_id_domain = None

    if message_id and "@" in message_id:

        try:

            message_id_domain = (
                message_id
                .split("@", 1)[1]
                .replace(">", "")
                .strip()
                .lower()
            )

        except Exception:
            pass

    domains = []

    domains.extend(
        extract_domains_from_text(
            safe_text(sender)
        )
    )

    domains.extend(
        extract_domains_from_text(
            safe_text(return_path)
        )
    )

    domains.extend(
        extract_domains_from_text(
            safe_text(reply_to)
        )
    )

    domains.extend(
        extract_domains_from_text(
            "\n".join(
                received_analysis.get(
                    "received_headers",
                    []
                )
            )
        )
    )

    domains = unique_list(domains)

    return {
        "sender": sender,
        "from": sender,
        "to": headers.get("to"),
        "subject": headers.get("subject"),
        "date": headers.get("date"),
        "return_path": return_path,
        "reply_to": reply_to,
        "message_id": message_id,

        "sender_domain": sender_domain,
        "return_path_domain": return_path_domain,
        "reply_to_domain": reply_to_domain,
        "message_id_domain": message_id_domain,

        "ip_addresses": ip_addresses,
        "domains": domains,

        "received_headers": received_analysis.get(
            "received_headers",
            []
        ),

        "received_count": received_analysis.get(
            "received_count",
            0
        ),

        "relay_analysis": received_analysis,

        "authentication_results": (
            headers.get(
                "authentication_results"
            )
        ),

        "authentication": (
            header_analysis.get(
                "authentication_results",
                {}
            )
            if isinstance(header_analysis, dict)
            else {}
        )
    }


# ============================================================
# ERROR RESPONSE
# ============================================================

def error_response(message, status_code=400):

    return jsonify(
        {
            "platform": PLATFORM_NAME,
            "problem_statement": PROBLEM_STATEMENT,
            "status": "ERROR",
            "error": message,
            "timestamp": utc_now()
        }
    ), status_code


# ============================================================
# ROUTES
# ============================================================

@app.route("/", methods=["GET"])
def index():

    try:
        return render_template(
            "index.html"
        )

    except Exception:

        return jsonify(
            {
                "platform": PLATFORM_NAME,
                "problem_statement": PROBLEM_STATEMENT,
                "project": PROJECT_NAME,
                "status": "ONLINE",
                "timestamp": utc_now()
            }
        )


@app.route("/health", methods=["GET"])
def health():

    return jsonify(
        {
            "platform": PLATFORM_NAME,
            "problem_statement": PROBLEM_STATEMENT,
            "project": PROJECT_NAME,
            "status": "ONLINE",
            "timestamp": utc_now(),

            "services": {
                "header_forensics": "ENABLED",
                "threat_analysis": "ENABLED",
                "ip_intelligence": "ENABLED",
                "geoip_intelligence": "ENABLED",
                "network_anonymization": (
                    "ENABLED"
                    if NETWORK_ANONYMIZATION_AVAILABLE
                    else "UNAVAILABLE"
                ),
                "origin_intelligence": "ENABLED",
                "domain_intelligence": "ENABLED",
                "url_intelligence": "ENABLED",
                "attachment_analysis": "ENABLED",
                "correlation_analysis": "ENABLED",
                "infrastructure_graph": "ENABLED",
                "evidence_preservation": "ENABLED",
                "chain_of_custody": "ENABLED"
            }
        }
    )


@app.route(
    "/analyze-email",
    methods=["POST"]
)
def analyze_email():

    analysis_started = utc_now()

    # --------------------------------------------------------
    # FILE VALIDATION
    # --------------------------------------------------------

    email_file = request.files.get("email")

    if email_file is None:
        email_file = request.files.get("file")

    if email_file is None:
        return error_response(
            "No email file was uploaded. Use form field 'email'.",
            400
        )

    filename = safe_text(
        email_file.filename
    ).strip()

    if not filename:
        return error_response(
            "Uploaded file has no filename.",
            400
        )

    if not filename.lower().endswith(
        ALLOWED_EXTENSION
    ):
        return error_response(
            "Only .eml email files are supported.",
            400
        )

    # --------------------------------------------------------
    # READ EMAIL
    # --------------------------------------------------------

    try:

        email_bytes = email_file.read()

    except Exception as error:

        return error_response(
            f"Unable to read email file: {str(error)}",
            400
        )

    if not email_bytes:

        return error_response(
            "Uploaded email file is empty.",
            400
        )

    # --------------------------------------------------------
    # SHA-256 / BASIC EVIDENCE
    # --------------------------------------------------------

    evidence_hash = sha256_bytes(
        email_bytes
    )

    evidence_data = {
        "evidence_id": (
            f"TRX-"
            f"{datetime.now().strftime('%Y%m%d')}-"
            f"{uuid.uuid4().hex[:8].upper()}"
        ),

        "filename": filename,

        "file_size": len(
            email_bytes
        ),

        "sha256": evidence_hash,

        "evidence_type": "EMAIL",

        "status": "PRESERVED",

        "preserved_at": utc_now(),

        "hash_algorithm": "SHA-256"
    }

    # --------------------------------------------------------
    # CHAIN OF CUSTODY
    # --------------------------------------------------------

    try:

        chain_of_custody = create_chain_of_custody(
            email_bytes,
            filename=filename,
            evidence_type="EMAIL"
        )

    except Exception as error:

        chain_of_custody = {
            "status": "ERROR",
            "case_id": None,
            "evidence_id": evidence_data[
                "evidence_id"
            ],
            "error": str(error),
            "timeline": []
        }

    # --------------------------------------------------------
    # PARSE EMAIL
    # --------------------------------------------------------

    try:

        message = BytesParser(
            policy=policy.default
        ).parsebytes(
            email_bytes
        )

    except Exception as error:

        return error_response(
            f"Unable to parse .eml file: {str(error)}",
            400
        )

    # --------------------------------------------------------
    # HEADERS
    # --------------------------------------------------------

    headers = extract_email_headers(
        message
    )

    # --------------------------------------------------------
    # BODY
    # --------------------------------------------------------

    body_data = extract_body(
        message
    )

    plain_body = body_data.get(
        "plain",
        ""
    )

    combined_body = body_data.get(
        "combined",
        ""
    )

    subject = headers.get(
        "subject",
        ""
    )

    # --------------------------------------------------------
    # HEADER FORENSICS
    # --------------------------------------------------------

    header_analysis = run_header_analysis(
        message,
        headers
    )

    if not isinstance(
        header_analysis,
        dict
    ):
        header_analysis = {
            "status": "ANALYZED",
            "result": header_analysis
        }

    # --------------------------------------------------------
    # RECEIVED / RELAY ANALYSIS
    # --------------------------------------------------------

    received_analysis = build_received_analysis(
        headers
    )

    # --------------------------------------------------------
    # EXTRACT IP ADDRESSES
    # --------------------------------------------------------

    ip_addresses = []

    ip_addresses.extend(
        extract_ips_from_text(
            "\n".join(
                received_analysis.get(
                    "received_headers",
                    []
                )
            )
        )
    )

    ip_addresses.extend(
        extract_ips_from_text(
            safe_text(
                headers.get(
                    "x_originating_ip"
                )
            )
        )
    )

    ip_addresses.extend(
        extract_ips_from_text(
            safe_text(
                headers.get(
                    "x_forwarded_for"
                )
            )
        )
    )

    # Some header analyzers may already have extracted IPs.
    analyzer_ips = header_analysis.get(
        "ip_addresses",
        []
    )

    if isinstance(
        analyzer_ips,
        list
    ):
        ip_addresses.extend(
            analyzer_ips
        )

    ip_addresses = unique_list(
        ip_addresses
    )

    # --------------------------------------------------------
    # DOMAINS
    # --------------------------------------------------------

    domains = []

    domains.extend(
        extract_domains_from_text(
            headers.get(
                "from",
                ""
            )
        )
    )

    domains.extend(
        extract_domains_from_text(
            headers.get(
                "return_path",
                ""
            )
        )
    )

    domains.extend(
        extract_domains_from_text(
            headers.get(
                "reply_to",
                ""
            )
        )
    )

    domains.extend(
        extract_domains_from_text(
            "\n".join(
                received_analysis.get(
                    "received_headers",
                    []
                )
            )
        )
    )

    domains = unique_list(
        domains
    )

    # --------------------------------------------------------
    # FORENSIC DATA
    # --------------------------------------------------------

    forensic_data = build_forensic_data(
        headers,
        header_analysis,
        ip_addresses,
        received_analysis
    )

    forensic_data["domains"] = unique_list(
        forensic_data.get(
            "domains",
            []
        ) + domains
    )

    # --------------------------------------------------------
    # IP INTELLIGENCE
    # --------------------------------------------------------

    ip_intelligence = run_ip_intelligence(
        ip_addresses
    )

    # --------------------------------------------------------
    # GEOIP
    # --------------------------------------------------------

    geoip_intelligence = run_geoip(
        ip_addresses
    )

    geoip_results = []

    if isinstance(
        geoip_intelligence,
        dict
    ):

        geoip_results = geoip_intelligence.get(
            "results",
            []
        )

    # --------------------------------------------------------
    # NETWORK ANONYMIZATION
    # --------------------------------------------------------

    network_anonymization = (
        run_network_anonymization(
            ip_addresses,
            geoip_results
        )
    )

    # --------------------------------------------------------
    # ORIGIN INTELLIGENCE
    # --------------------------------------------------------

    origin_intelligence = run_origin_analysis(
        headers,
        forensic_data
    )

    # --------------------------------------------------------
    # URL INTELLIGENCE
    # --------------------------------------------------------

    url_analysis = run_url_intelligence(
        combined_body
    )

    # --------------------------------------------------------
    # ATTACHMENT ANALYSIS
    # --------------------------------------------------------

    attachment_analysis = (
        run_attachment_analysis(
            message
        )
    )

    # --------------------------------------------------------
    # THREAT ANALYSIS
    # --------------------------------------------------------

    threat_analysis = run_threat_analysis(
        subject,
        combined_body,
        headers,
        url_analysis,
        attachment_analysis
    )

    # --------------------------------------------------------
    # DOMAIN INTELLIGENCE
    # --------------------------------------------------------

    sender_domain = extract_domain(
        headers.get(
            "from"
        )
    )

    domain_intelligence = (
        run_domain_intelligence(
            sender_domain
        )
    )

    # --------------------------------------------------------
    # CORRELATION ANALYSIS
    # --------------------------------------------------------

    correlation = run_correlation_analysis(
        headers,
        forensic_data,
        ip_intelligence,
        origin_intelligence
    )

    # --------------------------------------------------------
    # INFRASTRUCTURE GRAPH
    # --------------------------------------------------------

    infrastructure_graph = (
        run_infrastructure_graph(
            headers,
            forensic_data,
            ip_intelligence,
            origin_intelligence
        )
    )

    # --------------------------------------------------------
    # COMPLETE CHAIN OF CUSTODY
    # --------------------------------------------------------

    try:

        chain_of_custody = (
            complete_analysis_event(
                chain_of_custody
            )
        )

    except Exception as error:

        if isinstance(
            chain_of_custody,
            dict
        ):

            chain_of_custody[
                "completion_error"
            ] = str(error)

    # --------------------------------------------------------
    # INTEGRITY VERIFICATION
    # --------------------------------------------------------

    try:

        integrity_verification = (
            verify_evidence_integrity(
                evidence_hash,
                email_bytes
            )
        )

    except Exception as error:

        integrity_verification = {
            "status": "ERROR",
            "match": False,
            "original_hash": evidence_hash,
            "current_hash": None,
            "message": str(error)
        }

    # --------------------------------------------------------
    # CUSTODY SUMMARY
    # --------------------------------------------------------

    try:

        custody_summary = (
            generate_custody_summary(
                chain_of_custody
            )
        )

    except Exception:

        custody_summary = {
            "case_id": chain_of_custody.get(
                "case_id"
            )
            if isinstance(
                chain_of_custody,
                dict
            )
            else None,

            "evidence_id": chain_of_custody.get(
                "evidence_id"
            )
            if isinstance(
                chain_of_custody,
                dict
            )
            else evidence_data[
                "evidence_id"
            ],

            "sha256": evidence_hash,

            "integrity_status": (
                integrity_verification.get(
                    "status"
                )
            )
        }

    # --------------------------------------------------------
    # ANALYSIS COMPLETION
    # --------------------------------------------------------

    analysis_completed = utc_now()

    # --------------------------------------------------------
    # NORMALIZE THREAT SCORE
    # --------------------------------------------------------

    threat_score = 0

    if isinstance(
        threat_analysis,
        dict
    ):

        for key in [
            "threat_score",
            "fraud_score",
            "score"
        ]:

            value = threat_analysis.get(
                key
            )

            try:

                if value is not None:
                    threat_score = max(
                        threat_score,
                        float(value)
                    )

            except Exception:
                pass

    # --------------------------------------------------------
    # FINAL RESPONSE
    # --------------------------------------------------------

    response = {

        "platform": PLATFORM_NAME,

        "problem_statement": PROBLEM_STATEMENT,

        "project": PROJECT_NAME,

        "status": "ANALYZED",

        "analysis_started_at": (
            analysis_started
        ),

        "analysis_completed_at": (
            analysis_completed
        ),

        # ====================================================
        # EVIDENCE
        # ====================================================

        "evidence": evidence_data,

        "chain_of_custody": (
            chain_of_custody
        ),

        "custody_summary": (
            custody_summary
        ),

        "integrity_verification": (
            integrity_verification
        ),

        # ====================================================
        # EMAIL
        # ====================================================

        "headers": headers,

        "body": {
            "plain": body_data.get(
                "plain",
                ""
            ),

            "html": body_data.get(
                "html",
                ""
            )
        },

        # ====================================================
        # FORENSICS
        # ====================================================

        "forensics": forensic_data,

        # ====================================================
        # HEADER ANALYSIS
        # ====================================================

        "header_analysis": (
            header_analysis
        ),

        # ====================================================
        # THREAT
        # ====================================================

        "threat_analysis": (
            threat_analysis
        ),

        "threat_score": threat_score,

        # ====================================================
        # IP
        # ====================================================

        "ip_intelligence": (
            ip_intelligence
        ),

        # ====================================================
        # GEOIP
        # ====================================================

        "geoip_intelligence": (
            geoip_intelligence
        ),

        # ====================================================
        # NETWORK
        # ====================================================

        "network_anonymization": (
            network_anonymization
        ),

        # ====================================================
        # ORIGIN
        # ====================================================

        "origin_intelligence": (
            origin_intelligence
        ),

        # ====================================================
        # DOMAIN
        # ====================================================

        "domain_intelligence": (
            domain_intelligence
        ),

        # ====================================================
        # URL
        # ====================================================

        "url_analysis": (
            url_analysis
        ),

        "url_intelligence": (
            url_analysis
        ),

        # ====================================================
        # ATTACHMENTS
        # ====================================================

        "attachment_analysis": (
            attachment_analysis
        ),

        # ====================================================
        # CORRELATION
        # ====================================================

        "correlation": (
            correlation
        ),

        "correlation_analysis": (
            correlation
        ),

        # ====================================================
        # INFRASTRUCTURE
        # ====================================================

        "infrastructure_graph": (
            infrastructure_graph
        ),

        # ====================================================
        # RELAY
        # ====================================================

        "relay_analysis": (
            received_analysis
        ),

        # ====================================================
        # EXTRACTION SUMMARY
        # ====================================================

        "extraction": {

            "ip_count": len(
                ip_addresses
            ),

            "domain_count": len(
                domains
            ),

            "url_count": len(
                extract_urls_from_text(
                    combined_body
                )
            ),

            "attachment_count": (
                attachment_analysis.get(
                    "total",
                    0
                )
                if isinstance(
                    attachment_analysis,
                    dict
                )
                else 0
            ),

            "received_count": len(
                received_analysis.get(
                    "received_headers",
                    []
                )
            )
        },

        # ====================================================
        # ENGINE STATUS
        # ====================================================

        "engines": {

            "header_forensics": "ENABLED",

            "threat_analysis": "ENABLED",

            "ip_intelligence": "ENABLED",

            "geoip": "ENABLED",

            "network_anonymization": (
                "ENABLED"
                if NETWORK_ANONYMIZATION_AVAILABLE
                else "UNAVAILABLE"
            ),

            "origin_intelligence": "ENABLED",

            "domain_intelligence": "ENABLED",

            "url_intelligence": "ENABLED",

            "attachment_analysis": "ENABLED",

            "correlation_analysis": "ENABLED",

            "infrastructure_graph": "ENABLED",

            "evidence_preservation": "ENABLED",

            "chain_of_custody": "ENABLED"
        },

        "timestamp": utc_now()
    }

    return jsonify(
        response
    )


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(413)
def request_too_large(error):

    return error_response(
        "Email file exceeds the 25 MB upload limit.",
        413
    )


@app.errorhandler(404)
def not_found(error):

    return error_response(
        "Endpoint not found.",
        404
    )


@app.errorhandler(500)
def internal_error(error):

    return error_response(
        "Internal forensic processing error.",
        500
    )
@app.post("/generate-report")
def generate_report():
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "ERROR",
                "message": "No forensic analysis data received."
            }), 400

        report_html = generate_forensic_report(data)
        filename = generate_report_filename(data)

        return jsonify({
            "status": "SUCCESS",
            "filename": filename,
            "report": report_html
        })

    except Exception as error:
        return jsonify({
            "status": "ERROR",
            "message": f"Report generation failed: {str(error)}"
        }), 500


# ============================================================
# STARTUP
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 58)
    print("              TARVEX26 FORENSICS")
    print("=" * 58)

    print(
        f"SIH Problem Statement : {PROBLEM_STATEMENT}"
    )

    print(
        "Status                : ONLINE"
    )

    print(
        "Endpoint              : /analyze-email"
    )

    print(
        "Header Forensics      : ENABLED"
    )

    print(
        "Threat Analysis       : ENABLED"
    )

    print(
        "IP Intelligence       : ENABLED"
    )

    print(
        "GeoIP Intelligence    : ENABLED"
    )

    print(
        "Network Intelligence  : "
        + (
            "ENABLED"
            if NETWORK_ANONYMIZATION_AVAILABLE
            else "UNAVAILABLE"
        )
    )

    print(
        "Origin Intelligence   : ENABLED"
    )

    print(
        "Domain Intelligence   : ENABLED"
    )

    print(
        "URL Intelligence      : ENABLED"
    )

    print(
        "Attachment Analysis   : ENABLED"
    )

    print(
        "Correlation Analysis  : ENABLED"
    )

    print(
        "Infrastructure Graph  : ENABLED"
    )

    print(
        "Evidence Preservation : ENABLED"
    )

    print(
        "Chain of Custody      : ENABLED"
    )

    print("=" * 58)
    print()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )