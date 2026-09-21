"""
TARVEX26
AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

SIH26106 - Email Forensics
Backend: Flask

Pipeline:
    .eml upload
        ↓
    Evidence Preservation
        ↓
    Email Parsing
        ↓
    Header Forensics
        ↓
    Threat / NLP Analysis
        ↓
    URL Intelligence
        ↓
    Attachment Forensics
        ↓
    IP Intelligence
        ↓
    Domain Intelligence
        ↓
    Origin Intelligence
        ↓
    GeoIP Intelligence
        ↓
    Infrastructure Correlation
        ↓
    TARVEX26 Forensic Result
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

from email import policy
from email.parser import BytesParser

import hashlib
import uuid
from datetime import datetime, timezone


# ============================================================
# FORENSIC MODULES
# ============================================================

from forensic.header_analyzer import analyze_headers
from forensic.ip_intelligence import analyze_ips
from forensic.threat_analyzer import analyze_threat
from forensic.origin_intelligence import analyze_origin
from forensic.geoip_analyzer import analyze_ips as analyze_geoip_ips
from forensic.correlation_analyzer import analyze_correlation
from forensic.infrastructure_correlator import build_infrastructure_graph
from forensic.url_intelligence import analyze_urls
from forensic.attachment_analyzer import analyze_attachments
from forensic.domain_intelligence import analyze_domain


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(
    __name__,
    template_folder="templates"
)

CORS(app)


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe_string(value):
    """
    Convert values safely into strings.
    """

    if value is None:
        return ""

    if isinstance(value, bytes):

        try:
            return value.decode(
                "utf-8",
                errors="replace"
            )

        except Exception:
            return ""

    return str(value)


def unique_list(items):
    """
    Preserve order while removing duplicates.
    """

    result = []

    seen = set()

    for item in items:

        if item is None:
            continue

        value = safe_string(item).strip()

        if not value:
            continue

        if value not in seen:

            seen.add(value)

            result.append(value)

    return result


def extract_headers(message):
    """
    Extract important email headers into a normal dictionary.
    """

    return {

        "from":
            message.get("From"),

        "to":
            message.get("To"),

        "cc":
            message.get("Cc"),

        "bcc":
            message.get("Bcc"),

        "subject":
            message.get("Subject"),

        "date":
            message.get("Date"),

        "reply_to":
            message.get("Reply-To"),

        "return_path":
            message.get("Return-Path"),

        "message_id":
            message.get("Message-ID"),

        "authentication_results":
            message.get("Authentication-Results"),

        "received_spf":
            message.get("Received-SPF"),

        "dkim_signature":
            message.get("DKIM-Signature"),

        "arc_authentication_results":
            message.get("ARC-Authentication-Results"),

        "arc_seal":
            message.get("ARC-Seal"),

        "mime_version":
            message.get("MIME-Version"),

        "content_type":
            message.get("Content-Type"),

        "x_mailer":
            message.get("X-Mailer"),

        "user_agent":
            message.get("User-Agent"),
    }


def extract_received_headers(message):
    """
    Extract all Received headers.

    Email systems normally append Received headers as the
    message moves through mail infrastructure.
    """

    try:

        values = message.get_all(
            "Received",
            []
        )

        return [
            safe_string(value)
            for value in values
            if safe_string(value).strip()
        ]

    except Exception:

        return []


def extract_email_body(message):
    """
    Extract plain text and HTML body content.
    """

    parts = []

    try:

        if message.is_multipart():

            for part in message.walk():

                content_type = (
                    part.get_content_type()
                )

                disposition = (
                    part.get_content_disposition()
                )

                if disposition == "attachment":
                    continue

                if content_type not in (
                    "text/plain",
                    "text/html"
                ):
                    continue

                try:

                    content = part.get_content()

                except Exception:

                    payload = part.get_payload(
                        decode=True
                    )

                    content = safe_string(
                        payload
                    )

                content = safe_string(
                    content
                )

                if content_type == "text/html":

                    import re

                    content = re.sub(
                        r"<[^>]+>",
                        " ",
                        content
                    )

                if content.strip():

                    parts.append(
                        content.strip()
                    )

        else:

            try:

                content = message.get_content()

            except Exception:

                payload = message.get_payload(
                    decode=True
                )

                content = safe_string(
                    payload
                )

            parts.append(
                safe_string(content)
            )

    except Exception:

        try:

            payload = message.get_payload(
                decode=True
            )

            if payload:

                parts.append(
                    safe_string(payload)
                )

        except Exception:
            pass

    return "\n\n".join(
        part for part in parts if part
    )


def extract_domains(forensic_data):
    """
    Collect domains already discovered by header analysis.

    Additional domains are collected from:
    - sender
    - Reply-To
    - Return-Path
    - Message-ID
    - relay infrastructure
    """

    domains = []

    existing = forensic_data.get(
        "domains",
        []
    )

    if isinstance(existing, list):

        domains.extend(existing)

    sender_domain = (
        forensic_data.get(
            "sender_domain"
        )
    )

    if sender_domain:
        domains.append(sender_domain)

    reply_domain = (
        forensic_data.get(
            "reply_to_domain"
        )
    )

    if reply_domain:
        domains.append(reply_domain)

    relay_analysis = forensic_data.get(
        "relay_analysis",
        {}
    )

    if isinstance(
        relay_analysis,
        dict
    ):

        relay_domains = (
            relay_analysis.get(
                "domains",
                []
            )
        )

        if isinstance(
            relay_domains,
            list
        ):

            domains.extend(
                relay_domains
            )

    return unique_list(
        domains
    )


def run_domain_intelligence(domains):
    """
    Analyze every discovered domain.

    Each domain is isolated so one failed DNS/RDAP request
    does not break the complete email investigation.
    """

    results = {}

    for domain in domains:

        try:

            results[domain] = (
                analyze_domain(domain)
            )

        except Exception as error:

            results[domain] = {

                "domain":
                    domain,

                "status":
                    "ERROR",

                "error":
                    str(error),

                "findings": [
                    "Domain intelligence analysis failed"
                ],

                "engine": {

                    "name":
                        "TARVEX26 Domain Intelligence Engine",

                    "version":
                        "1.0",

                    "status":
                        "ERROR"
                }
            }

    return results


def collect_domain_findings(domain_intelligence):
    """
    Flatten important domain findings so they can be
    displayed in the forensic findings section.
    """

    findings = []

    for domain, result in (
        domain_intelligence.items()
    ):

        if not isinstance(
            result,
            dict
        ):
            continue

        result_findings = result.get(
            "findings",
            []
        )

        if isinstance(
            result_findings,
            list
        ):

            for finding in result_findings:

                findings.append(
                    f"{domain}: {finding}"
                )

    return unique_list(
        findings
    )


# ============================================================
# HEALTH ENDPOINT
# ============================================================

@app.route(
    "/health",
    methods=["GET"]
)
def health():

    return jsonify({

        "platform":
            "TARVEX26",

        "problem_statement":
            "SIH26106",

        "project":
            "AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform",

        "status":
            "ONLINE",

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat()
    })


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.route(
    "/",
    methods=["GET"]
)
def home():

    return jsonify({

        "platform":
            "TARVEX26",

        "project":
            "SIH26106 Email Forensics",

        "status":
            "ONLINE",

        "endpoint":
            "/analyze-email",

        "capabilities": [

            "Email Parsing",

            "Digital Evidence Preservation",

            "Header Forensics",

            "SPF Analysis",

            "DKIM Analysis",

            "DMARC Analysis",

            "Threat Detection",

            "NLP Feature Analysis",

            "URL Intelligence",

            "Attachment Forensics",

            "IP Intelligence",

            "Domain Intelligence",

            "DNS Analysis",

            "MX Analysis",

            "RDAP Intelligence",

            "GeoIP Intelligence",

            "Origin Intelligence",

            "Infrastructure Correlation",

            "Graph-Based Investigation"
        ]
    })


# ============================================================
# ANALYZE EMAIL
# ============================================================

@app.route(
    "/analyze-email",
    methods=["POST"]
)
def analyze_email():

    # --------------------------------------------------------
    # FILE VALIDATION
    # --------------------------------------------------------

    if "email" not in request.files:

        return jsonify({

            "status":
                "ERROR",

            "error":
                "No email file uploaded"
        }), 400

    email_file = (
        request.files["email"]
    )

    if not email_file.filename:

        return jsonify({

            "status":
                "ERROR",

            "error":
                "No filename supplied"
        }), 400

    if not email_file.filename.lower().endswith(
        ".eml"
    ):

        return jsonify({

            "status":
                "ERROR",

            "error":
                "Only .eml email files are supported"
        }), 400


    try:

        # ====================================================
        # 1. READ RAW EMAIL
        # ====================================================

        email_bytes = (
            email_file.read()
        )

        if not email_bytes:

            return jsonify({

                "status":
                    "ERROR",

                "error":
                    "Uploaded email file is empty"
            }), 400


        # ====================================================
        # 2. DIGITAL EVIDENCE PRESERVATION
        # ====================================================

        evidence_hash = hashlib.sha256(
            email_bytes
        ).hexdigest()

        evidence_data = {

            "evidence_id":
                (
                    f"TRX-"
                    f"{datetime.now().strftime('%Y%m%d')}-"
                    f"{uuid.uuid4().hex[:8].upper()}"
                ),

            "filename":
                email_file.filename,

            "file_size":
                len(email_bytes),

            "sha256":
                evidence_hash,

            "evidence_type":
                "EMAIL",

            "status":
                "PRESERVED",

            "preserved_at":
                datetime.now(
                    timezone.utc
                ).isoformat()
        }


        # ====================================================
        # 3. PARSE EMAIL
        # ====================================================

        message = BytesParser(
            policy=policy.default
        ).parsebytes(
            email_bytes
        )


        # ====================================================
        # 4. BASIC EMAIL HEADERS
        # ====================================================

        headers = extract_headers(
            message
        )

        received_headers = (
            extract_received_headers(
                message
            )
        )


        # ====================================================
        # 5. EMAIL BODY
        # ====================================================

        email_body = (
            extract_email_body(
                message
            )
        )


        # ====================================================
        # 6. HEADER FORENSICS
        # ====================================================

        try:

            forensic_data = (
                analyze_headers(
                    headers
                )
            )

        except Exception as error:

            forensic_data = {

                "ip_addresses": [],

                "domains": [],

                "authentication_results": [],

                "findings": [
                    f"Header analysis error: {str(error)}"
                ],

                "relay_analysis": {
                    "domains": []
                }
            }


        if not isinstance(
            forensic_data,
            dict
        ):

            forensic_data = {}


        # ====================================================
        # 7. THREAT / NLP ANALYSIS
        # ====================================================

        try:

            threat_analysis = (
                analyze_threat(
                    message,
                    headers
                )
            )

        except Exception as error:

            threat_analysis = {

                "classification":
                    "UNKNOWN",

                "threat_score":
                    0,

                "fraud_score":
                    0,

                "score":
                    0,

                "risk_level":
                    "UNKNOWN",

                "confidence":
                    0,

                "summary":
                    "Threat analysis could not be completed.",

                "indicators": [
                    f"Threat analysis error: {str(error)}"
                ]
            }


        # ====================================================
        # 8. URL INTELLIGENCE
        # ====================================================

        try:

            url_analysis = (
                analyze_urls(
                    email_body
                )
            )

        except Exception as error:

            url_analysis = {

                "urls": [],

                "suspicious_urls": [],

                "findings": [
                    f"URL analysis error: {str(error)}"
                ],

                "risk_level":
                    "UNKNOWN"
            }


        # ====================================================
        # 9. ATTACHMENT FORENSICS
        # ====================================================

        try:

            attachment_analysis = (
                analyze_attachments(
                    message
                )
            )

        except Exception as error:

            attachment_analysis = {

                "total":
                    0,

                "attachments":
                    [],

                "suspicious_count":
                    0,

                "suspicious_files":
                    [],

                "findings": [
                    f"Attachment analysis error: {str(error)}"
                ],

                "risk_level":
                    "UNKNOWN"
            }


        # ====================================================
        # 10. IP INTELLIGENCE
        # ====================================================

        try:
            ip_intelligence = (
    analyze_ips(
        forensic_data.get(
            "ip_addresses",
            []
        )
    )
)

        except Exception as error:

            ip_intelligence = {

                "ip_addresses":
                    forensic_data.get(
                        "ip_addresses",
                        []
                    ),

                "findings": [
                    f"IP intelligence error: {str(error)}"
                ],

                "status":
                    "ERROR"
            }


        # ====================================================
        # 11. DOMAIN EXTRACTION
        # ====================================================

        domains = extract_domains(
            forensic_data
        )

        # Make sure the clean domain list is returned
        # for the existing TARVEX26 frontend.

        forensic_data["domains"] = domains


        # ====================================================
        # 12. DOMAIN INTELLIGENCE
        # ====================================================

        domain_intelligence = (
            run_domain_intelligence(
                domains
            )
        )

        domain_findings = (
            collect_domain_findings(
                domain_intelligence
            )
        )


        # Add domain findings to the existing
        # forensic findings list.

        existing_findings = (
            forensic_data.get(
                "findings",
                []
            )
        )

        if not isinstance(
            existing_findings,
            list
        ):

            existing_findings = []

        forensic_data["findings"] = (
            unique_list(
                existing_findings
                + domain_findings
            )
        )


        # ====================================================
        # 13. ORIGIN INTELLIGENCE
        # ====================================================

        try:

            origin_intelligence = (
                analyze_origin(
                    forensic_data
                )
            )

        except Exception as error:

            origin_intelligence = {

                "status":
                    "ERROR",

                "findings": [
                    f"Origin intelligence error: {str(error)}"
                ]
            }


        # ====================================================
        # 14. GEOIP INTELLIGENCE
        # ====================================================

        try:

            geoip_intelligence = (
                analyze_geoip_ips(
                    forensic_data
                )
            )

        except Exception as error:

            geoip_intelligence = {

                "results":
                    [],

                "findings": [
                    f"GeoIP analysis error: {str(error)}"
                ],

                "status":
                    "ERROR"
            }


        # ====================================================
        # 15. CORRELATION ANALYSIS
        # ====================================================

        try:

            correlation = (
                analyze_correlation(
                    forensic_data,
                    ip_intelligence,
                    origin_intelligence
                )
            )

        except TypeError:

            try:

                correlation = (
                    analyze_correlation(
                        forensic_data
                    )
                )

            except Exception as error:

                correlation = {

                    "status":
                        "ERROR",

                    "findings": [
                        f"Correlation analysis error: {str(error)}"
                    ]
                }

        except Exception as error:

            correlation = {

                "status":
                    "ERROR",

                "findings": [
                    f"Correlation analysis error: {str(error)}"
                ]
            }


        # ====================================================
        # 16. INFRASTRUCTURE GRAPH
        # ====================================================

        try:

            infrastructure_graph = (
                build_infrastructure_graph(
                    headers,
                    forensic_data,
                    ip_intelligence,
                    origin_intelligence
                )
            )

        except Exception as error:

            infrastructure_graph = {

                "nodes": [],

                "relationships": [],

                "node_count":
                    0,

                "relationship_count":
                    0,

                "findings": [
                    f"Infrastructure graph error: {str(error)}"
                ]
            }


        # ====================================================
        # 17. ADD DOMAIN NODES TO GRAPH IF NECESSARY
        # ====================================================

        if isinstance(
            infrastructure_graph,
            dict
        ):

            nodes = infrastructure_graph.get(
                "nodes",
                []
            )

            relationships = infrastructure_graph.get(
                "relationships",
                []
            )

            existing_node_ids = {
                node.get("id")
                for node in nodes
                if isinstance(node, dict)
            }

            for domain in domains:

                node_id = (
                    f"domain-intel:{domain}"
                )

                if node_id not in existing_node_ids:

                    nodes.append({

                        "id":
                            node_id,

                        "type":
                            "domain-intelligence",

                        "label":
                            domain
                    })

            infrastructure_graph["nodes"] = nodes

            infrastructure_graph["relationships"] = (
                relationships
            )

            infrastructure_graph["node_count"] = (
                len(nodes)
            )

            infrastructure_graph["relationship_count"] = (
                len(relationships)
            )


        # ====================================================
        # 18. DOMAIN SUMMARY
        # ====================================================

        domain_summary = {

            "total_domains":
                len(domains),

            "analyzed_domains":
                len(domain_intelligence),

            "domains":
                domains,

            "results":
                domain_intelligence,

            "findings":
                domain_findings,

            "engine": {

                "name":
                    "TARVEX26 Domain Intelligence Engine",

                "version":
                    "1.0",

                "capabilities": [

                    "DNS analysis",

                    "DNS A records",

                    "DNS AAAA records",

                    "DNS MX records",

                    "DNS NS records",

                    "DNS TXT records",

                    "SPF analysis",

                    "DMARC analysis",

                    "DKIM selector intelligence",

                    "RDAP registration intelligence"
                ]
            }
        }


        # ====================================================
        # 19. FORENSIC PIPELINE SUMMARY
        # ====================================================

        pipeline_status = {

            "email_parsing":
                "ENABLED",

            "evidence_preservation":
                "ENABLED",

            "header_forensics":
                "ENABLED",

            "threat_detection":
                "ENABLED",

            "url_intelligence":
                "ENABLED",

            "attachment_analysis":
                "ENABLED",

            "ip_intelligence":
                "ENABLED",

            "domain_intelligence":
                "ENABLED",

            "geoip_intelligence":
                "ENABLED",

            "origin_intelligence":
                "ENABLED",

            "infrastructure_correlation":
                "ENABLED",

            "graph_analysis":
                "ENABLED"
        }


        # ====================================================
        # 20. FINAL RESPONSE
        # ====================================================

        return jsonify({

            "status":
                "SUCCESS",

            "platform":
                "TARVEX26",

            "problem_statement":
                "SIH26106",

            "project":
                "AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform",

            # ------------------------------------------------
            # DIGITAL EVIDENCE
            # ------------------------------------------------

            "evidence":
                evidence_data,

            # ------------------------------------------------
            # BASIC EMAIL DATA
            # ------------------------------------------------

            "headers":
                headers,

            "body":
                email_body,

            "received_headers":
                received_headers,

            # ------------------------------------------------
            # FORENSICS
            # ------------------------------------------------

            "forensics":
                forensic_data,

            # ------------------------------------------------
            # THREAT
            # ------------------------------------------------

            "threat_analysis":
                threat_analysis,

            # ------------------------------------------------
            # URL
            # ------------------------------------------------

            "url_intelligence":
                url_analysis,

            # ------------------------------------------------
            # ATTACHMENTS
            # ------------------------------------------------

            "attachment_analysis":
                attachment_analysis,

            # ------------------------------------------------
            # IP
            # ------------------------------------------------

            "ip_intelligence":
                ip_intelligence,

            # ------------------------------------------------
            # DOMAIN
            # ------------------------------------------------

            "domain_intelligence":
                domain_summary,

            # ------------------------------------------------
            # ORIGIN
            # ------------------------------------------------

            "origin_intelligence":
                origin_intelligence,

            # ------------------------------------------------
            # GEOLOCATION
            # ------------------------------------------------

            "geoip_intelligence":
                geoip_intelligence,

            # ------------------------------------------------
            # CORRELATION
            # ------------------------------------------------

            "correlation":
                correlation,

            # ------------------------------------------------
            # INFRASTRUCTURE GRAPH
            # ------------------------------------------------

            "infrastructure_graph":
                infrastructure_graph,

            # ------------------------------------------------
            # PIPELINE STATUS
            # ------------------------------------------------

            "pipeline_status":
                pipeline_status,

            # ------------------------------------------------
            # ANALYSIS TIMESTAMP
            # ------------------------------------------------

            "analyzed_at":
                datetime.now(
                    timezone.utc
                ).isoformat()
        })


    # ========================================================
    # ERROR HANDLING
    # ========================================================

    except Exception as error:

        return jsonify({

            "status":
                "ERROR",

            "platform":
                "TARVEX26",

            "problem_statement":
                "SIH26106",

            "error":
                str(error),

            "message":
                "Email forensic analysis failed."
        }), 500


# ============================================================
# STARTUP
# ============================================================

if __name__ == "__main__":

    print(
        "\n"
        "===============================================\n"
        "              TARVEX26 FORENSICS\n"
        "===============================================\n"
        " SIH Problem Statement : SIH26106\n"
        " Status                : ONLINE\n"
        " Endpoint              : /analyze-email\n"
        " Domain Intelligence   : ENABLED\n"
        " URL Intelligence      : ENABLED\n"
        " Attachment Analysis   : ENABLED\n"
        " IP Intelligence       : ENABLED\n"
        " GeoIP Intelligence    : ENABLED\n"
        " Infrastructure Graph  : ENABLED\n"
        " Evidence Preservation : ENABLED\n"
        "===============================================\n"
    )

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )