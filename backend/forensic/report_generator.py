"""
TARVEX26
Forensic Report Generator
SIH26106 - AI-Powered Email Threat Detection,
GeoLocation and Forensic Intelligence Platform

Generates a structured HTML forensic investigation report
from the complete TARVEX26 analysis response.
"""

from datetime import datetime
from html import escape
import json


# ============================================================
# SAFE HELPERS
# ============================================================

def safe(value, default="N/A"):
    """Return a safe display value."""
    if value is None or value == "":
        return default

    if isinstance(value, bool):
        return "YES" if value else "NO"

    return str(value)


def get_nested(data, *keys, default="N/A"):
    """Safely retrieve nested dictionary values."""
    current = data

    for key in keys:
        if not isinstance(current, dict):
            return default

        current = current.get(key)

        if current is None:
            return default

    return current


def as_list(value):
    """Normalize a value into a list."""
    if value is None:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, tuple):
        return list(value)

    return [value]


def html_list(items, empty_text="No findings available."):
    """Create an HTML unordered list."""
    items = as_list(items)

    if not items:
        return f"<p class='muted'>{escape(empty_text)}</p>"

    output = "<ul>"

    for item in items:
        if isinstance(item, dict):
            text = json.dumps(item, indent=2, default=str)
        else:
            text = str(item)

        output += f"<li>{escape(text)}</li>"

    output += "</ul>"

    return output


def format_timestamp(value=None):
    """Create a readable timestamp."""
    if value:
        return safe(value)

    return datetime.now().astimezone().strftime(
        "%d %b %Y, %I:%M:%S %p"
    )


def risk_class(risk):
    """Return CSS class based on risk."""
    value = str(risk or "").upper()

    if value in {"CRITICAL", "HIGH", "MALICIOUS"}:
        return "danger"

    if value in {"MEDIUM", "SUSPICIOUS"}:
        return "warning"

    if value in {"LOW", "MINIMAL"}:
        return "safe"

    return "neutral"


# ============================================================
# SECTION BUILDERS
# ============================================================

def build_case_section(analysis):
    evidence = analysis.get("evidence", {})
    chain = analysis.get("chain_of_custody", {})

    case_id = (
        analysis.get("case_id")
        or chain.get("case_id")
        or evidence.get("case_id")
        or "N/A"
    )

    evidence_id = (
        evidence.get("evidence_id")
        or chain.get("evidence_id")
        or "N/A"
    )

    filename = evidence.get("filename", "N/A")
    file_size = evidence.get("file_size", "N/A")
    sha256 = evidence.get("sha256", "N/A")
    evidence_status = evidence.get("status", "N/A")

    return f"""
    <section class="section">
        <div class="section-title">
            <span class="section-number">01</span>
            <div>
                <span class="eyebrow">CASE IDENTIFICATION</span>
                <h2>Evidence & Case Information</h2>
            </div>
        </div>

        <div class="grid two">
            <div class="card">
                <span class="label">CASE ID</span>
                <strong>{escape(safe(case_id))}</strong>
            </div>

            <div class="card">
                <span class="label">EVIDENCE ID</span>
                <strong>{escape(safe(evidence_id))}</strong>
            </div>

            <div class="card">
                <span class="label">SOURCE FILE</span>
                <strong>{escape(safe(filename))}</strong>
            </div>

            <div class="card">
                <span class="label">FILE SIZE</span>
                <strong>{escape(safe(file_size))} bytes</strong>
            </div>

            <div class="card wide">
                <span class="label">SHA-256 EVIDENCE HASH</span>
                <code>{escape(safe(sha256))}</code>
            </div>

            <div class="card">
                <span class="label">EVIDENCE STATUS</span>
                <strong class="status">{escape(safe(evidence_status))}</strong>
            </div>
        </div>
    </section>
    """


def build_executive_section(analysis):
    threat = analysis.get("threat_analysis", {})

    classification = (
        threat.get("classification")
        or threat.get("label")
        or "UNKNOWN"
    )

    threat_score = (
        threat.get("threat_score")
        if threat.get("threat_score") is not None
        else threat.get("score", "N/A")
    )

    risk_level = (
        threat.get("risk_level")
        or threat.get("risk")
        or "UNKNOWN"
    )

    confidence = threat.get("confidence", "N/A")

    summary = (
        threat.get("summary")
        or "No automated threat summary was provided."
    )

    return f"""
    <section class="section">
        <div class="section-title">
            <span class="section-number">02</span>
            <div>
                <span class="eyebrow">EXECUTIVE ASSESSMENT</span>
                <h2>Threat Assessment</h2>
            </div>
        </div>

        <div class="assessment">
            <div class="score-box {risk_class(risk_level)}">
                <span>THREAT SCORE</span>
                <strong>{escape(safe(threat_score))}</strong>
                <small>/ 100</small>
            </div>

            <div class="assessment-info">
                <div>
                    <span class="label">CLASSIFICATION</span>
                    <strong>{escape(safe(classification))}</strong>
                </div>

                <div>
                    <span class="label">RISK LEVEL</span>
                    <strong>{escape(safe(risk_level))}</strong>
                </div>

                <div>
                    <span class="label">CONFIDENCE</span>
                    <strong>{escape(safe(confidence))}</strong>
                </div>
            </div>
        </div>

        <div class="summary">
            <span class="label">AUTOMATED SUMMARY</span>
            <p>{escape(safe(summary))}</p>
        </div>
    </section>
    """


def build_threat_section(analysis):
    threat = analysis.get("threat_analysis", {})

    indicators = threat.get("indicators", [])

    category_scores = threat.get("category_scores", {})

    phishing = threat.get("phishing_risk", "N/A")
    bec = threat.get("bec_risk", "N/A")
    spoofing = threat.get("spoofing_risk", "N/A")

    return f"""
    <section class="section">
        <div class="section-title">
            <span class="section-number">03</span>
            <div>
                <span class="eyebrow">AI THREAT DETECTION</span>
                <h2>Threat Indicators</h2>
            </div>
        </div>

        <div class="grid three">
            <div class="metric">
                <span>PHISHING RISK</span>
                <strong>{escape(safe(phishing))}</strong>
            </div>

            <div class="metric">
                <span>BEC RISK</span>
                <strong>{escape(safe(bec))}</strong>
            </div>

            <div class="metric">
                <span>SPOOFING RISK</span>
                <strong>{escape(safe(spoofing))}</strong>
            </div>
        </div>

        <div class="card">
            <span class="label">DETECTED INDICATORS</span>
            {html_list(indicators)}
        </div>

        <div class="card">
            <span class="label">CATEGORY SCORES</span>
            {html_list([
                f"{key}: {value}"
                for key, value in category_scores.items()
            ])}
        </div>
    </section>
    """


def build_header_section(analysis):
    headers = analysis.get("headers", {})

    authentication = headers.get(
        "authentication_results",
        {}
    )

    if not isinstance(authentication, dict):
        authentication = {}

    ip_addresses = headers.get("ip_addresses", [])
    domains = headers.get("domains", [])
    received = headers.get("received_headers", [])

    return f"""
    <section class="section">
        <div class="section-title">
            <span class="section-number">04</span>
            <div>
                <span class="eyebrow">HEADER FORENSICS</span>
                <h2>Email Header & Protocol Analysis</h2>
            </div>
        </div>

        <div class="grid two">
            <div class="card">
                <span class="label">FROM</span>
                <strong>{escape(safe(headers.get("from")))}</strong>
            </div>

            <div class="card">
                <span class="label">RETURN-PATH</span>
                <strong>{escape(safe(headers.get("return_path")))}</strong>
            </div>

            <div class="card">
                <span class="label">REPLY-TO</span>
                <strong>{escape(safe(headers.get("reply_to")))}</strong>
            </div>

            <div class="card">
                <span class="label">MESSAGE-ID</span>
                <strong>{escape(safe(headers.get("message_id")))}</strong>
            </div>
        </div>

        <div class="card">
            <span class="label">AUTHENTICATION RESULTS</span>

            <div class="auth-grid">
                <div>
                    <span>SPF</span>
                    <strong>{escape(safe(
                        authentication.get("spf")
                        or headers.get("spf")
                    ))}</strong>
                </div>

                <div>
                    <span>DKIM</span>
                    <strong>{escape(safe(
                        authentication.get("dkim")
                        or headers.get("dkim")
                    ))}</strong>
                </div>

                <div>
                    <span>DMARC</span>
                    <strong>{escape(safe(
                        authentication.get("dmarc")
                        or headers.get("dmarc")
                    ))}</strong>
                </div>
            </div>
        </div>

        <div class="card">
            <span class="label">EXTRACTED IP ADDRESSES</span>
            {html_list(ip_addresses, "No IP addresses extracted.")}
        </div>

        <div class="card">
            <span class="label">EXTRACTED DOMAINS</span>
            {html_list(domains, "No domains extracted.")}
        </div>

        <div class="card">
            <span class="label">RECEIVED / RELAY HEADERS</span>
            {html_list(received, "No Received headers available.")}
        </div>
    </section>
    """


def build_ip_section(analysis):
    ip_data = analysis.get("ip_intelligence", {})

    if not isinstance(ip_data, dict):
        ip_data = {}

    results = ip_data.get("results", [])

    cards = ""

    for item in results:
        if not isinstance(item, dict):
            continue

        ip = item.get("ip", "N/A")
        address_type = item.get("address_type", "N/A")
        version = item.get("version", "N/A")
        confidence = item.get("confidence", "N/A")

        reverse_dns = item.get("reverse_dns")
        reputation = item.get("reputation", {})

        if isinstance(reputation, dict):
            reputation_value = (
                reputation.get("reputation")
                or reputation.get("status")
                or "UNKNOWN"
            )
        else:
            reputation_value = reputation or "UNKNOWN"

        findings = item.get("findings", [])

        cards += f"""
        <div class="card">
            <div class="ip-header">
                <strong>{escape(safe(ip))}</strong>
                <span class="badge">{escape(safe(address_type))}</span>
            </div>

            <div class="grid two compact">
                <div>
                    <span class="label">IP VERSION</span>
                    <strong>{escape(safe(version))}</strong>
                </div>

                <div>
                    <span class="label">REPUTATION</span>
                    <strong>{escape(safe(reputation_value))}</strong>
                </div>

                <div>
                    <span class="label">REVERSE DNS</span>
                    <strong>{escape(safe(reverse_dns))}</strong>
                </div>

                <div>
                    <span class="label">CONFIDENCE</span>
                    <strong>{escape(safe(confidence))}</strong>
                </div>
            </div>

            {html_list(findings)}
        </div>
        """

    if not cards:
        cards = """
        <div class="empty">
            No IP intelligence results were available.
        </div>
        """

    return f"""
    <section class="section">
        <div class="section-title">
            <span class="section-number">05</span>
            <div>
                <span class="eyebrow">IP INTELLIGENCE</span>
                <h2>Infrastructure & Reputation Analysis</h2>
            </div>
        </div>

        <div class="grid two">
            {cards}
        </div>
    </section>
    """


def build_geoip_section(analysis):
    geo = analysis.get("geoip_intelligence", {})

    if not isinstance(geo, dict):
        geo = {}

    results = geo.get("results", [])

    cards = ""

    for item in results:
        if not isinstance(item, dict):
            continue

        cards += f"""
        <div class="card">
            <div class="ip-header">
                <strong>{escape(safe(item.get("ip")))}</strong>
                <span class="badge">{escape(
                    safe(item.get("type"))
                )}</span>
            </div>

            <div class="grid two compact">
                <div>
                    <span class="label">COUNTRY</span>
                    <strong>{escape(safe(item.get("country")))}</strong>
                </div>

                <div>
                    <span class="label">REGION</span>
                    <strong>{escape(safe(item.get("region")))}</strong>
                </div>

                <div>
                    <span class="label">CITY</span>
                    <strong>{escape(safe(item.get("city")))}</strong>
                </div>

                <div>
                    <span class="label">ISP</span>
                    <strong>{escape(safe(item.get("isp")))}</strong>
                </div>

                <div>
                    <span class="label">ORGANIZATION</span>
                    <strong>{escape(safe(
                        item.get("organization")
                    ))}</strong>
                </div>

                <div>
                    <span class="label">ASN</span>
                    <strong>{escape(safe(item.get("asn")))}</strong>
                </div>

                <div>
                    <span class="label">REVERSE DNS</span>
                    <strong>{escape(safe(
                        item.get("reverse_dns")
                    ))}</strong>
                </div>

                <div>
                    <span class="label">CONFIDENCE</span>
                    <strong>{escape(safe(
                        item.get("confidence")
                    ))}</strong>
                </div>
            </div>

            {html_list(item.get("findings", []))}
        </div>
        """

    if not cards:
        cards = """
        <div class="empty">
            No GeoIP intelligence results were available.
        </div>
        """

    return f"""
    <section class="section">
        <div class="section-title">
            <span class="section-number">06</span>
            <div>
                <span class="eyebrow">ORIGIN TRACEABILITY</span>
                <h2>Geolocation Intelligence</h2>
            </div>
        </div>

        <div class="grid two">
            {cards}
        </div>
    </section>
    """


def build_network_section(analysis):
    network = analysis.get("network_anonymization", {})

    if not isinstance(network, dict):
        network = {}

    metrics = [
        ("TOR", network.get("tor_count", 0)),
        ("VPN", network.get("vpn_count", 0)),
        ("PROXY", network.get("proxy_count", 0)),
        ("HOSTING", network.get("hosting_count", 0)),
        ("CLOUD", network.get("cloud_count", 0)),
    ]

    metric_html = ""

    for label, value in metrics:
        metric_html += f"""
        <div class="metric">
            <span>{escape(label)}</span>
            <strong>{escape(safe(value, "0"))}</strong>
            <small>DETECTED</small>
        </div>
        """

    findings = network.get("findings", [])

    return f"""
    <section class="section">
        <div class="section-title">
            <span class="section-number">07</span>
            <div>
                <span class="eyebrow">NETWORK ATTRIBUTION</span>
                <h2>Anonymization & Infrastructure Indicators</h2>
            </div>
        </div>

        <div class="grid five">
            {metric_html}
        </div>

        <div class="card">
            <span class="label">NETWORK FINDINGS</span>
            {html_list(findings)}
        </div>
    </section>
    """


def build_domain_section(analysis):
    domain = analysis.get("domain_intelligence", {})

    if not isinstance(domain, dict):
        domain = {}

    findings = domain.get("findings", [])

    registration = domain.get("registration", {})
    infrastructure = domain.get("infrastructure", {})

    return f"""
    <section class="section">
        <div class="section-title">
            <span class="section-number">08</span>
            <div>
                <span class="eyebrow">DOMAIN INTELLIGENCE</span>
                <h2>DNS, Registration & Infrastructure</h2>
            </div>
        </div>

        <div class="grid two">
            <div class="card">
                <span class="label">REGISTRATION</span>
                {html_list([
                    f"{key}: {value}"
                    for key, value in registration.items()
                ])}
            </div>

            <div class="card">
                <span class="label">INFRASTRUCTURE</span>
                {html_list([
                    f"{key}: {value}"
                    for key, value in infrastructure.items()
                ])}
            </div>
        </div>

        <div class="card">
            <span class="label">DOMAIN FINDINGS</span>
            {html_list(findings)}
        </div>
    </section>
    """


def build_url_section(analysis):
    urls = analysis.get("url_analysis", {})

    if not isinstance(urls, dict):
        urls = {}

    results = (
        urls.get("results")
        or urls.get("urls")
        or []
    )

    findings = urls.get("findings", [])

    return f"""
    <section class="section">
        <div class="section-title">
            <span class="section-number">09</span>
            <div>
                <span class="eyebrow">LINK FORENSICS</span>
                <h2>URL Intelligence</h2>
            </div>
        </div>

        <div class="card">
            <span class="label">ANALYZED URLS</span>
            {html_list(results, "No URLs were detected.")}
        </div>

        <div class="card">
            <span class="label">URL FINDINGS</span>
            {html_list(findings)}
        </div>
    </section>
    """


def build_attachment_section(analysis):
    attachments = analysis.get("attachment_analysis", {})

    if not isinstance(attachments, dict):
        attachments = {}

    results = attachments.get("attachments", [])
    findings = attachments.get("findings", [])
    risk_level = attachments.get("risk_level", "NONE")

    cards = ""

    for item in results:
        if not isinstance(item, dict):
            continue

        cards += f"""
        <div class="card">
            <div class="ip-header">
                <strong>{escape(safe(
                    item.get("filename")
                ))}</strong>

                <span class="badge">
                    {escape(safe(item.get("category")))}
                </span>
            </div>

            <div class="grid two compact">
                <div>
                    <span class="label">EXTENSION</span>
                    <strong>{escape(safe(
                        item.get("extension")
                    ))}</strong>
                </div>

                <div>
                    <span class="label">MIME TYPE</span>
                    <strong>{escape(safe(
                        item.get("content_type")
                    ))}</strong>
                </div>

                <div>
                    <span class="label">SIZE</span>
                    <strong>{escape(safe(
                        item.get("size_bytes")
                    ))} bytes</strong>
                </div>

                <div>
                    <span class="label">DOUBLE EXTENSION</span>
                    <strong>{escape(safe(
                        item.get("double_extension")
                    ))}</strong>
                </div>
            </div>

            {html_list(item.get("risks", []))}
        </div>
        """

    if not cards:
        cards = """
        <div class="empty">
            No attachments detected.
        </div>
        """

    return f"""
    <section class="section">
        <div class="section-title">
            <span class="section-number">10</span>
            <div>
                <span class="eyebrow">MALWARE DELIVERY ANALYSIS</span>
                <h2>Attachment Intelligence</h2>
            </div>
        </div>

        <div class="metric">
            <span>ATTACHMENT RISK</span>
            <strong>{escape(safe(risk_level))}</strong>
        </div>

        <div class="grid two">
            {cards}
        </div>

        <div class="card">
            <span class="label">ATTACHMENT FINDINGS</span>
            {html_list(findings)}
        </div>
    </section>
    """


def build_correlation_section(analysis):
    correlation = analysis.get("correlation", {})

    if not isinstance(correlation, dict):
        correlation = {}

    findings = correlation.get("findings", [])

    return f"""
    <section class="section">
        <div class="section-title">
            <span class="section-number">11</span>
            <div>
                <span class="eyebrow">IDENTITY CORRELATION</span>
                <h2>Threat & Infrastructure Correlation</h2>
            </div>
        </div>

        <div class="card">
            <span class="label">CORRELATION RESULTS</span>
            {html_list([
                f"{key}: {value}"
                for key, value in correlation.items()
                if key not in {"findings"}
                and not isinstance(value, (dict, list))
            ])}
        </div>

        <div class="card">
            <span class="label">CORRELATION FINDINGS</span>
            {html_list(findings)}
        </div>
    </section>
    """


def build_graph_section(analysis):
    graph = analysis.get("infrastructure_graph", {})

    if not isinstance(graph, dict):
        graph = {}

    nodes = graph.get("nodes", [])
    relationships = graph.get("relationships", [])

    return f"""
    <section class="section">
        <div class="section-title">
            <span class="section-number">12</span>
            <div>
                <span class="eyebrow">GRAPH FORENSICS</span>
                <h2>Infrastructure Correlation Graph</h2>
            </div>
        </div>

        <div class="grid two">
            <div class="metric">
                <span>NODES</span>
                <strong>{escape(safe(
                    graph.get("node_count", len(nodes))
                ))}</strong>
            </div>

            <div class="metric">
                <span>RELATIONSHIPS</span>
                <strong>{escape(safe(
                    graph.get(
                        "relationship_count",
                        len(relationships)
                    )
                ))}</strong>
            </div>
        </div>

        <div class="card">
            <span class="label">RELATIONSHIPS</span>
            {html_list([
                f"{item.get('source')} → "
                f"{item.get('target')} "
                f"[{item.get('type', 'RELATED')}]"
                for item in relationships
                if isinstance(item, dict)
            ], "No infrastructure relationships detected.")}
        </div>
    </section>
    """


def build_evidence_section(analysis):
    evidence = analysis.get("evidence", {})
    chain = analysis.get("chain_of_custody", {})

    verification = analysis.get(
        "evidence_integrity",
        {}
    )

    return f"""
    <section class="section">
        <div class="section-title">
            <span class="section-number">13</span>
            <div>
                <span class="eyebrow">DIGITAL EVIDENCE</span>
                <h2>Evidence Preservation</h2>
            </div>
        </div>

        <div class="grid two">
            <div class="card">
                <span class="label">EVIDENCE STATUS</span>
                <strong>{escape(safe(
                    evidence.get("status")
                ))}</strong>
            </div>

            <div class="card">
                <span class="label">INTEGRITY</span>
                <strong class="status">{escape(safe(
                    verification.get("status")
                    if isinstance(verification, dict)
                    else verification
                ))}</strong>
            </div>

            <div class="card wide">
                <span class="label">SHA-256</span>
                <code>{escape(safe(
                    evidence.get("sha256")
                ))}</code>
            </div>
        </div>

        <div class="card">
            <span class="label">CHAIN OF CUSTODY</span>

            <div class="timeline">
                {
                    "".join(
                        f'''
                        <div class="timeline-item">
                            <span>{escape(safe(
                                event.get("event_id")
                                or event.get("id")
                            ))}</span>
                            <strong>{escape(safe(
                                event.get("event")
                                or event.get("action")
                                or event.get("type")
                            ))}</strong>
                            <small>{escape(safe(
                                event.get("status")
                            ))}</small>
                        </div>
                        '''
                        for event in as_list(
                            chain.get("events", [])
                            if isinstance(chain, dict)
                            else []
                        )
                        if isinstance(event, dict)
                    )
                }
            </div>
        </div>
    </section>
    """


def build_conclusion_section(analysis):
    threat = analysis.get("threat_analysis", {})

    classification = (
        threat.get("classification")
        or "UNKNOWN"
    )

    risk = (
        threat.get("risk_level")
        or "UNKNOWN"
    )

    confidence = threat.get(
        "confidence",
        "N/A"
    )

    return f"""
    <section class="section final-section">
        <div class="section-title">
            <span class="section-number">14</span>
            <div>
                <span class="eyebrow">FORENSIC ASSESSMENT</span>
                <h2>Investigation Summary</h2>
            </div>
        </div>

        <div class="conclusion">
            <div>
                <span class="label">CLASSIFICATION</span>
                <strong>{escape(safe(classification))}</strong>
            </div>

            <div>
                <span class="label">RISK</span>
                <strong>{escape(safe(risk))}</strong>
            </div>

            <div>
                <span class="label">CONFIDENCE</span>
                <strong>{escape(safe(confidence))}</strong>
            </div>
        </div>

        <div class="notice">
            <strong>FORENSIC LIMITATION</strong>

            <p>
                TARVEX26 provides evidence-based technical intelligence
                including header analysis, infrastructure correlation,
                IP intelligence, geolocation and threat indicators.
                Results represent investigative intelligence and should
                not be interpreted as definitive proof of an individual's
                identity without independent corroborating evidence.
            </p>
        </div>
    </section>
    """


# ============================================================
# COMPLETE HTML REPORT
# ============================================================

def generate_forensic_report(analysis):
    """
    Generate a complete standalone HTML forensic report.

    Parameters
    ----------
    analysis : dict
        Complete response generated by TARVEX26 /analyze-email.

    Returns
    -------
    str
        Standalone HTML report.
    """

    if not isinstance(analysis, dict):
        raise TypeError(
            "analysis must be a dictionary"
        )

    evidence = analysis.get("evidence", {})

    filename = safe(
        evidence.get("filename"),
        "Email Evidence"
    )

    generated_at = format_timestamp()

    threat = analysis.get(
        "threat_analysis",
        {}
    )

    risk_level = (
        threat.get("risk_level")
        or "UNKNOWN"
    )

    return f"""<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>
TARVEX26 Forensic Report
</title>

<style>

:root {{
    --bg: #03070d;
    --panel: #07111b;
    --panel2: #091722;
    --border: #12384b;
    --cyan: #00d9ff;
    --cyan2: #4de8ff;
    --text: #e8f7fb;
    --muted: #7893a0;
    --green: #19e6a2;
    --yellow: #ffd166;
    --red: #ff5c7a;
}}

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    background:
        radial-gradient(
            circle at top right,
            rgba(0,217,255,0.08),
            transparent 35%
        ),
        var(--bg);

    color: var(--text);

    font-family:
        Inter,
        Segoe UI,
        Arial,
        sans-serif;

    line-height: 1.6;
}}

.container {{
    width: min(1180px, 92%);
    margin: 0 auto;
}}

.header {{
    padding: 55px 0 35px;

    border-bottom:
        1px solid var(--border);
}}

.brand {{
    color: var(--cyan);
    font-size: 14px;
    font-weight: 800;
    letter-spacing: 4px;
}}

h1 {{
    margin: 8px 0;

    font-size: clamp(34px, 5vw, 60px);

    letter-spacing: -2px;
}}

.subtitle {{
    color: var(--muted);
    max-width: 760px;
}}

.report-meta {{
    margin-top: 25px;

    display: grid;

    grid-template-columns:
        repeat(auto-fit, minmax(180px, 1fr));

    gap: 12px;
}}

.meta {{
    background: var(--panel);
    border: 1px solid var(--border);
    padding: 16px;
    border-radius: 12px;
}}

.meta span {{
    display: block;
    color: var(--muted);
    font-size: 10px;
    letter-spacing: 1.5px;
    margin-bottom: 5px;
}}

.meta strong {{
    color: var(--cyan2);
}}

.section {{
    padding: 45px 0;

    border-bottom:
        1px solid rgba(18,56,75,0.65);
}}

.section-title {{
    display: flex;
    gap: 16px;
    align-items: center;
    margin-bottom: 25px;
}}

.section-number {{
    color: var(--cyan);
    font-weight: 900;
    font-size: 14px;
}}

.eyebrow {{
    display: block;

    color: var(--cyan);

    font-size: 10px;

    letter-spacing: 2px;

    font-weight: 800;
}}

h2 {{
    margin: 2px 0 0;

    font-size: 25px;
}}

.grid {{
    display: grid;
    gap: 14px;
}}

.grid.two {{
    grid-template-columns:
        repeat(auto-fit, minmax(280px, 1fr));
}}

.grid.three {{
    grid-template-columns:
        repeat(auto-fit, minmax(180px, 1fr));
}}

.grid.five {{
    grid-template-columns:
        repeat(auto-fit, minmax(130px, 1fr));
}}

.grid.compact {{
    gap: 10px;
}}

.card,
.metric,
.summary,
.assessment,
.notice,
.conclusion {{
    background:
        linear-gradient(
            145deg,
            rgba(7,17,27,0.95),
            rgba(9,23,34,0.88)
        );

    border:
        1px solid var(--border);

    border-radius: 14px;

    padding: 20px;
}}

.card.wide {{
    grid-column: 1 / -1;
}}

.label {{
    display: block;

    color: var(--muted);

    font-size: 10px;

    letter-spacing: 1.5px;

    font-weight: 800;

    margin-bottom: 7px;
}}

.card strong {{
    word-break: break-word;
}}

code {{
    display: block;

    color: var(--cyan2);

    font-family:
        Consolas,
        monospace;

    font-size: 12px;

    word-break: break-all;
}}

.status {{
    color: var(--green) !important;
}}

.metric {{
    text-align: center;
}}

.metric span {{
    display: block;

    color: var(--muted);

    font-size: 10px;

    letter-spacing: 1.5px;
}}

.metric strong {{
    display: block;

    margin-top: 5px;

    font-size: 25px;

    color: var(--cyan2);
}}

.metric small {{
    color: var(--muted);
    font-size: 9px;
}}

.assessment {{
    display: grid;

    grid-template-columns:
        190px 1fr;

    gap: 25px;

    align-items: center;
}}

.score-box {{
    border-radius: 14px;

    padding: 22px;

    text-align: center;

    border: 1px solid var(--border);
}}

.score-box span {{
    display: block;

    color: var(--muted);

    font-size: 10px;

    letter-spacing: 1px;
}}

.score-box strong {{
    display: block;

    font-size: 50px;
}}

.score-box small {{
    color: var(--muted);
}}

.score-box.danger {{
    border-color: rgba(255,92,122,0.5);
}}

.score-box.danger strong {{
    color: var(--red);
}}

.score-box.warning {{
    border-color: rgba(255,209,102,0.5);
}}

.score-box.warning strong {{
    color: var(--yellow);
}}

.score-box.safe strong {{
    color: var(--green);
}}

.assessment-info {{
    display: grid;

    grid-template-columns:
        repeat(auto-fit, minmax(160px, 1fr));

    gap: 18px;
}}

.summary {{
    margin-top: 14px;
}}

.summary p {{
    margin-bottom: 0;
    color: #c8d9df;
}}

.auth-grid {{
    display: grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap: 12px;
}}

.auth-grid div {{
    background: rgba(0,0,0,0.18);

    padding: 15px;

    border-radius: 10px;
}}

.auth-grid span {{
    display: block;

    color: var(--muted);

    font-size: 10px;

    letter-spacing: 1px;
}}

.auth-grid strong {{
    color: var(--cyan2);
}}

ul {{
    margin: 10px 0 0;
    padding-left: 20px;
}}

li {{
    margin: 7px 0;
    color: #bfd1d8;
}}

.muted {{
    color: var(--muted);
}}

.ip-header {{
    display: flex;

    align-items: center;

    justify-content: space-between;

    gap: 10px;

    margin-bottom: 20px;
}}

.ip-header strong {{
    color: var(--cyan2);
    font-size: 20px;
}}

.badge {{
    border: 1px solid var(--border);

    padding: 5px 9px;

    border-radius: 20px;

    color: var(--cyan);

    font-size: 9px;

    letter-spacing: 1px;
}}

.timeline {{
    display: grid;
    gap: 10px;
}}

.timeline-item {{
    display: grid;

    grid-template-columns:
        70px 1fr auto;

    gap: 12px;

    align-items: center;

    padding: 12px;

    border-left:
        2px solid var(--cyan);

    background: rgba(0,217,255,0.03);
}}

.timeline-item span {{
    color: var(--cyan);
    font-size: 11px;
}}

.timeline-item small {{
    color: var(--green);
}}

.conclusion {{
    display: grid;

    grid-template-columns:
        repeat(auto-fit, minmax(170px, 1fr));

    gap: 20px;
}}

.conclusion strong {{
    color: var(--cyan2);
    font-size: 20px;
}}

.notice {{
    margin-top: 15px;

    border-color:
        rgba(255,209,102,0.35);
}}

.notice strong {{
    color: var(--yellow);
}}

.notice p {{
    color: var(--muted);
    margin-bottom: 0;
}}

.empty {{
    padding: 30px;

    text-align: center;

    border:
        1px dashed var(--border);

    border-radius: 12px;

    color: var(--muted);
}}

.footer {{
    padding: 40px 0 70px;

    text-align: center;

    color: var(--muted);

    font-size: 11px;

    letter-spacing: 2px;
}}

@media (max-width: 700px) {{

    .assessment {{
        grid-template-columns: 1fr;
    }}

    .auth-grid {{
        grid-template-columns: 1fr;
    }}

    .timeline-item {{
        grid-template-columns: 1fr;
    }}

}}

@media print {{

    body {{
        background: white;
        color: black;
    }}

    .header,
    .section {{
        break-inside: avoid;
    }}

    .card,
    .metric,
    .summary,
    .assessment,
    .notice,
    .conclusion {{
        background: white;
        border-color: #ccc;
        color: black;
    }}

}}

</style>

</head>

<body>

<div class="container">

<header class="header">

    <div class="brand">
        TARVEX26 • SIH26106
    </div>

    <h1>
        Digital Email Forensic Report
    </h1>

    <p class="subtitle">
        AI-Powered Email Threat Detection,
        GeoLocation and Forensic Intelligence Platform
    </p>

    <div class="report-meta">

        <div class="meta">
            <span>EVIDENCE FILE</span>
            <strong>{escape(filename)}</strong>
        </div>

        <div class="meta">
            <span>GENERATED</span>
            <strong>{escape(generated_at)}</strong>
        </div>

        <div class="meta">
            <span>RISK LEVEL</span>
            <strong>{escape(safe(risk_level))}</strong>
        </div>

        <div class="meta">
            <span>ENGINE</span>
            <strong>TARVEX26</strong>
        </div>

    </div>

</header>

{build_case_section(analysis)}

{build_executive_section(analysis)}

{build_threat_section(analysis)}

{build_header_section(analysis)}

{build_ip_section(analysis)}

{build_geoip_section(analysis)}

{build_network_section(analysis)}

{build_domain_section(analysis)}

{build_url_section(analysis)}

{build_attachment_section(analysis)}

{build_correlation_section(analysis)}

{build_graph_section(analysis)}

{build_evidence_section(analysis)}

{build_conclusion_section(analysis)}

<footer class="footer">

    TARVEX26 • SIH26106 • EMAIL FORENSIC INTELLIGENCE

    <br><br>

    Generated for authorized cybersecurity investigation.

</footer>

</div>

</body>

</html>
"""


# ============================================================
# FILE NAME HELPER
# ============================================================

def generate_report_filename(analysis):
    """Generate a safe report filename."""

    evidence = analysis.get("evidence", {})

    evidence_id = evidence.get(
        "evidence_id",
        "TARVEX26"
    )

    clean_id = "".join(
        character
        for character in str(evidence_id)
        if character.isalnum() or character in "-_"
    )

    return f"TARVEX26_Forensic_Report_{clean_id}.html"


# ============================================================
# SIMPLE TEST
# ============================================================

if __name__ == "__main__":

    sample_analysis = {
        "evidence": {
            "evidence_id": "TRX-TEST-001",
            "filename": "forensic_test.eml",
            "file_size": 1747,
            "sha256": "TEST_SHA256_HASH",
            "status": "PRESERVED",
        },

        "threat_analysis": {
            "classification": "SUSPICIOUS",
            "threat_score": 83,
            "risk_level": "HIGH",
            "confidence": "HIGH",
            "summary": (
                "Suspicious email indicators detected."
            ),
            "indicators": [
                "Urgency language",
                "Credential verification request",
                "Suspicious URL",
            ],
            "phishing_risk": "HIGH",
            "bec_risk": "MEDIUM",
            "spoofing_risk": "HIGH",
            "category_scores": {
                "phishing": 80,
                "bec": 60,
                "spoofing": 75,
            },
        },

        "headers": {
            "from": "attacker@example.com",
            "return_path": "bounce@example.com",
            "reply_to": "reply@example.net",
            "message_id": "<test@example.com>",
            "ip_addresses": [
                "203.0.113.25"
            ],
            "domains": [
                "example.com"
            ],
            "authentication_results": {
                "spf": "NOT PRESENT",
                "dkim": "NOT PRESENT",
                "dmarc": "NOT PRESENT",
            },
            "received_headers": [],
        },

        "ip_intelligence": {
            "results": []
        },

        "geoip_intelligence": {
            "results": []
        },

        "network_anonymization": {
            "tor_count": 0,
            "vpn_count": 0,
            "proxy_count": 0,
            "hosting_count": 0,
            "cloud_count": 0,
            "findings": [],
        },

        "domain_intelligence": {
            "registration": {},
            "infrastructure": {},
            "findings": [],
        },

        "url_analysis": {
            "results": [],
            "findings": [],
        },

        "attachment_analysis": {
            "risk_level": "NONE",
            "attachments": [],
            "findings": [],
        },

        "correlation": {
            "findings": []
        },

        "infrastructure_graph": {
            "nodes": [],
            "relationships": [],
            "node_count": 0,
            "relationship_count": 0,
        },

        "chain_of_custody": {
            "events": []
        },

        "evidence_integrity": {
            "status": "VERIFIED"
        },
    }

    report = generate_forensic_report(
        sample_analysis
    )

    filename = generate_report_filename(
        sample_analysis
    )

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as report_file:

        report_file.write(report)

    print("=" * 60)
    print("TARVEX26 FORENSIC REPORT GENERATOR")
    print("=" * 60)
    print(f"Report generated : {filename}")
    print(f"Report size      : {len(report)} characters")
    print("Status           : SUCCESS")
    print("=" * 60)