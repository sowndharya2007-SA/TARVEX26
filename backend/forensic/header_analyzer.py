import re
from email import policy
from email.parser import BytesParser


# ---------------------------------------------------------
# Extract IPv4 addresses
# ---------------------------------------------------------

def extract_ip_addresses(text):
    if not text:
        return []

    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    ips = re.findall(pattern, text)

    valid_ips = []

    for ip in ips:
        parts = ip.split(".")

        if all(0 <= int(part) <= 255 for part in parts):
            if ip not in valid_ips:
                valid_ips.append(ip)

    return valid_ips


# ---------------------------------------------------------
# Extract domain names
# ---------------------------------------------------------

def extract_domains(text):
    if not text:
        return []

    pattern = (
        r"\b(?:[a-zA-Z0-9-]+\.)+"
        r"[a-zA-Z]{2,}\b"
    )

    matches = re.findall(pattern, text)

    domains = []

    for domain in matches:

        domain = domain.lower().strip(".")

        # Ignore obvious local/example addresses
        if domain not in domains:
            domains.append(domain)

    return domains


# ---------------------------------------------------------
# Authentication Results
# ---------------------------------------------------------

def extract_authentication_results(message):

    results = message.get_all(
        "Authentication-Results",
        []
    )

    return [
        str(result)
        for result in results
    ]


# ---------------------------------------------------------
# SPF / DKIM / DMARC
# ---------------------------------------------------------

def extract_authentication_status(authentication_results):

    text = " ".join(
        authentication_results
    ).lower()

    spf = "Not available"
    dkim = "Not available"
    dmarc = "Not available"

    if "spf=pass" in text:
        spf = "PASS"

    elif "spf=fail" in text:
        spf = "FAIL"

    elif "spf=softfail" in text:
        spf = "SOFTFAIL"

    elif "spf=neutral" in text:
        spf = "NEUTRAL"

    if "dkim=pass" in text:
        dkim = "PASS"

    elif "dkim=fail" in text:
        dkim = "FAIL"

    if "dmarc=pass" in text:
        dmarc = "PASS"

    elif "dmarc=fail" in text:
        dmarc = "FAIL"

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc
    }


# ---------------------------------------------------------
# Analyze Received headers
# ---------------------------------------------------------

def analyze_received_headers(received_headers):

    relay_data = []

    all_received_text = "\n".join(
        str(header)
        for header in received_headers
    )

    for header in received_headers:

        header_text = str(header)

        ips = extract_ip_addresses(
            header_text
        )

        domains = extract_domains(
            header_text
        )

        relay_data.append({
            "header": header_text,
            "ip_addresses": ips,
            "domains": domains
        })

    return {
        "relay_count": len(received_headers),
        "ip_addresses": extract_ip_addresses(
            all_received_text
        ),
        "domains": extract_domains(
            all_received_text
        ),
        "relays": relay_data
    }


# ---------------------------------------------------------
# Basic forensic findings
# ---------------------------------------------------------

def generate_findings(
    message,
    authentication_results,
    received_headers
):

    findings = []

    # Missing Date
    if not message.get("Date"):

        findings.append(
            "Date header is missing"
        )

    # Missing Message-ID
    if not message.get("Message-ID"):

        findings.append(
            "Message-ID header is missing"
        )

    # Missing authentication evidence
    if not authentication_results:

        findings.append(
            "No Authentication-Results header found"
        )

    # Missing relay information
    if not received_headers:

        findings.append(
            "No Received headers found"
        )

    # Reply-To mismatch
    sender = message.get("From")
    reply_to = message.get("Reply-To")

    if sender and reply_to:

        sender_match = re.search(
            r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
            sender
        )

        reply_match = re.search(
            r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
            reply_to
        )

        if sender_match and reply_match:

            sender_domain = (
                sender_match.group(1).lower()
            )

            reply_domain = (
                reply_match.group(1).lower()
            )

            if sender_domain != reply_domain:

                findings.append(
                    "Sender and Reply-To domains do not match"
                )

    return findings


# ---------------------------------------------------------
# Main header analyzer
# ---------------------------------------------------------

def analyze_headers(email_bytes):

    try:

        message = BytesParser(
            policy=policy.default
        ).parsebytes(email_bytes)

        received_headers = message.get_all(
            "Received",
            []
        )

        authentication_results = (
            extract_authentication_results(
                message
            )
        )

        authentication_status = (
            extract_authentication_status(
                authentication_results
            )
        )

        relay_analysis = (
            analyze_received_headers(
                received_headers
            )
        )

        # Collect domains from important headers
        header_text = "\n".join(
            str(value)
            for value in message.items()
        )

        header_domains = extract_domains(
            header_text
        )

        # Combine relay + header domains
        domains = list(
            dict.fromkeys(
                header_domains
                + relay_analysis["domains"]
            )
        )

        findings = generate_findings(
            message,
            authentication_results,
            received_headers
        )

        return {

            "spf": authentication_status["spf"],

            "dkim": authentication_status["dkim"],

            "dmarc": authentication_status["dmarc"],

            "message_id": (
                message.get("Message-ID")
            ),

            "ip_addresses": (
                relay_analysis["ip_addresses"]
            ),

            "domains": domains,

            "authentication_results": (
                authentication_results
            ),

            "received_headers": [
                str(header)
                for header in received_headers
            ],

            "relay_analysis": relay_analysis,

            "findings": findings

        }

    except Exception as e:

        return {
            "spf": "Not available",
            "dkim": "Not available",
            "dmarc": "Not available",
            "message_id": None,
            "ip_addresses": [],
            "domains": [],
            "authentication_results": [],
            "received_headers": [],
            "relay_analysis": {
                "relay_count": 0,
                "ip_addresses": [],
                "domains": [],
                "relays": []
            },
            "findings": [
                f"Header analysis error: {str(e)}"
            ]
        }