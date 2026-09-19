import re
from email import policy
from email.parser import BytesParser


def analyze_headers(email_bytes):
    """
    Analyze email headers for forensic investigation.
    """

    message = BytesParser(policy=policy.default).parsebytes(email_bytes)

    # Basic email information
    from_address = message.get("From", "Not available")
    to_address = message.get("To", "Not available")
    subject = message.get("Subject", "Not available")
    date = message.get("Date", "Not available")
    reply_to = message.get("Reply-To", "Not available")
    return_path = message.get("Return-Path", "Not available")
    message_id = message.get("Message-ID", "Not available")

    # All Received headers
    received_headers = message.get_all("Received", [])

    # Authentication results
    authentication_results = message.get_all(
        "Authentication-Results", []
    )

    # SPF / DKIM / DMARC results
    spf_result = "Not available"
    dkim_result = "Not available"
    dmarc_result = "Not available"

    auth_text = " ".join(str(x) for x in authentication_results).lower()

    spf_match = re.search(r"spf\s*=\s*([a-zA-Z]+)", auth_text)
    dkim_match = re.search(r"dkim\s*=\s*([a-zA-Z]+)", auth_text)
    dmarc_match = re.search(r"dmarc\s*=\s*([a-zA-Z]+)", auth_text)

    if spf_match:
        spf_result = spf_match.group(1).upper()

    if dkim_match:
        dkim_result = dkim_match.group(1).upper()

    if dmarc_match:
        dmarc_result = dmarc_match.group(1).upper()

    # Extract IP addresses from Received headers
    ip_addresses = []

    for header in received_headers:
        matches = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            str(header)
        )

        for ip in matches:
            if ip not in ip_addresses:
                ip_addresses.append(ip)

    # Extract domains from email addresses and headers
    domains = []

    email_addresses = re.findall(
        r"[\w.+-]+@([\w.-]+\.[A-Za-z]{2,})",
        f"{from_address} {to_address} {reply_to} {return_path}"
    )

    for domain in email_addresses:
        domain = domain.lower()

        if domain not in domains:
            domains.append(domain)

    # Basic forensic findings
    findings = []

    if reply_to != "Not available" and from_address != "Not available":
        from_domain = from_address.split("@")[-1].strip(">").lower()
        reply_domain = reply_to.split("@")[-1].strip(">").lower()

        if from_domain != reply_domain:
            findings.append(
                "Reply-To domain differs from sender domain"
            )

    if spf_result == "FAIL":
        findings.append("SPF authentication failed")

    if dkim_result == "FAIL":
        findings.append("DKIM authentication failed")

    if dmarc_result == "FAIL":
        findings.append("DMARC authentication failed")

    if not received_headers:
        findings.append("No Received relay headers found")

    return {
        "from": from_address,
        "to": to_address,
        "subject": subject,
        "date": date,
        "reply_to": reply_to,
        "return_path": return_path,
        "message_id": message_id,
        "received_headers": [
            str(header) for header in received_headers
        ],
        "authentication_results": [
            str(result) for result in authentication_results
        ],
        "spf": spf_result,
        "dkim": dkim_result,
        "dmarc": dmarc_result,
        "ip_addresses": ip_addresses,
        "domains": domains,
        "findings": findings
    }