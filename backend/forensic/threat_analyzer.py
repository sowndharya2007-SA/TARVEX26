import re
from urllib.parse import urlparse


# ---------------------------------------------------------
# Threat detection keywords
# ---------------------------------------------------------

URGENT_KEYWORDS = [
    "urgent",
    "immediately",
    "action required",
    "act now",
    "verify now",
    "account suspended",
    "account locked",
    "final warning",
    "important notice",
]

CREDENTIAL_KEYWORDS = [
    "verify your account",
    "verify your identity",
    "confirm your account",
    "login",
    "log in",
    "password",
    "username",
    "credentials",
    "security verification",
]

FINANCIAL_KEYWORDS = [
    "bank",
    "payment",
    "invoice",
    "transaction",
    "refund",
    "credit card",
    "debit card",
    "account number",
]

PHISHING_KEYWORDS = [
    "click here",
    "click the link",
    "verify your account",
    "confirm your identity",
    "update your information",
    "reset your password",
]


# ---------------------------------------------------------
# URL extraction
# ---------------------------------------------------------

def extract_urls(text):
    if not text:
        return []

    pattern = r"https?://[^\s<>\"]+"

    urls = re.findall(pattern, text)

    # Remove duplicates while preserving order
    return list(dict.fromkeys(urls))


# ---------------------------------------------------------
# Domain extraction from URLs
# ---------------------------------------------------------

def extract_url_domains(urls):
    domains = []

    for url in urls:
        try:
            parsed = urlparse(url)

            if parsed.netloc:
                domain = parsed.netloc.lower()

                if domain.startswith("www."):
                    domain = domain[4:]

                if domain not in domains:
                    domains.append(domain)

        except Exception:
            continue

    return domains


# ---------------------------------------------------------
# Sender / Reply-To mismatch
# ---------------------------------------------------------

def check_sender_mismatch(headers):

    sender = headers.get("from")
    reply_to = headers.get("reply_to")

    if not sender or not reply_to:
        return False

    sender_match = re.search(
        r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
        sender
    )

    reply_match = re.search(
        r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
        reply_to
    )

    if not sender_match or not reply_match:
        return False

    sender_domain = sender_match.group(1).lower()
    reply_domain = reply_match.group(1).lower()

    return sender_domain != reply_domain


# ---------------------------------------------------------
# Main threat analyzer
# ---------------------------------------------------------

def analyze_threat(headers, body, forensic_data):

    subject = headers.get("subject") or ""
    sender = headers.get("from") or ""
    reply_to = headers.get("reply_to") or ""

    body = body or ""

    # Combine email content
    content = f"{subject} {body}".lower()

    score = 0
    indicators = []

    # -----------------------------------------------------
    # 1. Urgency detection
    # -----------------------------------------------------

    urgency_matches = [
        keyword
        for keyword in URGENT_KEYWORDS
        if keyword in content
    ]

    if urgency_matches:

        score += min(len(urgency_matches) * 8, 20)

        indicators.append(
            "Urgency-based language detected"
        )

    # -----------------------------------------------------
    # 2. Credential / account targeting
    # -----------------------------------------------------

    credential_matches = [
        keyword
        for keyword in CREDENTIAL_KEYWORDS
        if keyword in content
    ]

    if credential_matches:

        score += min(len(credential_matches) * 8, 25)

        indicators.append(
            "Credential or account-verification language detected"
        )

    # -----------------------------------------------------
    # 3. Financial targeting
    # -----------------------------------------------------

    financial_matches = [
        keyword
        for keyword in FINANCIAL_KEYWORDS
        if keyword in content
    ]

    if financial_matches:

        score += min(len(financial_matches) * 6, 20)

        indicators.append(
            "Financial or transaction-related language detected"
        )

    # -----------------------------------------------------
    # 4. Phishing language
    # -----------------------------------------------------

    phishing_matches = [
        keyword
        for keyword in PHISHING_KEYWORDS
        if keyword in content
    ]

    if phishing_matches:

        score += min(len(phishing_matches) * 10, 25)

        indicators.append(
            "Potential phishing language detected"
        )

    # -----------------------------------------------------
    # 5. URL analysis
    # -----------------------------------------------------

    urls = extract_urls(body)

    url_domains = extract_url_domains(urls)

    if urls:

        score += min(len(urls) * 5, 15)

        indicators.append(
            f"{len(urls)} URL(s) detected in email content"
        )

    # -----------------------------------------------------
    # 6. Sender / Reply-To mismatch
    # -----------------------------------------------------

    if check_sender_mismatch(headers):

        score += 20

        indicators.append(
            "Sender and Reply-To domains do not match"
        )

    # -----------------------------------------------------
    # 7. Authentication analysis
    # -----------------------------------------------------

    authentication_results = forensic_data.get(
        "authentication_results",
        []
    )

    if not authentication_results:

        score += 5

        indicators.append(
            "No Authentication-Results header found"
        )

    # -----------------------------------------------------
    # 8. Header findings
    # -----------------------------------------------------

    forensic_findings = forensic_data.get(
        "findings",
        []
    )

    if forensic_findings:

        score += min(len(forensic_findings) * 5, 20)

        for finding in forensic_findings:

            if finding not in indicators:
                indicators.append(finding)

    # -----------------------------------------------------
    # Keep score within 0-100
    # -----------------------------------------------------

    score = min(score, 100)

    # -----------------------------------------------------
    # Risk classification
    # -----------------------------------------------------

    if score >= 70:

        risk_level = "HIGH"

    elif score >= 40:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    # -----------------------------------------------------
    # Summary
    # -----------------------------------------------------

    if score == 0:

        summary = (
            "No major threat indicators were detected "
            "by the current rule-based analysis."
        )

    elif risk_level == "HIGH":

        summary = (
            "Multiple suspicious indicators were detected. "
            "The email requires detailed forensic investigation."
        )

    elif risk_level == "MEDIUM":

        summary = (
            "Several suspicious indicators were detected. "
            "Further investigation is recommended."
        )

    else:

        summary = (
            "Limited suspicious indicators were detected. "
            "The email should still be reviewed in context."
        )

    # -----------------------------------------------------
    # Return intelligence
    # -----------------------------------------------------

    return {
        "threat_score": score,
        "risk_level": risk_level,
        "indicators": indicators,
        "urls": urls,
        "url_domains": url_domains,
        "summary": summary,
    }
