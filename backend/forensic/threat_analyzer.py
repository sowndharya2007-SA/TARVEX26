"""
TARVEX26
AI-Powered Email Threat Detection Engine
SIH26106 - Email Threat Detection & Forensic Intelligence

This module performs:
- NLP-style content analysis
- Phishing detection
- Social engineering detection
- Impersonation detection
- Business Email Compromise (BEC) detection
- Suspicious URL detection
- Sender / Reply-To mismatch detection
- Attachment risk analysis
- Threat scoring
- Confidence estimation
"""

import re
from urllib.parse import urlparse


# ============================================================
# THREAT PATTERNS
# ============================================================

URGENCY_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\basap\b",
    r"\baction required\b",
    r"\bact now\b",
    r"\blast warning\b",
    r"\bfinal warning\b",
    r"\bwithin \d+\s*(minutes?|hours?)\b",
    r"\baccount will be (closed|suspended|locked)\b",
]

CREDENTIAL_PATTERNS = [
    r"\bverify your account\b",
    r"\bverify your identity\b",
    r"\bconfirm your account\b",
    r"\bconfirm your identity\b",
    r"\blogin\b",
    r"\blog in\b",
    r"\bsign in\b",
    r"\bpassword\b",
    r"\busername\b",
    r"\bcredentials\b",
    r"\bsecurity verification\b",
    r"\baccount verification\b",
]

FINANCIAL_PATTERNS = [
    r"\binvoice\b",
    r"\bpayment\b",
    r"\bpay immediately\b",
    r"\bbank account\b",
    r"\bbank details\b",
    r"\bwire transfer\b",
    r"\btransfer funds\b",
    r"\baccount number\b",
    r"\bbeneficiary\b",
    r"\brefund\b",
    r"\btransaction\b",
]

BEC_PATTERNS = [
    r"\bceo\b",
    r"\bcfo\b",
    r"\bdirector\b",
    r"\bexecutive\b",
    r"\bmanager\b",
    r"\bsecretary\b",
    r"\bfinance department\b",
    r"\baccounts department\b",
    r"\bkeep this confidential\b",
    r"\bdo not tell\b",
    r"\bdo not disclose\b",
    r"\bconfidential\b",
    r"\bwire transfer\b",
    r"\bpayment request\b",
]

IMPERSONATION_PATTERNS = [
    r"\bthis is (your|the) (ceo|cfo|director|manager)\b",
    r"\bi am your (ceo|cfo|director|manager)\b",
    r"\bon behalf of\b",
    r"\bacting on behalf\b",
    r"\bfrom the office of\b",
    r"\bsecurity team\b",
    r"\bit support\b",
    r"\badmin(istrator)?\b",
]

SOCIAL_ENGINEERING_PATTERNS = [
    r"\btrust me\b",
    r"\bkeep this confidential\b",
    r"\bdo not tell anyone\b",
    r"\bdo not share\b",
    r"\bsecret\b",
    r"\bprivate matter\b",
    r"\bimmediate attention\b",
    r"\bavoid account suspension\b",
    r"\bavoid service interruption\b",
    r"\byou have been selected\b",
    r"\bcongratulations\b",
    r"\byou won\b",
    r"\bclaim your\b",
]

SUSPICIOUS_DOMAIN_WORDS = [
    "verify",
    "secure",
    "security",
    "account",
    "update",
    "login",
    "signin",
    "support",
    "alert",
    "confirmation",
    "wallet",
    "payment",
]


# ============================================================
# GENERIC HELPERS
# ============================================================

def _safe_text(value):
    """Convert any value into clean text."""
    if value is None:
        return ""

    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    return str(value)


def _extract_email(address):
    """
    Extract an email address from:
    John <john@example.com>
    john@example.com
    """
    if not address:
        return None

    match = re.search(
        r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",
        _safe_text(address)
    )

    return match.group(0).lower() if match else None


def _extract_domain(address):
    """Extract domain from an email address."""
    email = _extract_email(address)

    if not email:
        return None

    return email.split("@", 1)[1].lower()


def _find_patterns(text, patterns):
    """
    Detect regex patterns in text.
    Returns matched human-readable phrases.
    """
    matches = []

    text = _safe_text(text).lower()

    for pattern in patterns:
        try:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(pattern)
        except re.error:
            continue

    return matches


def _count_pattern_hits(text, patterns):
    """Count total regex pattern matches."""
    text = _safe_text(text).lower()

    count = 0

    for pattern in patterns:
        try:
            count += len(
                re.findall(
                    pattern,
                    text,
                    re.IGNORECASE
                )
            )
        except re.error:
            pass

    return count


# ============================================================
# EMAIL BODY EXTRACTION
# ============================================================

def _extract_message_content(message):
    """
    Extract subject, plain text and HTML text from
    email.message.Message or generic input.
    """

    subject = ""
    body = ""

    # --------------------------------------------------------
    # email.message.Message
    # --------------------------------------------------------

    if hasattr(message, "get"):
        try:
            subject = _safe_text(
                message.get("Subject", "")
            )
        except Exception:
            subject = ""

        # Multipart email
        if hasattr(message, "walk"):

            parts = []

            try:
                for part in message.walk():

                    content_type = part.get_content_type()

                    if content_type == "text/plain":

                        try:
                            payload = part.get_payload(
                                decode=True
                            )

                            if payload:
                                parts.append(
                                    _safe_text(payload)
                                )

                        except Exception:
                            pass

                    elif content_type == "text/html":

                        try:
                            payload = part.get_payload(
                                decode=True
                            )

                            if payload:
                                html = _safe_text(payload)

                                # Remove HTML tags
                                html = re.sub(
                                    r"<[^>]+>",
                                    " ",
                                    html
                                )

                                parts.append(html)

                        except Exception:
                            pass

                body = "\n".join(parts)

            except Exception:
                body = ""

        # Single-part email
        if not body and hasattr(message, "get_payload"):

            try:
                payload = message.get_payload(
                    decode=True
                )

                if payload:
                    body = _safe_text(payload)

            except Exception:
                pass

    # --------------------------------------------------------
    # String input
    # --------------------------------------------------------

    else:

        raw = _safe_text(message)

        lines = raw.splitlines()

        for line in lines:

            if line.lower().startswith("subject:"):

                subject = line.split(
                    ":",
                    1
                )[1].strip()

        body = raw

    return subject.strip(), body.strip()


# ============================================================
# URL ANALYSIS
# ============================================================

def _extract_urls(text):
    """Extract HTTP/HTTPS URLs."""
    return re.findall(
        r"https?://[^\s<>'\"]+",
        _safe_text(text),
        re.IGNORECASE
    )


def _analyse_urls(urls):
    """
    Analyse URLs for suspicious characteristics.
    """

    suspicious = []
    findings = []

    for url in urls:

        try:
            parsed = urlparse(url)

            domain = (
                parsed.netloc
                .lower()
                .split(":")[0]
            )

            path = parsed.path.lower()

            # IP address used instead of domain
            if re.fullmatch(
                r"\d{1,3}(\.\d{1,3}){3}",
                domain
            ):
                suspicious.append(url)

                findings.append(
                    f"URL uses a raw IP address: {domain}"
                )

            # Suspicious domain words
            domain_words = [
                word
                for word in SUSPICIOUS_DOMAIN_WORDS
                if word in domain
            ]

            if domain_words:

                suspicious.append(url)

                findings.append(
                    "Suspicious domain keyword detected: "
                    + ", ".join(domain_words)
                )

            # Long obfuscated-looking URL
            if len(url) > 120:

                suspicious.append(url)

                findings.append(
                    "Unusually long URL detected"
                )

            # URL encoded characters
            if "%" in url:

                suspicious.append(url)

                findings.append(
                    "URL contains encoded characters"
                )

            # Suspicious login/payment paths
            suspicious_paths = [
                "login",
                "signin",
                "verify",
                "account",
                "password",
                "payment",
                "invoice",
                "wallet",
                "secure",
            ]

            if any(
                item in path
                for item in suspicious_paths
            ):

                suspicious.append(url)

                findings.append(
                    f"Sensitive action path detected: {path}"
                )

        except Exception:
            continue

    # Remove duplicates
    suspicious = list(
        dict.fromkeys(suspicious)
    )

    findings = list(
        dict.fromkeys(findings)
    )

    return suspicious, findings


# ============================================================
# ATTACHMENT ANALYSIS
# ============================================================

def _analyse_attachments(message):
    """
    Inspect attachment metadata.

    This does NOT execute or open attachments.
    """

    attachments = []
    suspicious = []

    if not hasattr(message, "walk"):
        return attachments, suspicious

    try:

        for part in message.walk():

            filename = part.get_filename()

            if not filename:
                continue

            filename_lower = filename.lower()

            content_type = (
                part.get_content_type()
            )

            item = {
                "filename": filename,
                "content_type": content_type,
            }

            attachments.append(item)

            dangerous_extensions = [
                ".exe",
                ".scr",
                ".bat",
                ".cmd",
                ".com",
                ".js",
                ".vbs",
                ".ps1",
                ".msi",
                ".jar",
                ".hta",
                ".lnk",
                ".iso",
                ".zip",
                ".rar",
            ]

            if any(
                filename_lower.endswith(ext)
                for ext in dangerous_extensions
            ):
                suspicious.append(
                    f"Potentially risky attachment: {filename}"
                )

    except Exception:
        pass

    return attachments, suspicious


# ============================================================
# HEADER INTELLIGENCE
# ============================================================

def _analyse_headers(message, headers=None):

    if headers is None:
        headers = {}

    # --------------------------------------------------------
    # Normalize headers
    # --------------------------------------------------------

    normalized = {}

    if hasattr(headers, "items"):

        for key, value in headers.items():

            normalized[
                str(key).lower().replace(
                    "-",
                    "_"
                )
            ] = _safe_text(value)

    # If email Message was supplied, use it too
    if hasattr(message, "get"):

        header_map = {
            "from": "from",
            "reply_to": "reply_to",
            "return_path": "return_path",
            "message_id": "message_id",
            "authentication_results":
                "authentication_results",
        }

        for source, target in header_map.items():

            if not normalized.get(target):

                try:
                    normalized[target] = _safe_text(
                        message.get(
                            source.replace(
                                "_",
                                "-"
                            ),
                            ""
                        )
                    )

                except Exception:
                    pass

    sender = normalized.get(
        "from",
        ""
    )

    reply_to = normalized.get(
        "reply_to",
        ""
    )

    sender_domain = _extract_domain(sender)

    reply_domain = _extract_domain(reply_to)

    mismatch = False

    if sender_domain and reply_domain:

        mismatch = (
            sender_domain != reply_domain
        )

    # --------------------------------------------------------
    # Authentication header
    # --------------------------------------------------------

    auth_results = normalized.get(
        "authentication_results",
        ""
    ).lower()

    authentication_failures = []

    for mechanism in [
        "spf",
        "dkim",
        "dmarc",
    ]:

        if re.search(
            rf"{mechanism}\s*=\s*fail",
            auth_results
        ):

            authentication_failures.append(
                mechanism.upper()
            )

    return {
        "sender": sender,
        "reply_to": reply_to,
        "sender_domain": sender_domain,
        "reply_to_domain": reply_domain,
        "reply_to_mismatch": mismatch,
        "authentication_failures":
            authentication_failures,
    }


# ============================================================
# CLASSIFICATION
# ============================================================

def _classify(
    phishing_score,
    impersonation_score,
    bec_score,
    social_score,
    credential_score,
    financial_score,
):
    scores = {
        "PHISHING": phishing_score,
        "IMPERSONATION": impersonation_score,
        "BEC / FRAUD": bec_score,
        "SOCIAL ENGINEERING": social_score,
    }

    classification = max(
        scores,
        key=scores.get
    )

    highest = scores[classification]

    if highest < 20:
        classification = "LEGITIMATE"

    elif highest < 40:
        classification = "SUSPICIOUS"

    return classification


# ============================================================
# MAIN THREAT ANALYZER
# ============================================================

def analyze_threat(
    message=None,
    headers=None,
    *args,
    **kwargs
):
    """
    Main TARVEX26 threat detection engine.

    Compatible with the existing Flask pipeline.

    Returns a structured threat intelligence object
    consumed by the React forensic dashboard.
    """

    # ========================================================
    # CONTENT
    # ========================================================

    subject, body = _extract_message_content(
        message
    )

    combined_text = (
        subject
        + "\n"
        + body
    )

    combined_lower = combined_text.lower()

    # ========================================================
    # PATTERN DETECTION
    # ========================================================

    urgency_hits = _count_pattern_hits(
        combined_text,
        URGENCY_PATTERNS
    )

    credential_hits = _count_pattern_hits(
        combined_text,
        CREDENTIAL_PATTERNS
    )

    financial_hits = _count_pattern_hits(
        combined_text,
        FINANCIAL_PATTERNS
    )

    bec_hits = _count_pattern_hits(
        combined_text,
        BEC_PATTERNS
    )

    impersonation_hits = _count_pattern_hits(
        combined_text,
        IMPERSONATION_PATTERNS
    )

    social_hits = _count_pattern_hits(
        combined_text,
        SOCIAL_ENGINEERING_PATTERNS
    )

    # ========================================================
    # URL INTELLIGENCE
    # ========================================================

    urls = _extract_urls(
        combined_text
    )

    suspicious_urls, url_findings = (
        _analyse_urls(urls)
    )

    # ========================================================
    # ATTACHMENTS
    # ========================================================

    attachments, suspicious_attachments = (
        _analyse_attachments(message)
    )

    # ========================================================
    # HEADER ANALYSIS
    # ========================================================

    header_data = _analyse_headers(
        message,
        headers
    )

    # ========================================================
    # INDICATORS
    # ========================================================

    indicators = []

    if urgency_hits > 0:
        indicators.append(
            "Urgency and pressure language detected"
        )

    if credential_hits > 0:
        indicators.append(
            "Credential or account verification language detected"
        )

    if financial_hits > 0:
        indicators.append(
            "Financial transaction language detected"
        )

    if bec_hits > 0:
        indicators.append(
            "Business Email Compromise patterns detected"
        )

    if impersonation_hits > 0:
        indicators.append(
            "Possible executive or authority impersonation detected"
        )

    if social_hits > 0:
        indicators.append(
            "Social engineering language detected"
        )

    if suspicious_urls:
        indicators.append(
            f"{len(suspicious_urls)} suspicious URL(s) detected"
        )

    if suspicious_attachments:
        indicators.extend(
            suspicious_attachments
        )

    if header_data["reply_to_mismatch"]:

        indicators.append(
            "Sender and Reply-To domains do not match"
        )

    if header_data["authentication_failures"]:

        indicators.append(
            "Authentication failure detected: "
            + ", ".join(
                header_data[
                    "authentication_failures"
                ]
            )
        )

    # ========================================================
    # CATEGORY SCORES
    # ========================================================

    phishing_score = min(
        100,
        (
            urgency_hits * 6
            + credential_hits * 10
            + len(suspicious_urls) * 14
            + len(suspicious_attachments) * 12
            + len(
                header_data[
                    "authentication_failures"
                ]
            ) * 12
            + (
                18
                if header_data[
                    "reply_to_mismatch"
                ]
                else 0
            )
        )
    )

    impersonation_score = min(
        100,
        (
            impersonation_hits * 16
            + social_hits * 6
            + (
                20
                if header_data[
                    "reply_to_mismatch"
                ]
                else 0
            )
        )
    )

    bec_score = min(
        100,
        (
            bec_hits * 13
            + financial_hits * 7
            + impersonation_hits * 8
            + (
                15
                if header_data[
                    "reply_to_mismatch"
                ]
                else 0
            )
        )
    )

    social_score = min(
        100,
        (
            social_hits * 12
            + urgency_hits * 8
            + credential_hits * 6
        )
    )

    # ========================================================
    # OVERALL THREAT SCORE
    # ========================================================

    content_score = min(
        100,
        (
            urgency_hits * 4
            + credential_hits * 7
            + financial_hits * 5
            + bec_hits * 6
            + impersonation_hits * 7
            + social_hits * 5
            + len(suspicious_urls) * 10
            + len(suspicious_attachments) * 9
        )
    )

    header_score = min(
        100,
        (
            len(
                header_data[
                    "authentication_failures"
                ]
            ) * 15
            + (
                20
                if header_data[
                    "reply_to_mismatch"
                ]
                else 0
            )
        )
    )

    threat_score = round(
        (
            content_score * 0.65
            + header_score * 0.35
        )
    )

    threat_score = max(
        0,
        min(
            100,
            threat_score
        )
    )

    # ========================================================
    # CLASSIFICATION
    # ========================================================

    classification = _classify(
        phishing_score,
        impersonation_score,
        bec_score,
        social_score,
        credential_hits * 10,
        financial_hits * 10,
    )

    # ========================================================
    # RISK LEVEL
    # ========================================================

    if threat_score >= 75:

        risk_level = "CRITICAL"

    elif threat_score >= 55:

        risk_level = "HIGH"

    elif threat_score >= 30:

        risk_level = "MEDIUM"

    elif threat_score >= 15:

        risk_level = "LOW"

    else:

        risk_level = "MINIMAL"

    # ========================================================
    # CONFIDENCE
    # ========================================================

    evidence_count = (
        urgency_hits
        + credential_hits
        + financial_hits
        + bec_hits
        + impersonation_hits
        + social_hits
        + len(suspicious_urls)
        + len(suspicious_attachments)
        + len(
            header_data[
                "authentication_failures"
            ]
        )
        + (
            1
            if header_data[
                "reply_to_mismatch"
            ]
            else 0
        )
    )

    if evidence_count == 0:

        confidence = 58.0

    else:

        confidence = min(
            97.0,
            62.0
            + evidence_count * 4.5
        )

    # ========================================================
    # SUMMARY
    # ========================================================

    if classification == "LEGITIMATE":

        summary = (
            "No strong phishing, impersonation, "
            "BEC or social-engineering indicators "
            "were identified from the available "
            "email content and header evidence."
        )

    elif classification == "SUSPICIOUS":

        summary = (
            "The email contains suspicious "
            "behavioral or structural indicators "
            "that require investigator review."
        )

    elif classification == "PHISHING":

        summary = (
            "The email shows multiple indicators "
            "consistent with phishing, including "
            "credential targeting, suspicious links "
            "or social-engineering techniques."
        )

    elif classification == "IMPERSONATION":

        summary = (
            "The email contains indicators of "
            "possible sender impersonation or "
            "identity deception."
        )

    else:

        summary = (
            "The email contains patterns associated "
            "with Business Email Compromise or "
            "fraud-oriented financial requests."
        )

    # ========================================================
    # BEC / SPOOFING RISK
    # ========================================================

    bec_risk = (
        "HIGH"
        if bec_score >= 60
        else "MEDIUM"
        if bec_score >= 30
        else "LOW"
    )

    spoofing_risk = (
        "HIGH"
        if (
            header_data[
                "reply_to_mismatch"
            ]
            or header_data[
                "authentication_failures"
            ]
        )
        else "LOW"
    )

    phishing_risk = (
        "HIGH"
        if phishing_score >= 60
        else "MEDIUM"
        if phishing_score >= 30
        else "LOW"
    )

    # ========================================================
    # FEATURE ANALYSIS
    # ========================================================

    feature_analysis = {

        "urgency_language": urgency_hits,

        "credential_targeting":
            credential_hits,

        "financial_language":
            financial_hits,

        "bec_patterns":
            bec_hits,

        "impersonation_patterns":
            impersonation_hits,

        "social_engineering_patterns":
            social_hits,

        "url_count":
            len(urls),

        "suspicious_url_count":
            len(suspicious_urls),

        "attachment_count":
            len(attachments),

        "suspicious_attachment_count":
            len(suspicious_attachments),

        "reply_to_mismatch":
            header_data[
                "reply_to_mismatch"
            ],

        "authentication_failures":
            header_data[
                "authentication_failures"
            ],
    }

    # ========================================================
    # FINAL RESULT
    # ========================================================

    return {

        # ----------------------------------------------
        # Primary dashboard fields
        # ----------------------------------------------

        "classification":
            classification,

        "threat_score":
            threat_score,

        "fraud_score":
            threat_score,

        "score":
            threat_score,

        "risk_level":
            risk_level,

        "confidence":
            round(
                confidence,
                1
            ),

        "summary":
            summary,

        "indicators":
            indicators,

        # ----------------------------------------------
        # SIH-aligned threat categories
        # ----------------------------------------------

        "phishing_risk":
            phishing_risk,

        "bec_risk":
            bec_risk,

        "spoofing_risk":
            spoofing_risk,

        # ----------------------------------------------
        # Category intelligence
        # ----------------------------------------------

        "category_scores": {

            "phishing":
                phishing_score,

            "impersonation":
                impersonation_score,

            "bec_fraud":
                bec_score,

            "social_engineering":
                social_score,
        },

        # ----------------------------------------------
        # NLP / content analysis
        # ----------------------------------------------

        "nlp_analysis": {

            "subject":
                subject,

            "body_length":
                len(body),

            "word_count":
                len(
                    re.findall(
                        r"\b\w+\b",
                        body
                    )
                ),

            "urgency_hits":
                urgency_hits,

            "credential_hits":
                credential_hits,

            "financial_hits":
                financial_hits,

            "bec_hits":
                bec_hits,

            "impersonation_hits":
                impersonation_hits,

            "social_engineering_hits":
                social_hits,
        },

        # ----------------------------------------------
        # URL intelligence
        # ----------------------------------------------

        "url_intelligence": {

            "urls":
                urls,

            "suspicious_urls":
                suspicious_urls,

            "findings":
                url_findings,
        },

        # ----------------------------------------------
        # Attachment intelligence
        # ----------------------------------------------

        "attachment_intelligence": {

            "attachments":
                attachments,

            "suspicious":
                suspicious_attachments,
        },

        # ----------------------------------------------
        # Header intelligence
        # ----------------------------------------------

        "header_intelligence":
            header_data,

        # ----------------------------------------------
        # Scoring transparency
        # ----------------------------------------------

        "score_breakdown": {

            "content_score":
                content_score,

            "header_score":
                header_score,

            "threat_score":
                threat_score,
        },

        # ----------------------------------------------
        # Investigator-facing feature data
        # ----------------------------------------------

        "feature_analysis":
            feature_analysis,

        # ----------------------------------------------
        # Engine metadata
        # ----------------------------------------------

        "engine": {

            "name":
                "TARVEX26 Hybrid Threat Intelligence Engine",

            "version":
                "1.0",

            "analysis_type":
                "NLP + rule-based forensic correlation",

            "explainable":
                True,

            "model_status":
                "NLP feature extraction active; supervised ML model will be added in the next training stage",
        },
    }