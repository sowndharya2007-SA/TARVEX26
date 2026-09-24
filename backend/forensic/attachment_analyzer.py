"""
TARVEX26
Attachment Forensics Engine
SIH26106 - Email Threat Detection and Forensic Intelligence

Analyzes email attachments for:
- Executable files
- Scripts
- Archives
- Double extensions
- Suspicious filenames
- MIME types
- Attachment size

Note:
This module performs metadata and filename risk analysis.
It does NOT claim to perform malware execution or antivirus scanning.
"""

import os


DANGEROUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".ps1",
    ".msi",
    ".hta",
    ".jar",
    ".lnk",
    ".reg",
    ".dll",
}

SCRIPT_EXTENSIONS = {
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".ps1",
    ".bat",
    ".cmd",
    ".hta",
}

ARCHIVE_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".bz2",
}

DOCUMENT_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".txt",
}


def _get_extension(filename):
    return os.path.splitext(filename.lower())[1]


def _detect_double_extension(filename):
    name = filename.lower()
    parts = name.split(".")

    if len(parts) < 3:
        return False

    final_extension = "." + parts[-1]
    previous_extension = "." + parts[-2]

    return (
        final_extension in DANGEROUS_EXTENSIONS
        and previous_extension in (
            DOCUMENT_EXTENSIONS
            | {".jpg", ".jpeg", ".png", ".gif"}
        )
    )


def _classify_attachment(extension):
    if extension in DANGEROUS_EXTENSIONS:
        return "EXECUTABLE"

    if extension in SCRIPT_EXTENSIONS:
        return "SCRIPT"

    if extension in ARCHIVE_EXTENSIONS:
        return "ARCHIVE"

    if extension in DOCUMENT_EXTENSIONS:
        return "DOCUMENT"

    return "OTHER"


def analyze_attachments(message):
    attachments = []
    suspicious_files = []
    findings = []

    if not hasattr(message, "walk"):
        return {
            "total": 0,
            "attachments": [],
            "suspicious_count": 0,
            "suspicious_files": [],
            "findings": [],
            "risk_level": "NONE",
            "engine": {
                "name": "TARVEX26 Attachment Forensics Engine",
                "version": "1.0",
                "analysis_type": "Attachment metadata and risk analysis",
            },
        }

    try:
        for part in message.walk():

            filename = part.get_filename()

            if not filename:
                continue

            filename = str(filename)

            extension = _get_extension(filename)
            content_type = part.get_content_type()

            payload = part.get_payload(decode=True)
            size_bytes = len(payload) if payload else 0

            category = _classify_attachment(extension)
            double_extension = _detect_double_extension(filename)

            risks = []

            if extension in DANGEROUS_EXTENSIONS:
                risks.append("Potentially executable file")

            if extension in SCRIPT_EXTENSIONS:
                risks.append("Script-based attachment")

            if extension in ARCHIVE_EXTENSIONS:
                risks.append("Archive requires deeper inspection")

            if double_extension:
                risks.append("Suspicious double-extension filename")

            suspicious_keywords = [
                "invoice",
                "payment",
                "refund",
                "password",
                "account",
                "verify",
                "urgent",
                "salary",
                "bank",
                "document",
                "security",
            ]

            filename_lower = filename.lower()

            matched_keywords = [
                keyword
                for keyword in suspicious_keywords
                if keyword in filename_lower
            ]

            if matched_keywords:
                risks.append(
                    "Sensitive filename keywords: "
                    + ", ".join(matched_keywords)
                )

            item = {
                "filename": filename,
                "extension": extension if extension else "UNKNOWN",
                "content_type": content_type,
                "size_bytes": size_bytes,
                "category": category,
                "is_executable": extension in DANGEROUS_EXTENSIONS,
                "is_script": extension in SCRIPT_EXTENSIONS,
                "is_archive": extension in ARCHIVE_EXTENSIONS,
                "double_extension": double_extension,
                "suspicious_keywords": matched_keywords,
                "risks": list(dict.fromkeys(risks)),
            }

            attachments.append(item)

            if risks:
                suspicious_files.append(filename)

                for risk in risks:
                    findings.append(
                        f"{filename}: {risk}"
                    )

    except Exception as error:

        findings.append(
            f"Attachment analysis error: {str(error)}"
        )

    # ---------------------------------------------------------
    # RISK CLASSIFICATION
    # ---------------------------------------------------------

    if not attachments:
        risk_level = "NONE"

    elif any(
        item["is_executable"] or item["double_extension"]
        for item in attachments
    ):
        risk_level = "HIGH"

    elif any(
        item["is_script"]
        for item in attachments
    ):
        risk_level = "HIGH"

    elif any(
        item["is_archive"]
        for item in attachments
    ):
        risk_level = "MEDIUM"

    elif suspicious_files:
        risk_level = "LOW"

    else:
        risk_level = "MINIMAL"

    return {
        "total": len(attachments),
        "attachments": attachments,
        "suspicious_count": len(
            list(dict.fromkeys(suspicious_files))
        ),
        "suspicious_files": list(
            dict.fromkeys(suspicious_files)
        ),
        "findings": list(
            dict.fromkeys(findings)
        ),
        "risk_level": risk_level,
        "engine": {
            "name": "TARVEX26 Attachment Forensics Engine",
            "version": "1.0",
            "analysis_type": "Attachment metadata and risk analysis",
        },
    }