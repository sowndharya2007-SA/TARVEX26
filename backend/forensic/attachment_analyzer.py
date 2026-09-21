"""
TARVEX26
Attachment Forensics Engine
SIH26106 - Email Forensics
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
    ".iso",
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
}


def analyze_attachments(message):

    attachments = []
    suspicious = []
    findings = []

    if not hasattr(message, "walk"):
        return {
            "total": 0,
            "attachments": [],
            "suspicious_count": 0,
            "findings": [],
            "risk_level": "LOW",
        }

    try:

        for part in message.walk():

            filename = part.get_filename()

            if not filename:
                continue

            filename = str(filename)

            extension = os.path.splitext(
                filename.lower()
            )[1]

            content_type = (
                part.get_content_type()
            )

            payload = part.get_payload(
                decode=True
            )

            size = (
                len(payload)
                if payload
                else 0
            )

            # -----------------------------------------
            # Double extension detection
            # -----------------------------------------

            name_without_last = os.path.splitext(
                filename.lower()
            )[0]

            previous_extension = os.path.splitext(
                name_without_last
            )[1]

            double_extension = (
                previous_extension in
                DANGEROUS_EXTENSIONS
            )

            # -----------------------------------------
            # Risk classification
            # -----------------------------------------

            risks = []

            if extension in DANGEROUS_EXTENSIONS:

                risks.append(
                    "Potentially executable attachment"
                )

            if extension in SCRIPT_EXTENSIONS:

                risks.append(
                    "Script-based attachment"
                )

            if extension in ARCHIVE_EXTENSIONS:

                risks.append(
                    "Archive attachment requires inspection"
                )

            if double_extension:

                risks.append(
                    "Suspicious double-extension filename"
                )

            item = {
                "filename": filename,
                "extension": extension or "UNKNOWN",
                "content_type": content_type,
                "size_bytes": size,
                "is_executable": (
                    extension
                    in DANGEROUS_EXTENSIONS
                ),
                "is_script": (
                    extension
                    in SCRIPT_EXTENSIONS
                ),
                "is_archive": (
                    extension
                    in ARCHIVE_EXTENSIONS
                ),
                "double_extension": double_extension,
                "risks": risks,
            }

            attachments.append(item)

            if risks:

                suspicious.append(
                    filename
                )

                for risk in risks:

                    findings.append(
                        f"{filename}: {risk}"
                    )

    except Exception as error:

        findings.append(
            f"Attachment analysis error: {str(error)}"
        )

    # ---------------------------------------------
    # Overall risk
    # ---------------------------------------------

    if any(
        item["is_executable"]
        or item["double_extension"]
        for item in attachments
    ):

        risk_level = "HIGH"

    elif any(
        item["is_script"]
        or item["is_archive"]
        for item in attachments
    ):

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    return {

        "total": len(attachments),

        "attachments": attachments,

        "suspicious_count": len(
            suspicious
        ),

        "suspicious_files": suspicious,

        "findings": list(
            dict.fromkeys(findings)
        ),

        "risk_level": risk_level,

        "engine": {
            "name":
                "TARVEX26 Attachment Forensics Engine",

            "version":
                "1.0",

            "analysis_type":
                "Attachment metadata and risk analysis"
        }
    }