"""
TARVEX26
Digital Evidence Chain of Custody Engine
SIH26106 - Email Threat Detection and Forensic Intelligence

Purpose:
- Create forensic case/evidence identifiers
- Preserve SHA-256 evidence integrity
- Track acquisition and analysis events
- Generate a structured chain-of-custody timeline
- Provide verification information for forensic reporting
"""

import hashlib
import uuid
from datetime import datetime, timezone


ENGINE_NAME = "TARVEX26 Digital Evidence Chain of Custody"
ENGINE_VERSION = "1.0"


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _generate_case_id():
    date_part = datetime.now().strftime("%Y%m%d")
    random_part = uuid.uuid4().hex[:8].upper()

    return f"CASE-{date_part}-{random_part}"


def _generate_evidence_id():
    date_part = datetime.now().strftime("%Y%m%d")
    random_part = uuid.uuid4().hex[:8].upper()

    return f"TRX-{date_part}-{random_part}"


def calculate_sha256(data):
    """
    Calculate SHA-256 hash for evidence bytes.
    """

    if data is None:
        data = b""

    if isinstance(data, str):
        data = data.encode("utf-8")

    return hashlib.sha256(data).hexdigest()


def create_chain_of_custody(
    evidence_bytes,
    filename="unknown.eml",
    evidence_type="EMAIL"
):
    """
    Create a complete chain-of-custody record for an email evidence file.
    """

    now = _utc_now()

    evidence_hash = calculate_sha256(evidence_bytes)

    case_id = _generate_case_id()
    evidence_id = _generate_evidence_id()

    file_size = len(evidence_bytes) if evidence_bytes else 0

    events = [
        {
            "event_id": "E01",
            "event_type": "EVIDENCE_ACQUIRED",
            "description": "Email evidence file acquired for forensic analysis.",
            "timestamp": now,
            "status": "COMPLETED"
        },
        {
            "event_id": "E02",
            "event_type": "HASH_GENERATED",
            "description": "SHA-256 integrity hash generated for acquired evidence.",
            "timestamp": now,
            "status": "COMPLETED"
        },
        {
            "event_id": "E03",
            "event_type": "EVIDENCE_PRESERVED",
            "description": "Original evidence metadata preserved before analysis.",
            "timestamp": now,
            "status": "COMPLETED"
        },
        {
            "event_id": "E04",
            "event_type": "FORENSIC_ANALYSIS_STARTED",
            "description": "Automated TARVEX26 forensic analysis initiated.",
            "timestamp": now,
            "status": "COMPLETED"
        }
    ]

    return {
        "case_id": case_id,
        "evidence_id": evidence_id,

        "evidence": {
            "filename": filename,
            "evidence_type": evidence_type,
            "file_size": file_size,
            "sha256": evidence_hash,
            "hash_algorithm": "SHA-256"
        },

        "integrity": {
            "status": "VERIFIED",
            "hash": evidence_hash,
            "hash_algorithm": "SHA-256",
            "original_hash": evidence_hash,
            "verification": "INITIAL_HASH_RECORDED"
        },

        "custody": {
            "status": "PRESERVED",
            "acquired_at": now,
            "preserved_at": now,
            "analysis_started_at": now,
            "current_state": "FORENSIC_ANALYSIS"
        },

        "timeline": events,

        "chain_of_custody": {
            "event_count": len(events),
            "events": events,
            "continuity": "INTACT"
        },

        "engine": {
            "name": ENGINE_NAME,
            "version": ENGINE_VERSION,
            "capabilities": [
                "Evidence identification",
                "SHA-256 integrity hashing",
                "Evidence preservation",
                "Acquisition timestamp",
                "Forensic analysis tracking",
                "Chain-of-custody timeline"
            ]
        },

        "status": "PRESERVED",
        "created_at": now
    }


def verify_evidence_integrity(original_hash, evidence_bytes):
    """
    Recalculate SHA-256 and compare it with the preserved hash.
    """

    current_hash = calculate_sha256(evidence_bytes)

    if not original_hash:
        return {
            "status": "UNVERIFIED",
            "match": False,
            "original_hash": None,
            "current_hash": current_hash,
            "message": "Original evidence hash was not supplied."
        }

    match = current_hash.lower() == original_hash.lower()

    return {
        "status": "VERIFIED" if match else "INTEGRITY_COMPROMISED",
        "match": match,
        "original_hash": original_hash,
        "current_hash": current_hash,
        "message": (
            "Evidence integrity verified. SHA-256 hashes match."
            if match
            else
            "Evidence integrity check failed. SHA-256 hashes do not match."
        )
    }


def complete_analysis_event(chain_data):
    """
    Add a forensic analysis completion event to an existing custody record.
    """

    if not isinstance(chain_data, dict):
        return chain_data

    now = _utc_now()

    timeline = chain_data.setdefault("timeline", [])

    completion_event = {
        "event_id": f"E{len(timeline) + 1:02d}",
        "event_type": "FORENSIC_ANALYSIS_COMPLETED",
        "description": "TARVEX26 forensic analysis completed.",
        "timestamp": now,
        "status": "COMPLETED"
    }

    timeline.append(completion_event)

    chain_data["chain_of_custody"] = {
        "event_count": len(timeline),
        "events": timeline,
        "continuity": "INTACT"
    }

    chain_data.setdefault("custody", {})
    chain_data["custody"]["analysis_completed_at"] = now
    chain_data["custody"]["current_state"] = "ANALYSIS_COMPLETED"

    chain_data["status"] = "ANALYSIS_COMPLETED"

    return chain_data


def generate_custody_summary(chain_data):
    """
    Generate a compact summary suitable for dashboard/report display.
    """

    if not isinstance(chain_data, dict):
        return {
            "status": "ERROR",
            "message": "Invalid chain-of-custody data."
        }

    evidence = chain_data.get("evidence", {})
    integrity = chain_data.get("integrity", {})
    custody = chain_data.get("custody", {})
    custody_data = chain_data.get("chain_of_custody", {})

    return {
        "case_id": chain_data.get("case_id"),
        "evidence_id": chain_data.get("evidence_id"),
        "filename": evidence.get("filename"),
        "file_size": evidence.get("file_size"),
        "sha256": evidence.get("sha256"),
        "integrity_status": integrity.get("status"),
        "evidence_status": chain_data.get("status"),
        "acquired_at": custody.get("acquired_at"),
        "preserved_at": custody.get("preserved_at"),
        "analysis_started_at": custody.get("analysis_started_at"),
        "analysis_completed_at": custody.get("analysis_completed_at"),
        "custody_continuity": custody_data.get("continuity"),
        "event_count": custody_data.get("event_count", 0)
    }


if __name__ == "__main__":
    print("=" * 60)
    print("TARVEX26 CHAIN OF CUSTODY TEST")
    print("=" * 60)

    sample_email = b"""
From: security@example.com
To: investigator@example.com
Subject: Forensic Test Email

This is a TARVEX26 forensic test.
"""

    chain = create_chain_of_custody(
        sample_email,
        filename="forensic_test.eml",
        evidence_type="EMAIL"
    )

    chain = complete_analysis_event(chain)

    print("\nCASE ID:")
    print(chain["case_id"])

    print("\nEVIDENCE ID:")
    print(chain["evidence_id"])

    print("\nSHA-256:")
    print(chain["evidence"]["sha256"])

    print("\nINTEGRITY:")
    print(chain["integrity"]["status"])

    print("\nEVIDENCE STATUS:")
    print(chain["status"])

    print("\nCHAIN EVENTS:")
    for event in chain["timeline"]:
        print(
            f"{event['event_id']} | "
            f"{event['event_type']} | "
            f"{event['status']}"
        )

    verification = verify_evidence_integrity(
        chain["evidence"]["sha256"],
        sample_email
    )

    print("\nINTEGRITY VERIFICATION:")
    print(verification["status"])

    print("\nSUMMARY:")
    print(generate_custody_summary(chain))

    print("\n" + "=" * 60)
    print("CHAIN OF CUSTODY TEST COMPLETE")
    print("=" * 60)