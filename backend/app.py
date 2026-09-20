from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from email import policy
from email.parser import BytesParser

import hashlib
from datetime import datetime, timezone
import uuid

from forensic.header_analyzer import analyze_headers
from forensic.ip_intelligence import analyze_ips
from forensic.threat_analyzer import analyze_threat
from forensic.origin_intelligence import analyze_origin
from forensic.geoip_analyzer import analyze_ips as analyze_geoip_ips
from forensic.correlation_analyzer import analyze_correlation
from forensic.infrastructure_correlator import build_infrastructure_graph


app = Flask(__name__)
CORS(app)


# ---------------------------------------------------------
# HOME PAGE
# ---------------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# ---------------------------------------------------------
# EMAIL ANALYSIS API
# ---------------------------------------------------------

@app.route("/analyze-email", methods=["POST"])
def analyze_email():

    if "email" not in request.files:
        return jsonify({
            "status": "error",
            "error": "No email file uploaded"
        }), 400

    email_file = request.files["email"]

    try:

        # -------------------------------------------------
        # 1. READ EMAIL
        # -------------------------------------------------

        email_bytes = email_file.read()
        # -----------------------------------------------------
        # EVIDENCE PRESERVATION
        # -----------------------------------------------------

        evidence_hash = hashlib.sha256(email_bytes).hexdigest()

        evidence_data = {
    "evidence_id": f"TRX-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}",
    "filename": email_file.filename,
    "file_size": len(email_bytes),
    "sha256": evidence_hash,
    "evidence_type": "EMAIL",
    "status": "PRESERVED",
    "preserved_at": datetime.now(timezone.utc).isoformat(),
}


        # -------------------------------------------------
        # 2. HEADER FORENSICS
        # -------------------------------------------------

        forensic_data = analyze_headers(email_bytes)

        ip_addresses = forensic_data.get(
            "ip_addresses",
            []
        )


        # -------------------------------------------------
        # 3. PARSE EMAIL
        # -------------------------------------------------

        message = BytesParser(
            policy=policy.default
        ).parsebytes(email_bytes)


        # -------------------------------------------------
        # 4. BASIC EMAIL HEADERS
        # -------------------------------------------------

        headers = {
            "from": message.get("From"),
            "to": message.get("To"),
            "subject": message.get("Subject"),
            "date": message.get("Date"),
            "reply_to": message.get("Reply-To"),
            "return_path": message.get("Return-Path"),
            "message_id": message.get("Message-ID")
        }


        # -------------------------------------------------
        # 5. IP INTELLIGENCE
        # -------------------------------------------------

        ip_intelligence = analyze_ips(
            ip_addresses
        )


        # -------------------------------------------------
        # 6. ORIGIN INTELLIGENCE
        # -------------------------------------------------

        origin_data = analyze_origin(
            ip_addresses
        )


        # -------------------------------------------------
        # 7. GEOIP INTELLIGENCE
        # -------------------------------------------------

        geoip_data = analyze_geoip_ips(
            ip_addresses
        )


        # -------------------------------------------------
        # 8. INFRASTRUCTURE CORRELATION
        # -------------------------------------------------

        infrastructure_graph = build_infrastructure_graph(
            headers,
            forensic_data,
            ip_intelligence,
            origin_data
        )


        # -------------------------------------------------
        # 9. CORRELATION ANALYSIS
        # -------------------------------------------------

        correlation_data = analyze_correlation(
            headers,
            forensic_data,
            origin_data
        )


        # -------------------------------------------------
        # 10. RECEIVED / RELAY HEADERS
        # -------------------------------------------------

        received_headers = message.get_all(
            "Received",
            []
        )


        # -------------------------------------------------
        # 11. EMAIL BODY
        # -------------------------------------------------

        body = ""

        if message.is_multipart():

            for part in message.walk():

                if part.get_content_type() == "text/plain":

                    try:
                        body = part.get_content()
                    except Exception:
                        body = ""

                    break

        else:

            try:
                body = message.get_content()
            except Exception:
                body = ""


        # -------------------------------------------------
        # 12. THREAT ANALYSIS
        # -------------------------------------------------

        threat_analysis = analyze_threat(
            headers,
            body,
            forensic_data
        )


        # -------------------------------------------------
        # 13. COMPLETE TARVEX26 RESPONSE
        # -------------------------------------------------

        return jsonify({

            "status": "success",

            "filename": email_file.filename,
            "evidence": evidence_data,

            # Basic email information
            "headers": headers,

            # Email body
            "body": body,

            # Relay information
            "received_headers": received_headers,

            # Header forensic intelligence
            "forensics": forensic_data,

            # IP intelligence
            "ip_intelligence": ip_intelligence,

            # Origin intelligence
            "origin_intelligence": origin_data,

            # GeoIP intelligence
            "geoip_intelligence": geoip_data,

            # Correlation analysis
            "correlation": correlation_data,

            # Infrastructure graph
            "infrastructure_graph": infrastructure_graph,

            # Threat detection
            "threat_analysis": threat_analysis
        })


    except Exception as e:

        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500


# ---------------------------------------------------------
# RUN APPLICATION
# ---------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)