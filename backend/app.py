from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from email import policy
from email.parser import BytesParser

from forensic.header_analyzer import analyze_headers


app = Flask(__name__)
CORS(app)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze-email", methods=["POST"])
def analyze_email():

    if "email" not in request.files:
        return jsonify({
            "error": "No email file uploaded"
        }), 400

    email_file = request.files["email"]

    # Read the uploaded email once
    email_bytes = email_file.read()

    # Run TARVEX26 forensic header analysis
    forensic_data = analyze_headers(email_bytes)

    try:
        # Parse the same email bytes
        raw_email = email_bytes

        message = BytesParser(
            policy=policy.default
        ).parsebytes(raw_email)

        # Basic email headers
        headers = {
            "from": message.get("From"),
            "to": message.get("To"),
            "subject": message.get("Subject"),
            "date": message.get("Date"),
            "reply_to": message.get("Reply-To"),
            "return_path": message.get("Return-Path"),
            "message_id": message.get("Message-ID")
        }

        # Received / relay headers
        received_headers = message.get_all("Received", [])

        # Extract email body
        body = ""

        if message.is_multipart():

            for part in message.walk():

                if part.get_content_type() == "text/plain":
                    body = part.get_content()
                    break

        else:
            body = message.get_content()

        # Return complete TARVEX26 analysis
        return jsonify({

            "status": "success",

            "filename": email_file.filename,

            # Basic email information
            "headers": headers,

            # Existing relay information
            "received_headers": received_headers,

            # Email body
            "body": body,

            # New forensic intelligence
            "forensics": forensic_data
        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


if __name__ == "__main__":
    app.run(debug=True)