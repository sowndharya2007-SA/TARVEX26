# TARVEX26

## AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

TARVEX26 is an AI-powered email threat detection and forensic intelligence platform developed for **Smart India Hackathon 2026 – Problem Statement SIH26106** under the **Blockchain & Cybersecurity** theme.

The platform provides an end-to-end workflow for analyzing suspicious emails, identifying threat indicators, tracing associated infrastructure, enriching findings with intelligence, preserving digital evidence, and generating forensic reports.

---

## 🎯 Problem Statement

Email-based attacks such as phishing, spoofing, impersonation, fraud, credential theft, and malware delivery are difficult to investigate because important evidence is distributed across email headers, IP addresses, domains, URLs, and attachments.

Traditional investigation workflows often require multiple tools, making source tracing, threat correlation, and forensic analysis time-consuming and complex.

**TARVEX26 brings these capabilities together into a unified forensic investigation platform.**

---

## 🚀 Key Features

### 📧 Email Header Forensics

- From, To and Reply-To analysis
- Return-Path analysis
- Message-ID extraction
- Received-header analysis
- SPF, DKIM and DMARC analysis
- Authentication anomaly detection
- Sender and Reply-To domain correlation

### 🛡️ Threat Detection

- Phishing detection
- Social engineering indicators
- Credential-targeting detection
- Suspicious URL detection
- Suspicious attachment detection
- Explainable threat scoring
- Risk classification

### 🌐 IP & GeoLocation Intelligence

- IPv4 and IPv6 extraction
- Public, private and special-purpose IP classification
- IP GeoLocation enrichment
- Country, region and city information
- ISP and organization information
- ASN identification
- Reverse DNS information
- Network infrastructure intelligence

### 🔗 Domain Intelligence

- DNS analysis
- A record analysis
- MX record analysis
- NS record analysis
- SPF and DMARC record analysis
- Domain registration information
- Domain infrastructure correlation

### 🔍 URL Intelligence

- HTTP/HTTPS analysis
- Suspicious domain pattern detection
- Credential-oriented URL detection
- Suspicious path analysis
- URL risk assessment

### 📎 Attachment Intelligence

- Executable file detection
- Double-extension detection
- Suspicious filename analysis
- Attachment risk assessment
- File metadata analysis

### 🧠 Threat Intelligence

- External IOC correlation
- ThreatFox integration
- Threat intelligence enrichment
- IOC matching
- Investigation findings

### 🕸️ Infrastructure Correlation

TARVEX26 correlates email indicators and visualizes relationships between:

```text
Email
  ↓
Domains
  ↓
IP Addresses
  ↓
Infrastructure
  ↓
Relays / Related Indicators
🔐 Digital Evidence Preservation
Evidence ID generation
SHA-256 evidence hashing
Evidence preservation
Chain of custody
Integrity verification
Evidence status tracking
📄 Automated Forensic Reporting

TARVEX26 generates structured forensic reports containing:

Case information
Evidence information
Threat assessment
Authentication results
Extracted indicators
Infrastructure findings
Investigation results
Evidence information
🔄 System Workflow
Suspicious Email
       ↓
Evidence Extraction
       ↓
Header & Content Analysis
       ↓
Threat Detection
       ↓
IP / Domain / URL / Attachment Intelligence
       ↓
GeoLocation & Threat Intelligence
       ↓
Infrastructure Correlation
       ↓
Digital Evidence Preservation
       ↓
Forensic Report
Investigation Workflow
DETECT
   ↓
TRACE
   ↓
CORRELATE
   ↓
ENRICH
   ↓
INVESTIGATE
   ↓
PRESERVE
   ↓
REPORT
🏗️ System Architecture
                    TARVEX26
                       │
              ┌────────┴────────┐
              │                 │
          React.js            Flask
          Frontend            Backend
              │                 │
              │          ┌──────┴──────┐
              │          │             │
              │      Forensic       Intelligence
              │      Analysis         Sources
              │          │             │
              │          ├─ Headers    ├─ ThreatFox
              │          ├─ IPs        ├─ GeoIP
              │          ├─ Domains    └─ DNS
              │          ├─ URLs
              │          └─ Attachments
              │
              └──────────────┐
                             ↓
                       Investigation
                         Dashboard
                             │
                             ↓
                      Forensic Report
🛠️ Technology Stack
Frontend
React.js
Vite
JavaScript
HTML5
CSS3
Framer Motion
React Leaflet
Lucide React
Backend
Python
Flask
Flask-CORS
Python Email Parser
Requests
dnspython
python-dotenv
Gunicorn
Security & Intelligence
Email Header Forensics
IP Intelligence
GeoLocation Intelligence
DNS Intelligence
Threat Intelligence
ThreatFox
URL Intelligence
Attachment Analysis
Infrastructure Correlation
Evidence & Forensics
SHA-256
Digital Evidence Preservation
Chain of Custody
Integrity Verification
Automated Forensic Reporting
Deployment & Version Control
Git
GitHub
Render
Gunicorn
📁 Project Structure
TARVEX26/
│
├── backend/
│   ├── app.py
│   ├── requirements.txt
│   │
│   ├── templates/
│   │   └── index.html
│   │
│   └── forensic/
│       ├── __init__.py
│       ├── header_analyzer.py
│       ├── ip_intelligence.py
│       ├── threat_analyzer.py
│       ├── origin_intelligence.py
│       ├── geoip_analyzer.py
│       ├── correlation_analyzer.py
│       ├── infrastructure_correlator.py
│       ├── url_intelligence.py
│       ├── attachment_analyzer.py
│       ├── domain_intelligence.py
│       ├── network_anonymization.py
│       ├── threat_intelligence.py
│       ├── report_generator.py
│       └── chain_of_custody.py
│
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── assets/
│   │   ├── App.jsx
│   │   ├── App.css
│   │   ├── Dashboard.jsx
│   │   ├── GeoLocationMap.jsx
│   │   ├── InfrastructureGraph.jsx
│   │   ├── ThreatIntelligencePanel.jsx
│   │   ├── CyberBackground.jsx
│   │   ├── index.css
│   │   └── main.jsx
│   │
│   ├── package.json
│   └── vite.config.js
│
├── data/
├── models/
├── reports/
├── .gitignore
└── README.md