import { useState } from "react";
import { motion } from "framer-motion";
import {
  ShieldCheck,
  Mail,
  Search,
  MapPin,
  Network,
  FileSearch,
  Upload,
  Activity,
  Server,
  Globe,
  Fingerprint,
  ShieldAlert,
} from "lucide-react";

import "./App.css";

function App() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [analysis, setAnalysis] = useState(null);
  const [error, setError] = useState("");

  const handleFileChange = (event) => {
    const file = event.target.files[0];

    if (!file) return;

    if (!file.name.toLowerCase().endsWith(".eml")) {
      setError("Please select a valid .eml email file.");
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
    setAnalysis(null);
    setError("");
  };

  const analyzeEmail = async () => {
    if (!selectedFile) {
      setError("Please select an .eml file first.");
      return;
    }

    setLoading(true);
    setError("");
    setAnalysis(null);

    const formData = new FormData();
    formData.append("email", selectedFile);

    try {
      const response = await fetch(
        "http://127.0.0.1:5000/analyze-email",
        {
          method: "POST",
          body: formData,
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Email analysis failed.");
      }

      setAnalysis(data);
    } catch (err) {
      setError(
        "Could not connect to the forensic backend. Make sure Flask is running."
      );
    } finally {
      setLoading(false);
    }
  };

  const forensic = analysis?.forensics;

  return (
    <div className="app">

      <div className="grid-background"></div>
      <div className="glow glow-one"></div>
      <div className="glow glow-two"></div>

      {/* Navigation */}
      <nav className="navbar">

        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={22} />
          </div>

          <div>
            <h2>
              TARVEX<span>26</span>
            </h2>
            <p>EMAIL FORENSICS</p>
          </div>
        </div>

        <div className="nav-links">
          <a className="active">Dashboard</a>
          <a>Cases</a>
          <a>Reports</a>
        </div>

        <div className="system-status">
          <span></span>
          SYSTEM ONLINE
        </div>

      </nav>

      <main className="main">

        {/* Hero */}
        <motion.div
          className="hero"
          initial={{ opacity: 0, y: 25 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7 }}
        >

          <div className="eyebrow">
            <Activity size={15} />
            AI-POWERED CYBER FORENSICS
          </div>

          <h1>
            Detect. Trace.
            <br />
            <span>Investigate.</span>
          </h1>

          <p className="hero-text">
            Analyze suspicious emails, uncover malicious infrastructure,
            trace probable origins and generate forensic intelligence.
          </p>

        </motion.div>

        {/* Upload */}
        <motion.div
          className="upload-card"
          initial={{ opacity: 0, scale: 0.97 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.2, duration: 0.6 }}
        >

          <div className="upload-icon">
            <Upload size={30} />
          </div>

          <h2>Analyze Suspicious Email</h2>

          <p>
            Upload a raw <strong>.eml</strong> file to begin forensic analysis
          </p>

          <label className="upload-button">

            <Mail size={18} />

            {selectedFile ? selectedFile.name : "Choose Email"}

            <input
              type="file"
              accept=".eml"
              hidden
              onChange={handleFileChange}
            />

          </label>

          {selectedFile && (
            <button
              className="analyze-button"
              onClick={analyzeEmail}
              disabled={loading}
            >
              {loading ? "ANALYZING..." : "ANALYZE EMAIL"}
            </button>
          )}

          <div className="upload-info">
            <span>SUPPORTED</span>
            <span>.EML</span>
            <span>•</span>
            <span>HEADER + BODY ANALYSIS</span>
          </div>

          {error && (
            <p className="error-message">
              {error}
            </p>
          )}

        </motion.div>

        {/* Analysis result */}
        {analysis && (
          <motion.div
            className="analysis-card"
            initial={{ opacity: 0, y: 25 }}
            animate={{ opacity: 1, y: 0 }}
          >

            {/* Result Header */}
            <div className="analysis-header">

              <div>
                <span className="result-label">
                  FORENSIC ANALYSIS COMPLETE
                </span>

                <h2>{analysis.filename}</h2>
              </div>

              <div className="success-status">
                ANALYZED
              </div>

            </div>

            {/* Basic Email Information */}
            <div className="analysis-grid">

              <InfoBox
                label="FROM"
                value={analysis.headers?.from || "Not available"}
              />

              <InfoBox
                label="TO"
                value={analysis.headers?.to || "Not available"}
              />

              <InfoBox
                label="SUBJECT"
                value={analysis.headers?.subject || "Not available"}
              />

              <InfoBox
                label="DATE"
                value={analysis.headers?.date || "Not available"}
              />

              <InfoBox
                label="REPLY-TO"
                value={analysis.headers?.reply_to || "Not available"}
              />

              <InfoBox
                label="RETURN-PATH"
                value={analysis.headers?.return_path || "Not available"}
              />

            </div>

            {/* Header Forensics */}
            {forensic && (
              <motion.div
                className="forensics-section"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.15 }}
              >

                <div className="section-heading">
                  <div>
                    <span className="result-label">
                      HEADER FORENSICS
                    </span>

                    <h3>
                      Authentication & Infrastructure Intelligence
                    </h3>
                  </div>

                  <Fingerprint size={24} />
                </div>

                {/* Authentication */}
                <div className="forensics-grid">

                  <ForensicBox
                    label="SPF"
                    value={forensic.spf || "Not available"}
                    icon={<ShieldCheck size={18} />}
                  />

                  <ForensicBox
                    label="DKIM"
                    value={forensic.dkim || "Not available"}
                    icon={<ShieldCheck size={18} />}
                  />

                  <ForensicBox
                    label="DMARC"
                    value={forensic.dmarc || "Not available"}
                    icon={<ShieldCheck size={18} />}
                  />

                  <ForensicBox
                    label="MESSAGE ID"
                    value={forensic.message_id || "Not available"}
                    icon={<Fingerprint size={18} />}
                  />

                </div>

                {/* IP Addresses */}
                <div className="intel-block">

                  <div className="intel-title">
                    <Server size={18} />
                    <span>IP ADDRESSES</span>
                  </div>

                  {forensic.ip_addresses?.length > 0 ? (
                    <div className="intel-list">
                      {forensic.ip_addresses.map((ip, index) => (
                        <span className="intel-tag" key={index}>
                          {ip}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <div className="empty-intel">
                      No IP addresses extracted.
                    </div>
                  )}

                </div>

                {/* Domains */}
                <div className="intel-block">

                  <div className="intel-title">
                    <Globe size={18} />
                    <span>DOMAINS</span>
                  </div>

                  {forensic.domains?.length > 0 ? (
                    <div className="intel-list">
                      {forensic.domains.map((domain, index) => (
                        <span className="intel-tag" key={index}>
                          {domain}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <div className="empty-intel">
                      No domains extracted.
                    </div>
                  )}

                </div>

                {/* Authentication Results */}
                <div className="intel-block">

                  <div className="intel-title">
                    <ShieldCheck size={18} />
                    <span>AUTHENTICATION RESULTS</span>
                  </div>

                  {forensic.authentication_results?.length > 0 ? (
                    forensic.authentication_results.map(
                      (result, index) => (
                        <div
                          className="received-item"
                          key={index}
                        >
                          {result}
                        </div>
                      )
                    )
                  ) : (
                    <div className="empty-intel">
                      No Authentication-Results header found.
                    </div>
                  )}

                </div>

                {/* Findings */}
                <div className="intel-block">

                  <div className="intel-title">
                    <ShieldAlert size={18} />
                    <span>FORENSIC FINDINGS</span>
                  </div>

                  {forensic.findings?.length > 0 ? (
                    forensic.findings.map((finding, index) => (
                      <div
                        className="finding-item"
                        key={index}
                      >
                        <ShieldAlert size={16} />
                        {finding}
                      </div>
                    ))
                  ) : (
                    <div className="finding-safe">
                      No basic header anomalies detected.
                    </div>
                  )}

                </div>

              </motion.div>
            )}

            {/* Received / Relay Headers */}
            <div className="received-section">

              <h3>RECEIVED / RELAY HEADERS</h3>

              {analysis.received_headers?.length > 0 ? (
                analysis.received_headers.map((header, index) => (
                  <div
                    className="received-item"
                    key={index}
                  >
                    {header}
                  </div>
                ))
              ) : (
                <div className="received-item">
                  No Received headers found.
                </div>
              )}

            </div>

          </motion.div>
        )}
                {/* Threat Assessment */}
        {analysis?.threat_analysis && (
          <motion.div
            className="threat-card"
            initial={{ opacity: 0, y: 25 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <div className="threat-header">
              <div>
                <span className="result-label">
                  THREAT DETECTION
                </span>

                <h2>Threat Assessment</h2>
              </div>

              <div className="threat-risk">
                {analysis.threat_analysis.risk_level || "UNKNOWN"}
              </div>
            </div>

            <div className="threat-score-section">

              <div className="score-box">
                <span>THREAT SCORE</span>

                <strong>
                  {analysis.threat_analysis.threat_score ?? 0}
                </strong>

                <small>/ 100</small>
              </div>

              <div className="threat-summary">
                <span>ANALYSIS SUMMARY</span>

                <p>
                  {analysis.threat_analysis.summary ||
                    "No threat summary available."}
                </p>
              </div>

            </div>

            <div className="indicators-section">

              <h3>DETECTED INDICATORS</h3>

              {analysis.threat_analysis.indicators?.length > 0 ? (
                analysis.threat_analysis.indicators.map(
                  (indicator, index) => (
                    <div
                      className="indicator-item"
                      key={index}
                    >
                      <span className="indicator-dot"></span>

                      <span>{indicator}</span>
                    </div>
                  )
                )
              ) : (
                <div className="no-indicators">
                  No suspicious indicators detected.
                </div>
              )}

            </div>

          </motion.div>
        )}

        {/* Feature cards */}
        <div className="features">

          <FeatureCard
            icon={<Search size={21} />}
            title="Threat Detection"
            description="Identify phishing, spoofing, impersonation and fraud indicators."
          />

          <FeatureCard
            icon={<FileSearch size={21} />}
            title="Header Forensics"
            description="Analyze SPF, DKIM, DMARC and email relay information."
          />

          <FeatureCard
            icon={<MapPin size={21} />}
            title="Origin Intelligence"
            description="Investigate IP addresses, domains and probable locations."
          />

          <FeatureCard
            icon={<Network size={21} />}
            title="Infrastructure Correlation"
            description="Connect emails, domains, IPs and related infrastructure."
          />

        </div>

        <footer>
          <span>TARVEX26</span>
          <span>•</span>
          <span>SIH 26106</span>
          <span>•</span>
          <span>EMAIL FORENSIC INTELLIGENCE</span>
        </footer>

      </main>
    </div>
  );
}


/* Basic information box */
function InfoBox({ label, value }) {
  return (
    <div className="info-box">
      <span>{label}</span>
      <p>{value}</p>
    </div>
  );
}


/* Forensic information box */
function ForensicBox({ label, value, icon }) {
  const status = String(value).toUpperCase();

  const isPass =
    status === "PASS" ||
    status === "OK";

  const isFail =
    status === "FAIL" ||
    status === "ERROR";

  return (
    <div
      className={`forensic-box ${
        isPass
          ? "status-pass"
          : isFail
            ? "status-fail"
            : ""
      }`}
    >

      <div className="forensic-box-icon">
        {icon}
      </div>

      <span>{label}</span>

      <strong>{value}</strong>

    </div>
  );
}


/* Feature card */
function FeatureCard({ icon, title, description }) {
  return (
    <motion.div
      className="feature-card"
      whileHover={{ y: -5 }}
    >

      <div className="feature-icon">
        {icon}
      </div>

      <h3>{title}</h3>

      <p>{description}</p>

    </motion.div>
  );
}


export default App;