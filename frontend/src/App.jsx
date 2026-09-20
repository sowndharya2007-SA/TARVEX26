import { useState, Fragment } from "react";
import { motion } from "framer-motion";
import InfrastructureGraph from "./InfrastructureGraph";
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
function CasesPage() {
  return (
    <section className="page-view">
      <div className="page-header">
        <span className="section-label">CASE MANAGEMENT</span>
        <h1>Forensic Cases</h1>
        <p>Manage and investigate preserved email evidence.</p>
      </div>

      <div className="case-grid">
        <div className="case-card">
          <span className="case-status">ACTIVE</span>
          <h3>TRX-20260920-FD40E6D7</h3>
          <p>forensic_test.eml</p>
          <small>Email Forensic Investigation</small>
        </div>

        <div className="case-card">
          <span className="case-status">PRESERVED</span>
          <h3>Digital Evidence</h3>
          <p>SHA-256 verified</p>
          <small>Evidence integrity maintained</small>
        </div>
      </div>
    </section>
  );
}

function ReportsPage() {
  return (
    <section className="page-view">
      <div className="page-header">
        <span className="section-label">FORENSIC REPORTING</span>
        <h1>Investigation Reports</h1>
        <p>Review generated forensic intelligence and evidence.</p>
      </div>

      <div className="report-grid">
        <div className="report-card">
          <span>FORENSIC ANALYSIS</span>
          <h3>Email Threat Investigation</h3>
          <p>Header, authentication, infrastructure and origin analysis.</p>
          <button>VIEW REPORT</button>
        </div>

        <div className="report-card">
          <span>DIGITAL EVIDENCE</span>
          <h3>Evidence Integrity Report</h3>
          <p>SHA-256 evidence fingerprint and preservation information.</p>
          <button>VIEW REPORT</button>
        </div>
      </div>
    </section>
  );
}

function App() {
  const [activePage, setActivePage] = useState("dashboard");
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
      console.error(err);
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

      {/* =====================================================
          NAVIGATION
      ===================================================== */}

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
          <button
  className={activePage === "dashboard" ? "active" : ""}
  onClick={() => setActivePage("dashboard")}
>
  Dashboard
</button>

<button
  className={activePage === "cases" ? "active" : ""}
  onClick={() => setActivePage("cases")}
>
  Cases
</button>

<button
  className={activePage === "reports" ? "active" : ""}
  onClick={() => setActivePage("reports")}
>
  Reports
</button>
        </div>

        <div className="system-status">
          <span></span>
          SYSTEM ONLINE
        </div>

      </nav>

      <main className="main">

        {/* =====================================================
            HERO
        ===================================================== */}

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

        {/* =====================================================
            UPLOAD
        ===================================================== */}

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

        {/* =====================================================
            ANALYSIS RESULT
        ===================================================== */}

        {analysis && (
          <motion.div
            className="analysis-card"
            initial={{ opacity: 0, y: 25 }}
            animate={{ opacity: 1, y: 0 }}
          >

            {/* RESULT HEADER */}

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

            {/* =================================================
                BASIC EMAIL INFORMATION
            ================================================= */}

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

            {/* =================================================
                HEADER FORENSICS
            ================================================= */}

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

                {/* AUTHENTICATION */}

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

                {/* IP ADDRESSES */}

                <div className="intel-block">

                  <div className="intel-title">
                    <Server size={18} />
                    <span>IP ADDRESSES</span>
                  </div>

                  {forensic.ip_addresses?.length > 0 ? (
                    <div className="intel-list">

                      {forensic.ip_addresses.map((ip, index) => (
                        <span
                          className="intel-tag"
                          key={index}
                        >
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

                {/* DOMAINS */}

                <div className="intel-block">

                  <div className="intel-title">
                    <Globe size={18} />
                    <span>DOMAINS</span>
                  </div>

                  {forensic.domains?.length > 0 ? (
                    <div className="intel-list">

                      {forensic.domains.map((domain, index) => (
                        <span
                          className="intel-tag"
                          key={index}
                        >
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

                {/* AUTHENTICATION RESULTS */}

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

                {/* FORENSIC FINDINGS */}

                <div className="intel-block">

                  <div className="intel-title">
                    <ShieldAlert size={18} />
                    <span>FORENSIC FINDINGS</span>
                  </div>

                  {forensic.findings?.length > 0 ? (

                    forensic.findings.map(
                      (finding, index) => (

                        <div
                          className="finding-item"
                          key={index}
                        >
                          <ShieldAlert size={16} />
                          {finding}
                        </div>

                      )
                    )

                  ) : (

                    <div className="finding-safe">
                      No basic header anomalies detected.
                    </div>

                  )}

                </div>

              </motion.div>
            )}

            {/* =================================================
                ORIGIN INTELLIGENCE
            ================================================= */}

            <div className="origin-section">

              <div className="section-heading">

                <MapPin size={20} />

                <div>
                  <span>ORIGIN INTELLIGENCE</span>
                  <h3>IP & Infrastructure Origin</h3>
                </div>

              </div>

              {analysis.geoip_intelligence?.results?.length > 0 ? (

                <div className="origin-grid">

                  {analysis.geoip_intelligence.results.map(
                    (ipInfo, index) => (

                      <div
                        className="origin-card"
                        key={index}
                      >

                        <div className="origin-card-header">

                          <span>IP ADDRESS</span>

                          <strong>
                            {ipInfo.ip}
                          </strong>

                        </div>

                        <div className="origin-details">

                          <div>
                            <span>TYPE</span>
                            <p>{ipInfo.type}</p>
                          </div>

                          <div>
                            <span>IP VERSION</span>
                            <p>IPv{ipInfo.version}</p>
                          </div>

                          <div>
                            <span>COUNTRY</span>
                            <p>{ipInfo.country}</p>
                          </div>

                          <div>
                            <span>CITY</span>
                            <p>{ipInfo.city}</p>
                          </div>

                          <div>
                            <span>ORGANIZATION</span>
                            <p>{ipInfo.organization}</p>
                          </div>

                          <div>
                            <span>ASN</span>
                            <p>{ipInfo.asn}</p>
                          </div>

                        </div>

                      </div>

                    )
                  )}

                </div>

              ) : (

                <div className="origin-empty">
                  No IP intelligence available.
                </div>

              )}

            </div>

            {/* =================================================
                RECEIVED / RELAY HEADERS
            ================================================= */}

            <div className="received-section">

              <h3>RECEIVED / RELAY HEADERS</h3>

              {analysis.received_headers?.length > 0 ? (

                analysis.received_headers.map(
                  (header, index) => (

                    <div
                      className="received-item"
                      key={index}
                    >
                      {header}
                    </div>

                  )
                )

              ) : (

                <div className="received-item">
                  No Received headers found.
                </div>

              )}

            </div>

          </motion.div>
        )}
        {/* =====================================================
    DIGITAL EVIDENCE
===================================================== */}

{analysis?.evidence && (
  <motion.section
    className="evidence-section"
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.5 }}
  >

    <div className="evidence-top">

      <div>
        <span className="result-label">
          DIGITAL EVIDENCE
        </span>

        <h3>Evidence Preservation</h3>

        <p>
          Cryptographic verification of the original email evidence.
        </p>
      </div>

      <div className="evidence-badge">
        <ShieldCheck size={17} />
        VERIFIED
      </div>

    </div>


    <div className="evidence-main">

      {/* EVIDENCE ID */}

      <div className="evidence-item evidence-wide">
        <span>EVIDENCE ID</span>

        <strong>
          {analysis.evidence.evidence_id || "N/A"}
        </strong>
      </div>


      {/* FILE */}

      <div className="evidence-item">
        <span>FILE</span>

        <strong>
          {analysis.evidence.filename || "N/A"}
        </strong>
      </div>


      {/* SIZE */}

      <div className="evidence-item">
        <span>SIZE</span>

        <strong>
          {analysis.evidence.file_size
            ? `${analysis.evidence.file_size} bytes`
            : "N/A"}
        </strong>
      </div>


      {/* TYPE */}

      <div className="evidence-item">
        <span>TYPE</span>

        <strong>
          {analysis.evidence.evidence_type || "EMAIL"}
        </strong>
      </div>


      {/* STATUS */}

      <div className="evidence-item">
        <span>STATUS</span>

        <strong className="evidence-valid">
          {analysis.evidence.status || "PRESERVED"}
        </strong>
      </div>

    </div>


    {/* HASH */}

    <div className="evidence-hash">

      <div className="hash-title">
        <Fingerprint size={16} />
        <span>SHA-256 EVIDENCE HASH</span>
      </div>

      <code>
        {analysis.evidence.sha256 || "Hash unavailable"}
      </code>

      <p>
        Digital fingerprint generated from the uploaded email.
        Used to verify evidence integrity.
      </p>

    </div>


    {/* TIMESTAMP */}

    <div className="evidence-time">

      <span>PRESERVED AT</span>

      <strong>
        {analysis.evidence.preserved_at
          ? new Date(
              analysis.evidence.preserved_at
            ).toLocaleString()
          : "N/A"}
      </strong>

    </div>

  </motion.section>
)}


        {/* =====================================================
    INFRASTRUCTURE CORRELATION
===================================================== */}

{analysis?.infrastructure_graph && (
  <InfrastructureGraph
    infrastructureGraph={analysis.infrastructure_graph}
  />
)}
        {/* =====================================================
            THREAT ASSESSMENT
        ===================================================== */}

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

                <h2>
                  Threat Assessment
                </h2>

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

              <h3>
                DETECTED INDICATORS
              </h3>

              {analysis.threat_analysis.indicators?.length > 0 ? (

                analysis.threat_analysis.indicators.map(
                  (indicator, index) => (

                    <div
                      className="indicator-item"
                      key={index}
                    >

                      <span className="indicator-dot"></span>

                      <span>
                        {indicator}
                      </span>

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

        {/* =====================================================
            FEATURE CARDS
        ===================================================== */}

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

        {/* FOOTER */}

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


/* =========================================================
   INFO BOX
========================================================= */

function InfoBox({ label, value }) {

  return (
    <div className="info-box">

      <span>{label}</span>

      <p>{value}</p>

    </div>
  );
}


/* =========================================================
   FORENSIC BOX
========================================================= */

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


/* =========================================================
   FEATURE CARD
========================================================= */

function FeatureCard({
  icon,
  title,
  description
}) {

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