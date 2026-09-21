import { useState } from "react";
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
  Globe,
  Fingerprint,
  ShieldAlert,
  FileText,
  Database,
  Hash,
  Server,
} from "lucide-react";

import "./App.css";


/* =========================================================
   CASES PAGE
========================================================= */

function CasesPage({ analysis, onOpenInvestigation }) {
  return (
    <section className="page-view">

      <div className="page-header">
        <span className="section-label">
          CASE MANAGEMENT
        </span>

        <h1>
          Forensic Cases
        </h1>

        <p>
          Manage and investigate preserved email evidence.
        </p>
      </div>

      {analysis?.evidence ? (

        <div className="case-grid">

          <motion.div
            className="case-card"
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            whileHover={{ y: -5 }}
            onClick={onOpenInvestigation}
            style={{ cursor: "pointer" }}
          >

            <div className="case-card-top">
              <span className="case-status">
                ACTIVE
              </span>

              <ShieldCheck size={20} />
            </div>

            <h3>
              {analysis.evidence.evidence_id || "CASE"}
            </h3>

            <p>
              {analysis.evidence.filename || "Email evidence"}
            </p>

            <small>
              Email Forensic Investigation
            </small>

          </motion.div>


          <motion.div
            className="case-card"
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            whileHover={{ y: -5 }}
            onClick={onOpenInvestigation}
            style={{ cursor: "pointer" }}
          >

            <div className="case-card-top">
              <span className="case-status">
                PRESERVED
              </span>

              <Fingerprint size={20} />
            </div>

            <h3>
              Digital Evidence
            </h3>

            <p>
              SHA-256 verified
            </p>

            <small>
              Evidence integrity maintained
            </small>

          </motion.div>

        </div>

      ) : (

        <div className="empty-page-state">

          <Database size={42} />

          <h2>
            No active cases
          </h2>

          <p>
            Analyze an .eml file from the Dashboard
            to create a forensic investigation.
          </p>

        </div>

      )}

    </section>
  );
}


/* =========================================================
   REPORTS PAGE
========================================================= */

function ReportsPage({ analysis, onOpenSection }) {
  return (
    <section className="page-view">

      <div className="page-header">

        <span className="section-label">
          FORENSIC REPORTING
        </span>

        <h1>
          Investigation Reports
        </h1>

        <p>
          Review generated forensic intelligence and evidence.
        </p>

      </div>


      {analysis ? (

        <div className="report-grid">

          <motion.div
            className="report-card"
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            whileHover={{ y: -5 }}
            onClick={() => onOpenSection("overview")}
            style={{ cursor: "pointer" }}
          >

            <span>
              FORENSIC ANALYSIS
            </span>

            <h3>
              Email Threat Investigation
            </h3>

            <p>
              Header, authentication, infrastructure,
              origin and threat analysis.
            </p>

            <div className="report-meta">

              <FileText size={16} />

              <span>
                {analysis.filename || "Email evidence"}
              </span>

            </div>

          </motion.div>


          <motion.div
            className="report-card"
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            whileHover={{ y: -5 }}
            onClick={() => onOpenSection("evidence")}
            style={{ cursor: "pointer" }}
          >

            <span>
              DIGITAL EVIDENCE
            </span>

            <h3>
              Evidence Integrity Report
            </h3>

            <p>
              SHA-256 evidence fingerprint and
              preservation information.
            </p>

            <div className="report-meta">

              <Hash size={16} />

              <span>
                {analysis.evidence?.sha256
                  ? "SHA-256 VERIFIED"
                  : "HASH UNAVAILABLE"}
              </span>

            </div>

          </motion.div>


          <motion.div
            className="report-card"
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            whileHover={{ y: -5 }}
            onClick={() => onOpenSection("threat")}
            style={{ cursor: "pointer" }}
          >

            <span>
              THREAT INTELLIGENCE
            </span>

            <h3>
              Threat Assessment
            </h3>

            <p>
              Risk classification and detected
              suspicious indicators.
            </p>

            <div className="report-meta">

              <ShieldAlert size={16} />

              <span>
                {analysis.threat_analysis?.risk_level ||
                  "UNKNOWN"}
              </span>

            </div>

          </motion.div>


          <motion.div
            className="report-card"
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            whileHover={{ y: -5 }}
            onClick={() => onOpenSection("origin")}
            style={{ cursor: "pointer" }}
          >

            <span>
              ORIGIN INTELLIGENCE
            </span>

            <h3>
              Origin Investigation
            </h3>

            <p>
              Candidate origin IP, geolocation,
              ISP, ASN and infrastructure analysis.
            </p>

            <div className="report-meta">

              <Globe size={16} />

              <span>
                {analysis.origin_intelligence?.origin?.ip ||
                  "ORIGIN UNKNOWN"}
              </span>

            </div>

          </motion.div>

        </div>

      ) : (

        <div className="empty-page-state">

          <FileText size={42} />

          <h2>
            No reports available
          </h2>

          <p>
            Analyze an email from the Dashboard
            to generate forensic reports.
          </p>

        </div>

      )}

    </section>
  );
}


/* =========================================================
   MAIN APP
========================================================= */

function App() {

  const [selectedFile, setSelectedFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [analysis, setAnalysis] = useState(null);
  const [error, setError] = useState("");

  const [activePage, setActivePage] = useState("dashboard");

  const [
    activeAnalysisSection,
    setActiveAnalysisSection
  ] = useState("overview");


  /* =======================================================
     FILE SELECTION
  ======================================================= */

  const handleFileChange = (event) => {

    const file = event.target.files[0];

    if (!file) {
      return;
    }

    if (!file.name.toLowerCase().endsWith(".eml")) {

      setError(
        "Please select a valid .eml email file."
      );

      setSelectedFile(null);

      return;
    }

    setSelectedFile(file);
    setAnalysis(null);
    setError("");
    setActiveAnalysisSection("overview");
  };


  /* =======================================================
     EMAIL ANALYSIS
  ======================================================= */

  const analyzeEmail = async () => {

    if (!selectedFile) {

      setError(
        "Please select an .eml file first."
      );

      return;
    }

    setLoading(true);
    setError("");
    setAnalysis(null);

    const formData = new FormData();

    formData.append(
      "email",
      selectedFile
    );

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

        throw new Error(
          data.error ||
          "Email analysis failed."
        );
      }

      setAnalysis(data);

      setActivePage("dashboard");
      setActiveAnalysisSection("overview");

    } catch (err) {

      console.error(err);

      setError(
        "Could not connect to the forensic backend. " +
        "Make sure Flask is running."
      );

    } finally {

      setLoading(false);

    }
  };


  /* =======================================================
     NAVIGATION HELPERS
  ======================================================= */

  const openInvestigation = (section = "overview") => {

    setActivePage("dashboard");
    setActiveAnalysisSection(section);

    window.scrollTo({
      top: 0,
      behavior: "smooth"
    });
  };


  /* =======================================================
     FORENSIC DATA
  ======================================================= */

  const forensic = analysis?.forensics;

  const ipIntelligence =
    analysis?.ip_intelligence;

  const originIntelligence =
    analysis?.origin_intelligence ||
    analysis?.geoip_intelligence;

  const candidateOrigin =
    originIntelligence?.origin;


  /* =======================================================
     APPLICATION
  ======================================================= */

  return (

    <div className="app">

      <div className="grid-background"></div>

      <div className="glow glow-one"></div>

      <div className="glow glow-two"></div>


      {/* =================================================
          NAVIGATION
      ================================================= */}

      <nav className="navbar">

        <div className="brand">

          <div className="brand-icon">
            <ShieldCheck size={22} />
          </div>

          <div>

            <h2>
              TARVEX<span>26</span>
            </h2>

            <p>
              EMAIL FORENSICS
            </p>

          </div>

        </div>


        <div className="nav-links">

          <a
            className={
              activePage === "dashboard"
                ? "active"
                : ""
            }
            onClick={() =>
              setActivePage("dashboard")
            }
          >
            Dashboard
          </a>


          <a
            className={
              activePage === "cases"
                ? "active"
                : ""
            }
            onClick={() =>
              setActivePage("cases")
            }
          >
            Cases
          </a>


          <a
            className={
              activePage === "reports"
                ? "active"
                : ""
            }
            onClick={() =>
              setActivePage("reports")
            }
          >
            Reports
          </a>

        </div>


        <div className="system-status">

          <span></span>

          SYSTEM ONLINE

        </div>

      </nav>


      {/* =================================================
          MAIN
      ================================================= */}

      <main className="main">


        {/* =================================================
            CASES PAGE
        ================================================= */}

        {activePage === "cases" && (

          <CasesPage
            analysis={analysis}
            onOpenInvestigation={() =>
              openInvestigation("overview")
            }
          />

        )}


        {/* =================================================
            REPORTS PAGE
        ================================================= */}

        {activePage === "reports" && (

          <ReportsPage
            analysis={analysis}
            onOpenSection={openInvestigation}
          />

        )}


        {/* =================================================
            DASHBOARD
        ================================================= */}

        {activePage === "dashboard" && (

          <>


            {/* =================================================
                HERO
            ================================================= */}

            <motion.div
              className="hero"
              initial={{
                opacity: 0,
                y: 25
              }}
              animate={{
                opacity: 1,
                y: 0
              }}
              transition={{
                duration: 0.7
              }}
            >

              <div className="eyebrow">

                <Activity size={15} />

                AI-POWERED CYBER FORENSICS

              </div>


              <h1>

                Detect. Trace.

                <br />

                <span>
                  Investigate.
                </span>

              </h1>


              <p className="hero-text">

                Analyze suspicious emails,
                uncover malicious infrastructure,
                trace probable origins and
                generate forensic intelligence.

              </p>

            </motion.div>


            {/* =================================================
                EMAIL UPLOAD
            ================================================= */}

            <motion.div
              className="upload-card"
              initial={{
                opacity: 0,
                scale: 0.97
              }}
              animate={{
                opacity: 1,
                scale: 1
              }}
              transition={{
                delay: 0.2,
                duration: 0.6
              }}
            >

              <div className="upload-icon">
                <Upload size={30} />
              </div>


              <h2>
                Analyze Suspicious Email
              </h2>


              <p>

                Upload a raw
                <strong> .eml </strong>
                file to begin forensic analysis

              </p>


              <label className="upload-button">

                <Mail size={18} />

                {selectedFile
                  ? selectedFile.name
                  : "Choose Email"}

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

                  {loading
                    ? "ANALYZING..."
                    : "ANALYZE EMAIL"}

                </button>

              )}


              <div className="upload-info">

                <span>
                  SUPPORTED
                </span>

                <span>
                  .EML
                </span>

                <span>
                  •
                </span>

                <span>
                  HEADER + BODY ANALYSIS
                </span>

              </div>


              {error && (

                <p className="error-message">
                  {error}
                </p>

              )}

            </motion.div>


            {/* =================================================
                FORENSIC CASE HEADER
            ================================================= */}

            {analysis && (

              <motion.section
                className="case-header"
                initial={{
                  opacity: 0,
                  y: 15
                }}
                animate={{
                  opacity: 1,
                  y: 0
                }}
                transition={{
                  duration: 0.4
                }}
              >

                <div className="case-header-top">

                  <div className="case-identity">

                    <div className="case-status-line">

                      <span className="status-dot"></span>

                      ACTIVE FORENSIC INVESTIGATION

                    </div>


                    <h2>

                      {analysis.evidence?.evidence_id ||
                        "TRX-UNASSIGNED"}

                    </h2>


                    <p className="case-file-name">

                      <Mail size={14} />

                      {analysis.evidence?.filename ||
                        analysis.filename ||
                        "Email evidence"}

                    </p>

                  </div>


                  <div className="case-analysis-status">

                    <div className="case-complete">

                      <ShieldCheck size={15} />

                      ANALYSIS COMPLETE

                    </div>

                    <span>
                      EMAIL EVIDENCE
                    </span>

                  </div>

                </div>


                {/* CASE INTELLIGENCE */}

                <div className="case-intelligence">


                  <div className="case-intelligence-item">

                    <div className="case-intelligence-icon threat-icon">
                      <ShieldAlert size={17} />
                    </div>


                    <div>

                      <span>
                        THREAT ASSESSMENT
                      </span>

                      <strong>

                        {analysis.threat_analysis?.threat_score ??
                          analysis.threat_analysis?.fraud_score ??
                          analysis.threat_analysis?.score ??
                          "N/A"}

                        {(

                          analysis.threat_analysis?.threat_score !== undefined ||
                          analysis.threat_analysis?.fraud_score !== undefined ||
                          analysis.threat_analysis?.score !== undefined

                        ) && (

                          <small>
                            /100
                          </small>

                        )}

                      </strong>

                      <em>
                        FORENSIC RISK
                      </em>

                    </div>

                  </div>


                  <div className="case-intelligence-item">

                    <div className="case-intelligence-icon">
                      <Globe size={17} />
                    </div>


                    <div>

                      <span>
                        ORIGIN INDICATORS
                      </span>

                      <strong>
                        {analysis.forensics?.ip_addresses?.length || 0}
                      </strong>

                      <em>
                        IP ADDRESSES
                      </em>

                    </div>

                  </div>


                  <div className="case-intelligence-item">

                    <div className="case-intelligence-icon">
                      <Network size={17} />
                    </div>


                    <div>

                      <span>
                        INFRASTRUCTURE
                      </span>

                      <strong>

                        {analysis.infrastructure_graph?.node_count ??
                          analysis.infrastructure_graph?.nodes?.length ??
                          0}

                      </strong>

                      <em>

                        {analysis.infrastructure_graph?.relationship_count ??
                          analysis.infrastructure_graph?.relationships?.length ??
                          0}

                        {" "}
                        RELATIONSHIPS

                      </em>

                    </div>

                  </div>


                  <div className="case-intelligence-item">

                    <div className="case-intelligence-icon evidence-icon">
                      <Fingerprint size={17} />
                    </div>


                    <div>

                      <span>
                        DIGITAL EVIDENCE
                      </span>

                      <strong>

                        {analysis.evidence?.sha256
                          ? "VERIFIED"
                          : "PENDING"}

                      </strong>

                      <em>
                        SHA-256 INTEGRITY
                      </em>

                    </div>

                  </div>

                </div>


                {/* CASE METADATA */}

                <div className="case-metadata">

                  <div>

                    <span>
                      FILE TYPE
                    </span>

                    <strong>
                      {analysis.evidence?.evidence_type ||
                        "EMAIL"}
                    </strong>

                  </div>


                  <div>

                    <span>
                      FILE SIZE
                    </span>

                    <strong>

                      {analysis.evidence?.file_size
                        ? `${analysis.evidence.file_size} bytes`
                        : "N/A"}

                    </strong>

                  </div>


                  <div>

                    <span>
                      EVIDENCE STATUS
                    </span>

                    <strong className="metadata-preserved">

                      {analysis.evidence?.status ||
                        "PRESERVED"}

                    </strong>

                  </div>


                  <div>

                    <span>
                      PRESERVED AT
                    </span>

                    <strong>

                      {analysis.evidence?.preserved_at
                        ? new Date(
                            analysis.evidence.preserved_at
                          ).toLocaleString()
                        : "N/A"}

                    </strong>

                  </div>

                </div>

              </motion.section>

            )}


            {/* =================================================
                FORENSIC SECTION NAVIGATION
            ================================================= */}

            {analysis && (

              <motion.div
                className="forensic-section-nav"
                initial={{
                  opacity: 0,
                  y: 10
                }}
                animate={{
                  opacity: 1,
                  y: 0
                }}
              >

                <button
                  className={
                    activeAnalysisSection === "overview"
                      ? "active"
                      : ""
                  }
                  onClick={() =>
                    setActiveAnalysisSection("overview")
                  }
                >

                  <Activity size={15} />

                  <span>
                    OVERVIEW
                  </span>

                </button>


                <button
                  className={
                    activeAnalysisSection === "threat"
                      ? "active"
                      : ""
                  }
                  onClick={() =>
                    setActiveAnalysisSection("threat")
                  }
                >

                  <ShieldAlert size={15} />

                  <span>
                    THREAT
                  </span>

                </button>


                <button
                  className={
                    activeAnalysisSection === "headers"
                      ? "active"
                      : ""
                  }
                  onClick={() =>
                    setActiveAnalysisSection("headers")
                  }
                >

                  <Mail size={15} />

                  <span>
                    HEADERS
                  </span>

                </button>


                <button
                  className={
                    activeAnalysisSection === "origin"
                      ? "active"
                      : ""
                  }
                  onClick={() =>
                    setActiveAnalysisSection("origin")
                  }
                >

                  <Globe size={15} />

                  <span>
                    ORIGIN
                  </span>

                </button>


                <button
                  className={
                    activeAnalysisSection === "infrastructure"
                      ? "active"
                      : ""
                  }
                  onClick={() =>
                    setActiveAnalysisSection("infrastructure")
                  }
                >

                  <Network size={15} />

                  <span>
                    INFRASTRUCTURE
                  </span>

                </button>


                <button
                  className={
                    activeAnalysisSection === "evidence"
                      ? "active"
                      : ""
                  }
                  onClick={() =>
                    setActiveAnalysisSection("evidence")
                  }
                >

                  <Fingerprint size={15} />

                  <span>
                    EVIDENCE
                  </span>

                </button>

              </motion.div>

            )}


            {/* =================================================
                OVERVIEW
            ================================================= */}

            {analysis &&
              activeAnalysisSection === "overview" && (

              <motion.section
                className="analysis-card"
                initial={{
                  opacity: 0,
                  y: 20
                }}
                animate={{
                  opacity: 1,
                  y: 0
                }}
              >

                <div className="analysis-header">

                  <div>

                    <span className="result-label">
                      INVESTIGATION OVERVIEW
                    </span>

                    <h2>
                      Email Evidence Profile
                    </h2>

                  </div>


                  <div className="success-status">
                    ANALYZED
                  </div>

                </div>


                <div className="analysis-grid">

                  <InfoBox
                    label="FROM"
                    value={
                      analysis.headers?.from ||
                      "Not available"
                    }
                  />

                  <InfoBox
                    label="TO"
                    value={
                      analysis.headers?.to ||
                      "Not available"
                    }
                  />

                  <InfoBox
                    label="SUBJECT"
                    value={
                      analysis.headers?.subject ||
                      "Not available"
                    }
                  />

                  <InfoBox
                    label="DATE"
                    value={
                      analysis.headers?.date ||
                      "Not available"
                    }
                  />

                  <InfoBox
                    label="REPLY-TO"
                    value={
                      analysis.headers?.reply_to ||
                      "Not available"
                    }
                  />

                  <InfoBox
                    label="RETURN-PATH"
                    value={
                      analysis.headers?.return_path ||
                      "Not available"
                    }
                  />

                </div>


                <div className="section-heading">

                  <div>

                    <span className="result-label">
                      INVESTIGATION SCOPE
                    </span>

                    <h3>
                      TARVEX26 Forensic Analysis Pipeline
                    </h3>

                  </div>

                  <ShieldCheck size={24} />

                </div>


                <div className="features">

                  <FeatureCard
                    icon={<ShieldAlert size={21} />}
                    title="Threat Detection"
                    description="Identify phishing, spoofing, impersonation and fraud indicators."
                    onClick={() =>
                      setActiveAnalysisSection("threat")
                    }
                  />


                  <FeatureCard
                    icon={<FileSearch size={21} />}
                    title="Header Forensics"
                    description="Analyze sender identity, authentication results and mail relay information."
                    onClick={() =>
                      setActiveAnalysisSection("headers")
                    }
                  />


                  <FeatureCard
                    icon={<MapPin size={21} />}
                    title="Origin Intelligence"
                    description="Investigate originating IP addresses and probable geographic infrastructure."
                    onClick={() =>
                      setActiveAnalysisSection("origin")
                    }
                  />


                  <FeatureCard
                    icon={<Network size={21} />}
                    title="Infrastructure Correlation"
                    description="Connect email, domains, IP addresses and relay infrastructure."
                    onClick={() =>
                      setActiveAnalysisSection("infrastructure")
                    }
                  />


                  <FeatureCard
                    icon={<Fingerprint size={21} />}
                    title="Digital Evidence"
                    description="Verify evidence integrity using cryptographic SHA-256 preservation."
                    onClick={() =>
                      setActiveAnalysisSection("evidence")
                    }
                  />

                </div>

              </motion.section>

            )}


            {/* =================================================
                THREAT SECTION
            ================================================= */}

            {analysis &&
              activeAnalysisSection === "threat" && (

              <motion.section
                className="threat-card"
                initial={{
                  opacity: 0,
                  y: 20
                }}
                animate={{
                  opacity: 1,
                  y: 0
                }}
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

                    {analysis.threat_analysis?.risk_level ||
                      "UNKNOWN"}

                  </div>

                </div>


                <div className="threat-score-section">

                  <div className="score-box">

                    <span>
                      THREAT SCORE
                    </span>

                    <strong>

                      {analysis.threat_analysis?.threat_score ??
                        analysis.threat_analysis?.fraud_score ??
                        analysis.threat_analysis?.score ??
                        0}

                    </strong>

                    <small>
                      / 100
                    </small>

                  </div>


                  <div className="threat-summary">

                    <span>
                      ANALYSIS SUMMARY
                    </span>

                    <p>

                      {analysis.threat_analysis?.summary ||
                        "No threat summary available."}

                    </p>

                  </div>

                </div>


                <div className="indicators-section">

                  <h3>
                    DETECTED INDICATORS
                  </h3>


                  {analysis.threat_analysis?.indicators?.length > 0 ? (

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


                <div className="section-heading">

                  <div>

                    <span className="result-label">
                      INVESTIGATOR NOTE
                    </span>

                    <h3>
                      Threat intelligence requires contextual review
                    </h3>

                  </div>

                  <ShieldAlert size={22} />

                </div>

                <p className="hero-text">

                  TARVEX26 presents the detected indicators,
                  calculated threat score and supporting
                  forensic evidence so an investigator can
                  review the decision rather than relying
                  on an opaque classification alone.

                </p>

              </motion.section>

            )}


            {/* =================================================
                HEADER FORENSICS
            ================================================= */}

            {analysis &&
              activeAnalysisSection === "headers" && (

              <motion.section
                className="forensics-section"
                initial={{
                  opacity: 0,
                  y: 20
                }}
                animate={{
                  opacity: 1,
                  y: 0
                }}
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
                    value={
                      forensic?.spf ||
                      "Not available"
                    }
                    icon={
                      <ShieldCheck size={18} />
                    }
                  />


                  <ForensicBox
                    label="DKIM"
                    value={
                      forensic?.dkim ||
                      "Not available"
                    }
                    icon={
                      <ShieldCheck size={18} />
                    }
                  />


                  <ForensicBox
                    label="DMARC"
                    value={
                      forensic?.dmarc ||
                      "Not available"
                    }
                    icon={
                      <ShieldCheck size={18} />
                    }
                  />


                  <ForensicBox
                    label="MESSAGE ID"
                    value={
                      forensic?.message_id ||
                      "Not available"
                    }
                    icon={
                      <Fingerprint size={18} />
                    }
                  />

                </div>


                {/* IP ADDRESSES */}

                <div className="intel-block">

                  <div className="intel-title">

                    <Server size={18} />

                    <span>
                      IP ADDRESSES
                    </span>

                  </div>


                  {forensic?.ip_addresses?.length > 0 ? (

                    <div className="intel-list">

                      {forensic.ip_addresses.map(
                        (ip, index) => (

                          <span
                            className="intel-tag"
                            key={index}
                          >
                            {ip}
                          </span>

                        )
                      )}

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

                    <span>
                      DOMAINS
                    </span>

                  </div>


                  {forensic?.domains?.length > 0 ? (

                    <div className="intel-list">

                      {forensic.domains.map(
                        (domain, index) => (

                          <span
                            className="intel-tag"
                            key={index}
                          >
                            {domain}
                          </span>

                        )
                      )}

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

                    <span>
                      AUTHENTICATION RESULTS
                    </span>

                  </div>


                  {forensic?.authentication_results?.length > 0 ? (

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

                    <span>
                      FORENSIC FINDINGS
                    </span>

                  </div>


                  {forensic?.findings?.length > 0 ? (

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


                {/* RECEIVED HEADERS */}

                <div className="received-section">

                  <h3>
                    RECEIVED / RELAY HEADERS
                  </h3>


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

              </motion.section>

            )}


            {/* =================================================
                ORIGIN INTELLIGENCE
            ================================================= */}

            {analysis &&
              activeAnalysisSection === "origin" && (

              <motion.section
                className="origin-section"
                initial={{
                  opacity: 0,
                  y: 20
                }}
                animate={{
                  opacity: 1,
                  y: 0
                }}
              >

                {/* HEADER */}

                <div className="section-heading">

                  <div>

                    <span className="result-label">
                      ORIGIN INTELLIGENCE
                    </span>

                    <h3>
                      IP & Infrastructure Origin
                    </h3>

                  </div>

                  <MapPin size={24} />

                </div>


                {/* =================================================
                    CANDIDATE ORIGIN
                ================================================= */}

                <div className="intel-block">

                  <div className="intel-title">

                    <Globe size={18} />

                    <span>
                      CANDIDATE ORIGIN
                    </span>

                  </div>


                  {candidateOrigin?.ip ? (

                    <div className="origin-card">

                      <div className="origin-card-header">

                        <span>
                          ORIGIN IP
                        </span>

                        <strong>
                          {candidateOrigin.ip}
                        </strong>

                      </div>


                      <div className="origin-details">

                        <div>
                          <span>ASSESSMENT</span>
                          <p>
                            {candidateOrigin.assessment ||
                              "CANDIDATE_ORIGIN"}
                          </p>
                        </div>


                        <div>
                          <span>CONFIDENCE</span>
                          <p>
                            {candidateOrigin.confidence ?? 0}%
                          </p>
                        </div>


                        <div>
                          <span>COUNTRY</span>
                          <p>
                            {candidateOrigin.country ||
                              "Unknown"}
                          </p>
                        </div>


                        <div>
                          <span>REGION</span>
                          <p>
                            {candidateOrigin.region ||
                              "Unknown"}
                          </p>
                        </div>


                        <div>
                          <span>CITY</span>
                          <p>
                            {candidateOrigin.city ||
                              "Unknown"}
                          </p>
                        </div>


                        <div>
                          <span>ISP</span>
                          <p>
                            {candidateOrigin.isp ||
                              "Unknown"}
                          </p>
                        </div>


                        <div>
                          <span>ORGANIZATION</span>
                          <p>
                            {candidateOrigin.organization ||
                              "Unknown"}
                          </p>
                        </div>


                        <div>
                          <span>ASN</span>
                          <p>
                            {candidateOrigin.asn
                              ? `AS${candidateOrigin.asn}`
                              : "Unknown"}
                          </p>
                        </div>


                        <div>
                          <span>REVERSE DNS</span>
                          <p>
                            {candidateOrigin.hostname ||
                              "Unavailable"}
                          </p>
                        </div>


                        <div>
                          <span>LATITUDE</span>
                          <p>
                            {candidateOrigin.latitude ??
                              "Unknown"}
                          </p>
                        </div>


                        <div>
                          <span>LONGITUDE</span>
                          <p>
                            {candidateOrigin.longitude ??
                              "Unknown"}
                          </p>
                        </div>

                      </div>

                    </div>

                  ) : (

                    <div className="origin-empty">
                      No reliable public origin IP was identified.
                    </div>

                  )}

                </div>


                {/* =================================================
                    IP INTELLIGENCE
                ================================================= */}

                <div className="intel-block">

                  <div className="intel-title">

                    <Server size={18} />

                    <span>
                      IP INTELLIGENCE
                    </span>

                  </div>


                  {ipIntelligence?.results?.length > 0 ? (

                    <div className="origin-grid">

                      {ipIntelligence.results.map(
                        (ipInfo, index) => (

                          <motion.div
                            className="origin-card"
                            key={`${ipInfo.ip}-${index}`}
                            initial={{
                              opacity: 0,
                              y: 10
                            }}
                            animate={{
                              opacity: 1,
                              y: 0
                            }}
                            transition={{
                              delay: index * 0.05
                            }}
                          >

                            <div className="origin-card-header">

                              <span>
                                IP ADDRESS
                              </span>

                              <strong>
                                {ipInfo.ip ||
                                  "Unknown"}
                              </strong>

                            </div>


                            <div className="origin-details">

                              <div>
                                <span>TYPE</span>
                                <p>
                                  {ipInfo.type ||
                                    "Unknown"}
                                </p>
                              </div>


                              <div>
                                <span>VERSION</span>
                                <p>
                                  {ipInfo.version
                                    ? `IPv${ipInfo.version}`
                                    : "Unknown"}
                                </p>
                              </div>


                              <div>
                                <span>COUNTRY</span>
                                <p>
                                  {ipInfo.country ||
                                    "Unknown"}
                                </p>
                              </div>


                              <div>
                                <span>REGION</span>
                                <p>
                                  {ipInfo.region ||
                                    "Unknown"}
                                </p>
                              </div>


                              <div>
                                <span>CITY</span>
                                <p>
                                  {ipInfo.city ||
                                    "Unknown"}
                                </p>
                              </div>


                              <div>
                                <span>ISP</span>
                                <p>
                                  {ipInfo.isp ||
                                    "Unknown"}
                                </p>
                              </div>


                              <div>
                                <span>ORGANIZATION</span>
                                <p>
                                  {ipInfo.organization ||
                                    "Unknown"}
                                </p>
                              </div>


                              <div>
                                <span>ASN</span>
                                <p>
                                  {ipInfo.asn
                                    ? `AS${ipInfo.asn}`
                                    : "Unknown"}
                                </p>
                              </div>


                              <div>
                                <span>REVERSE DNS</span>
                                <p>
                                  {ipInfo.hostname ||
                                    "Unavailable"}
                                </p>
                              </div>


                              <div>
                                <span>CONFIDENCE</span>
                                <p>
                                  {ipInfo.confidence ?? 0}%
                                </p>
                              </div>


                              <div>
                                <span>REPUTATION</span>
                                <p>
                                  {ipInfo.reputation?.status ||
                                    "UNKNOWN"}
                                </p>
                              </div>


                              <div>
                                <span>HOSTING</span>
                                <p>
                                  {ipInfo.hosting?.detected
                                    ? ipInfo.hosting.providers?.join(
                                        ", "
                                      ) || "Detected"
                                    : "Not detected"}
                                </p>
                              </div>

                            </div>


                            {ipInfo.findings?.length > 0 && (

                              <div
                                className="intel-block"
                                style={{
                                  marginTop: "14px",
                                  marginBottom: "0"
                                }}
                              >

                                <div className="intel-title">

                                  <ShieldAlert size={16} />

                                  <span>
                                    FINDINGS
                                  </span>

                                </div>


                                {ipInfo.findings.map(
                                  (
                                    finding,
                                    findingIndex
                                  ) => (

                                    <div
                                      className="finding-item"
                                      key={findingIndex}
                                    >

                                      <ShieldAlert size={14} />

                                      {finding}

                                    </div>

                                  )
                                )}

                              </div>

                            )}

                          </motion.div>

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
                    ORIGIN FINDINGS
                ================================================= */}

                <div className="intel-block">

                  <div className="intel-title">

                    <ShieldAlert size={18} />

                    <span>
                      ORIGIN ASSESSMENT
                    </span>

                  </div>


                  {originIntelligence?.findings?.length > 0 ? (

                    originIntelligence.findings.map(
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
                      No origin findings available.
                    </div>

                  )}

                </div>


                {/* =================================================
                    TRACEABILITY SUMMARY
                ================================================= */}

                <div className="intel-block">

                  <div className="intel-title">

                    <Globe size={18} />

                    <span>
                      TRACEABILITY SUMMARY
                    </span>

                  </div>


                  <p className="hero-text">

                    TARVEX26 correlates extracted email
                    IP addresses with geolocation, ISP,
                    organization, ASN, reverse DNS and
                    infrastructure indicators to identify
                    a candidate origin for investigative review.

                  </p>


                  <p className="hero-text">

                    Origin information represents network
                    infrastructure associated with the observed
                    IP address and should not be interpreted as
                    direct identification of the individual sender.

                  </p>

                </div>

              </motion.section>

            )}


            {/* =================================================
                INFRASTRUCTURE CORRELATION
            ================================================= */}

            {analysis &&
              activeAnalysisSection === "infrastructure" && (

              <motion.section
                className="infrastructure-section"
                initial={{
                  opacity: 0,
                  y: 20
                }}
                animate={{
                  opacity: 1,
                  y: 0
                }}
              >

                <div className="section-heading">

                  <div>

                    <span className="result-label">
                      INFRASTRUCTURE CORRELATION
                    </span>

                    <h3>
                      Email Infrastructure Relationships
                    </h3>

                  </div>

                  <Network size={24} />

                </div>


                <p className="hero-text">

                  Relationship graph connecting the analyzed
                  email with sender domains, source IP addresses
                  and relay infrastructure.

                </p>


                {analysis.infrastructure_graph ? (

                  <InfrastructureGraph
                    infrastructureGraph={
                      analysis.infrastructure_graph
                    }
                  />

                ) : (

                  <div className="empty-page-state">

                    <Network size={42} />

                    <h2>
                      No infrastructure graph available
                    </h2>

                    <p>
                      No correlated infrastructure was returned
                      by the forensic backend.
                    </p>

                  </div>

                )}

              </motion.section>

            )}


            {/* =================================================
                DIGITAL EVIDENCE
            ================================================= */}

            {analysis &&
              activeAnalysisSection === "evidence" &&
              analysis.evidence && (

              <motion.section
                className="evidence-section"
                initial={{
                  opacity: 0,
                  y: 20
                }}
                animate={{
                  opacity: 1,
                  y: 0
                }}
              >

                <div className="evidence-top">

                  <div>

                    <span className="result-label">
                      DIGITAL EVIDENCE
                    </span>

                    <h3>
                      Evidence Preservation
                    </h3>

                    <p>
                      Cryptographic verification of the
                      original email evidence.
                    </p>

                  </div>


                  <div className="evidence-badge">

                    <ShieldCheck size={17} />

                    VERIFIED

                  </div>

                </div>


                <div className="evidence-main">

                  <div className="evidence-item evidence-wide">

                    <span>
                      EVIDENCE ID
                    </span>

                    <strong>
                      {analysis.evidence.evidence_id ||
                        "N/A"}
                    </strong>

                  </div>


                  <div className="evidence-item">

                    <span>
                      FILE
                    </span>

                    <strong>
                      {analysis.evidence.filename ||
                        "N/A"}
                    </strong>

                  </div>


                  <div className="evidence-item">

                    <span>
                      SIZE
                    </span>

                    <strong>

                      {analysis.evidence.file_size
                        ? `${analysis.evidence.file_size} bytes`
                        : "N/A"}

                    </strong>

                  </div>


                  <div className="evidence-item">

                    <span>
                      TYPE
                    </span>

                    <strong>
                      {analysis.evidence.evidence_type ||
                        "EMAIL"}
                    </strong>

                  </div>


                  <div className="evidence-item">

                    <span>
                      STATUS
                    </span>

                    <strong className="evidence-valid">

                      {analysis.evidence.status ||
                        "PRESERVED"}

                    </strong>

                  </div>

                </div>


                <div className="evidence-hash">

                  <div className="hash-title">

                    <Fingerprint size={16} />

                    <span>
                      SHA-256 EVIDENCE HASH
                    </span>

                  </div>


                  <code>
                    {analysis.evidence.sha256 ||
                      "Hash unavailable"}
                  </code>


                  <p>
                    Digital fingerprint generated from
                    the uploaded email. Used to verify
                    evidence integrity.
                  </p>

                </div>


                <div className="evidence-time">

                  <span>
                    PRESERVED AT
                  </span>

                  <strong>

                    {analysis.evidence.preserved_at
                      ? new Date(
                          analysis.evidence.preserved_at
                        ).toLocaleString()
                      : "N/A"}

                  </strong>

                </div>


                <div className="intel-block">

                  <div className="intel-title">

                    <ShieldCheck size={18} />

                    <span>
                      EVIDENCE INTEGRITY
                    </span>

                  </div>


                  <div className="finding-safe">

                    SHA-256 fingerprint generated from
                    the uploaded email and associated
                    evidence metadata.

                  </div>

                </div>

              </motion.section>

            )}


            {/* =================================================
                FOOTER
            ================================================= */}

            <footer>

              <span>
                TARVEX26
              </span>

              <span>
                •
              </span>

              <span>
                SIH 26106
              </span>

              <span>
                •
              </span>

              <span>
                EMAIL FORENSIC INTELLIGENCE
              </span>

            </footer>

          </>

        )}

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

      <span>
        {label}
      </span>

      <p>
        {value}
      </p>

    </div>

  );
}


/* =========================================================
   FORENSIC BOX
========================================================= */

function ForensicBox({
  label,
  value,
  icon
}) {

  const status =
    String(value).toUpperCase();

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

      <span>
        {label}
      </span>

      <strong>
        {value}
      </strong>

    </div>

  );
}


/* =========================================================
   FEATURE CARD
========================================================= */

function FeatureCard({
  icon,
  title,
  description,
  onClick
}) {

  return (

    <motion.div
      className="feature-card"
      whileHover={{
        y: -5,
        scale: 1.01
      }}
      whileTap={{
        scale: 0.98
      }}
      onClick={onClick}
      style={{
        cursor: onClick
          ? "pointer"
          : "default"
      }}
    >

      <div className="feature-icon">
        {icon}
      </div>


      <h3>
        {title}
      </h3>


      <p>
        {description}
      </p>


      {onClick && (

        <span
          style={{
            display: "block",
            marginTop: "12px",
            fontSize: "10px",
            letterSpacing: "1.2px",
            opacity: 0.55
          }}
        >
          OPEN INVESTIGATION →
        </span>

      )}

    </motion.div>

  );
}


export default App;