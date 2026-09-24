import { useState } from "react";
import { motion } from "framer-motion";
import InfrastructureGraph from "./InfrastructureGraph";
import GeoLocationMap from "./GeoLocationMap";

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
  Download,
  ExternalLink,
  LoaderCircle,
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

function ReportsPage({
  analysis,
  onOpenSection,
  onGenerateReport,
  reportLoading,
  reportData,
  reportError,
  onOpenReport,
  onDownloadReport,
}) {
  return (
    <section className="page-view">

      <div className="page-header">
        <span className="section-label">FORENSIC REPORTING</span>

        <h1>Investigation Reports</h1>

        <p>
          Review generated forensic intelligence and evidence.
        </p>
      </div>

      {analysis ? (
        <>

          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            className="report-card"
            style={{
              marginBottom: "18px",
              cursor: "default",
              border: "1px solid rgba(0, 220, 255, 0.18)",
              background: "rgba(0, 20, 35, 0.58)",
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: "18px",
                flexWrap: "wrap",
              }}
            >
              <div style={{ flex: "1 1 420px" }}>
                <span
                  style={{
                    display: "block",
                    fontSize: "10px",
                    letterSpacing: "1.8px",
                    opacity: 0.55,
                    marginBottom: "7px",
                  }}
                >
                  STRUCTURED FORENSIC REPORT
                </span>

                <h3 style={{ marginBottom: "8px" }}>
                  Generate Investigation Report
                </h3>

                <p style={{ marginBottom: "0" }}>
                  Compile the current TARVEX26 analysis into a structured
                  forensic HTML report containing threat assessment,
                  header intelligence, origin analysis, infrastructure,
                  evidence integrity and chain-of-custody information.
                </p>
              </div>

              <button
                onClick={onGenerateReport}
                disabled={reportLoading}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "9px",
                  minWidth: "220px",
                  padding: "13px 18px",
                  borderRadius: "10px",
                  border: "1px solid rgba(0, 220, 255, 0.35)",
                  background: reportLoading
                    ? "rgba(0, 220, 255, 0.08)"
                    : "rgba(0, 220, 255, 0.12)",
                  color: "inherit",
                  cursor: reportLoading ? "wait" : "pointer",
                  fontWeight: 700,
                  letterSpacing: "0.8px",
                }}
              >
                {reportLoading ? (
                  <>
                    <LoaderCircle size={17} className="spin" />
                    GENERATING...
                  </>
                ) : (
                  <>
                    <FileText size={17} />
                    GENERATE REPORT
                  </>
                )}
              </button>
            </div>

            {reportError && (
              <div
                style={{
                  marginTop: "15px",
                  padding: "11px 13px",
                  borderRadius: "8px",
                  border: "1px solid rgba(255, 92, 122, 0.22)",
                  background: "rgba(255, 92, 122, 0.06)",
                  fontSize: "12px",
                  lineHeight: 1.5,
                }}
              >
                {reportError}
              </div>
            )}

            {reportData && (
              <div
                style={{
                  marginTop: "17px",
                  paddingTop: "16px",
                  borderTop: "1px solid rgba(255,255,255,0.07)",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: "12px",
                    flexWrap: "wrap",
                  }}
                >
                  <div>
                    <span
                      style={{
                        display: "block",
                        fontSize: "9px",
                        letterSpacing: "1.5px",
                        opacity: 0.5,
                        marginBottom: "5px",
                      }}
                    >
                      REPORT READY
                    </span>

                    <strong
                      style={{
                        display: "block",
                        wordBreak: "break-word",
                        fontSize: "12px",
                      }}
                    >
                      {reportData.filename || "TARVEX26_Forensic_Report.html"}
                    </strong>
                  </div>

                  <div
                    style={{
                      display: "flex",
                      gap: "8px",
                      flexWrap: "wrap",
                    }}
                  >
                    <button
                      onClick={onOpenReport}
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "7px",
                        padding: "9px 13px",
                        borderRadius: "8px",
                        border: "1px solid rgba(0, 220, 255, 0.22)",
                        background: "rgba(0, 220, 255, 0.07)",
                        color: "inherit",
                        cursor: "pointer",
                      }}
                    >
                      <ExternalLink size={15} />
                      OPEN REPORT
                    </button>

                    <button
                      onClick={onDownloadReport}
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "7px",
                        padding: "9px 13px",
                        borderRadius: "8px",
                        border: "1px solid rgba(255,255,255,0.10)",
                        background: "rgba(255,255,255,0.035)",
                        color: "inherit",
                        cursor: "pointer",
                      }}
                    >
                      <Download size={15} />
                      DOWNLOAD
                    </button>
                  </div>
                </div>
              </div>
            )}
          </motion.div>

          <div className="report-grid">

            <motion.div
              className="report-card"
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              whileHover={{ y: -5 }}
              onClick={() => onOpenSection("overview")}
              style={{ cursor: "pointer" }}
            >
              <span>FORENSIC ANALYSIS</span>

              <h3>Email Threat Investigation</h3>

              <p>
                Header, authentication, infrastructure,
                origin and threat analysis.
              </p>

              <div className="report-meta">
                <FileText size={16} />
                <span>
                  {analysis.filename ||
                    analysis.evidence?.filename ||
                    "Email evidence"}
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
              <span>DIGITAL EVIDENCE</span>

              <h3>Evidence Integrity Report</h3>

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
              <span>THREAT INTELLIGENCE</span>

              <h3>Threat Assessment</h3>

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
              onClick={() => onOpenSection("infrastructure")}
              style={{ cursor: "pointer" }}
            >
              <span>INFRASTRUCTURE</span>

              <h3>Correlation Intelligence</h3>

              <p>
                Relationship graph connecting domains,
                IP addresses and relay infrastructure.
              </p>

              <div className="report-meta">
                <Network size={16} />
                <span>
                  {analysis.infrastructure_graph?.node_count ??
                    analysis.infrastructure_graph?.nodes?.length ??
                    0}{" "}
                  NODES
                </span>
              </div>
            </motion.div>

          </div>

          {reportData?.report && (
            <motion.div
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              className="report-card"
              style={{
                marginTop: "18px",
                cursor: "default",
                padding: "0",
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  padding: "17px 18px",
                  borderBottom: "1px solid rgba(255,255,255,0.07)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: "12px",
                  flexWrap: "wrap",
                }}
              >
                <div>
                  <span
                    style={{
                      display: "block",
                      fontSize: "9px",
                      letterSpacing: "1.5px",
                      opacity: 0.5,
                      marginBottom: "5px",
                    }}
                  >
                    LIVE REPORT PREVIEW
                  </span>

                  <strong>TARVEX26 FORENSIC REPORT</strong>
                </div>

                <span
                  style={{
                    fontSize: "9px",
                    letterSpacing: "1px",
                    opacity: 0.55,
                  }}
                >
                  HTML FORENSIC DOCUMENT
                </span>
              </div>

              <iframe
                title="TARVEX26 Forensic Report Preview"
                srcDoc={reportData.report}
                style={{
                  width: "100%",
                  minHeight: "620px",
                  border: "0",
                  background: "#03070d",
                }}
              />
            </motion.div>
          )}

        </>
      ) : (
        <div className="empty-page-state">
          <FileText size={42} />

          <h2>No reports available</h2>

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
  // Start with no investigation. Analysis appears only after the user analyzes an .eml file.
  const [analysis, setAnalysis] = useState(null);
  const [error, setError] = useState("");

  const [activePage, setActivePage] = useState("dashboard");

  const [
    activeAnalysisSection,
    setActiveAnalysisSection
  ] = useState("overview");


  const [reportLoading, setReportLoading] = useState(false);
  const [reportData, setReportData] = useState(null);
  const [reportError, setReportError] = useState("");


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
    try {
      localStorage.removeItem("tarvex26_analysis");
    } catch {}
    setError("");
    setReportData(null);
    setReportError("");
    setReportLoading(false);

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
    setReportData(null);
    setReportError("");

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
     FORENSIC REPORT GENERATION
  ======================================================= */

  const generateReport = async () => {

    if (!analysis) {
      setReportError("Analyze an email before generating a report.");
      return;
    }

    setReportLoading(true);
    setReportError("");

    try {

      const response = await fetch(
        "http://127.0.0.1:5000/generate-report",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(analysis),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
          "Forensic report generation failed."
        );
      }

      if (!data.report) {
        throw new Error(
          "The backend returned no report content."
        );
      }

      setReportData({
        filename:
          data.filename ||
          "TARVEX26_Forensic_Report.html",
        report: data.report,
      });

      setActivePage("reports");

    } catch (err) {

      console.error(err);

      setReportData(null);

      setReportError(
        err?.message ||
        "Could not generate the forensic report. Make sure Flask is running."
      );

    } finally {

      setReportLoading(false);

    }
  };


  const openGeneratedReport = () => {

    if (!reportData?.report) {
      return;
    }

    const reportBlob = new Blob(
      [reportData.report],
      { type: "text/html;charset=utf-8" }
    );

    const reportUrl = URL.createObjectURL(reportBlob);

    window.open(
      reportUrl,
      "_blank",
      "noopener,noreferrer"
    );

    window.setTimeout(() => {
      URL.revokeObjectURL(reportUrl);
    }, 60000);
  };


  const downloadGeneratedReport = () => {

    if (!reportData?.report) {
      return;
    }

    const reportBlob = new Blob(
      [reportData.report],
      { type: "text/html;charset=utf-8" }
    );

    const reportUrl = URL.createObjectURL(reportBlob);

    const link = document.createElement("a");

    link.href = reportUrl;

    link.download =
      reportData.filename ||
      "TARVEX26_Forensic_Report.html";

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    window.setTimeout(() => {
      URL.revokeObjectURL(reportUrl);
    }, 1000);
  };


  /* =======================================================
     NAVIGATION HELPERS
  ======================================================= */

  const openInvestigation = (section = "overview") => {

    if (!analysis) {
      setActivePage("dashboard");
      setActiveAnalysisSection("overview");
      return;
    }

    setActivePage("dashboard");
    setActiveAnalysisSection(section);

    window.scrollTo({
      top: 0,
      behavior: "smooth"
    });
  };


  const forensic = analysis?.forensics || {};

  /* =======================================================
     ROBUST IP EXTRACTION

     The backend may return IP intelligence as:
     - forensics.ip_addresses
     - ip_intelligence.results
     - ip_intelligence.ip_addresses
     - ip_intelligence.ips
     - ip_intelligence.items
     - geoip_intelligence.results

     We normalize all of those shapes here so the UI does not
     silently show an empty box just because the response shape
     changed. No IP is invented.
  ======================================================= */

  const isIPv4 = (value) => {
    if (typeof value !== "string") return false;

    const ip = value.trim();
    const parts = ip.split(".");

    return (
      parts.length === 4 &&
      parts.every((part) => {
        if (!/^\d+$/.test(part)) return false;
        const number = Number(part);
        return number >= 0 && number <= 255;
      })
    );
  };

  const isIPv6 = (value) => {
    if (typeof value !== "string") return false;

    const ip = value.trim();

    // A real IPv6 address must contain at least two colons.
    // URL parsing gives us a much stricter validation than a
    // loose colon/hex regex, preventing timestamps such as
    // 09:30:00 from being displayed as IPv6 addresses.
    if ((ip.match(/:/g) || []).length < 2) return false;
    if (!/^[0-9a-fA-F:]+$/.test(ip)) return false;

    try {
      new URL(`http://[${ip}]/`);
      return true;
    } catch {
      return false;
    }
  };

  const isIP = (value) =>
    isIPv4(value) || isIPv6(value);

  const uniqueIPs = (values) =>
    [...new Set(
      values
        .filter((value) => typeof value === "string")
        .map((value) => value.trim())
        .filter(isIP)
    )];

  const collectIPs = (value, output = []) => {
    if (value == null) return output;

    if (typeof value === "string") {
      const matches = value.match(
        /(?:\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){2,7}\b)/g
      ) || [];

      matches.forEach((match) => {
        if (isIP(match)) output.push(match);
      });

      return output;
    }

    if (Array.isArray(value)) {
      value.forEach((item) => collectIPs(item, output));
      return output;
    }

    if (typeof value === "object") {
      Object.entries(value).forEach(([key, item]) => {
        const keyLooksLikeIP =
          /^(ip|source_ip|origin_ip|client_ip|server_ip|address|host_ip)$/i.test(key);

        if (keyLooksLikeIP && typeof item === "string") {
          collectIPs(item, output);
        } else if (typeof item === "object" || typeof item === "string") {
          collectIPs(item, output);
        }
      });
    }

    return output;
  };

  const directIPSources = [
    forensic.ip_addresses,
    forensic.ips,
    analysis?.ip_intelligence?.ip_addresses,
    analysis?.ip_intelligence?.ips,
    analysis?.ip_intelligence?.results,
    analysis?.ip_intelligence?.items,
    analysis?.geoip_intelligence?.results,
    analysis?.origin_intelligence?.results,
    analysis?.origin_intelligence?.ips,
    forensic.relay_analysis,
    forensic.received_headers,
    analysis?.received_headers,
  ];

  const extractedIPs = uniqueIPs(
    directIPSources.flatMap((source) => collectIPs(source))
  );

  const receivedHeaders = Array.isArray(analysis?.received_headers)
    ? analysis.received_headers
    : Array.isArray(forensic.received_headers)
      ? forensic.received_headers
      : [];

  const ipIntelligenceResults =
    Array.isArray(analysis?.ip_intelligence?.results)
      ? analysis.ip_intelligence.results
      : Array.isArray(analysis?.ip_intelligence?.items)
        ? analysis.ip_intelligence.items
        : [];

  const sourceIPCount =
    Array.isArray(forensic.ip_addresses)
      ? forensic.ip_addresses.length
      : 0;


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
            onGenerateReport={generateReport}
            reportLoading={reportLoading}
            reportData={reportData}
            reportError={reportError}
            onOpenReport={openGeneratedReport}
            onDownloadReport={downloadGeneratedReport}
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
                        {sourceIPCount || extractedIPs.length}
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
                  className={activeAnalysisSection === "domain" ? "active" : ""}
                  onClick={() => setActiveAnalysisSection("domain")}
                >
                  <Globe size={15} />
                  <span>DOMAIN</span>
                </button>

                <button
                  className={activeAnalysisSection === "urls" ? "active" : ""}
                  onClick={() => setActiveAnalysisSection("urls")}
                >
                  <Search size={15} />
                  <span>URLS</span>
                </button>

                <button
                  className={activeAnalysisSection === "attachments" ? "active" : ""}
                  onClick={() => setActiveAnalysisSection("attachments")}
                >
                  <FileText size={15} />
                  <span>ATTACHMENTS</span>
                </button>

                <button
                  className={activeAnalysisSection === "correlation" ? "active" : ""}
                  onClick={() => setActiveAnalysisSection("correlation")}
                >
                  <Network size={15} />
                  <span>CORRELATION</span>
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
                  review the decision rather than relying on
                  an opaque classification alone.

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


                  {extractedIPs.length > 0 ? (

                    <div className="intel-list">

                      {extractedIPs.map(
                        (ip, index) => (

                          <span
                            className="intel-tag"
                            key={`${ip}-${index}`}
                            title="IP extracted from email forensic headers"
                          >
                            {ip}
                          </span>

                        )
                      )}

                    </div>

                  ) : (

                    <div className="empty-intel">
                      No source IP address was found in the analyzed
                      email headers. This is expected when the .eml
                      file contains no usable Received/client IP.
                    </div>

                  )}

                  {ipIntelligenceResults.length > 0 && (
                    <div className="intel-list" style={{ marginTop: "12px" }}>
                      {ipIntelligenceResults.map((item, index) => {
                        const ip =
                          item?.ip ||
                          item?.source_ip ||
                          item?.address ||
                          "";

                        return ip && isIP(ip) ? (
                          <span
                            className="intel-tag"
                            key={`intel-${ip}-${index}`}
                            title="IP returned by TARVEX26 IP intelligence"
                          >
                            {ip}
                          </span>
                        ) : null;
                      })}
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


                  {forensic?.authentication_results ? (
                    <div className="authentication-results-list">

                      {typeof forensic.authentication_results === "string" ? (
                        <div className="received-item">
                          <span>
                            {forensic.authentication_results}
                          </span>
                        </div>

                      ) : Array.isArray(forensic.authentication_results) ? (
                        forensic.authentication_results.length > 0 ? (
                          forensic.authentication_results.map((result, index) => (
                            <div
                              className="received-item"
                              key={index}
                            >
                              <span>
                                {typeof result === "object"
                                  ? JSON.stringify(result)
                                  : String(result ?? "N/A")}
                              </span>
                            </div>
                          ))
                        ) : (
                          <div className="empty-intel">
                            No Authentication-Results header found.
                          </div>
                        )

                      ) : typeof forensic.authentication_results === "object" ? (
                        Object.entries(forensic.authentication_results).map(
                          ([key, value]) => (
                            <div
                              className="received-item"
                              key={key}
                            >
                              <strong>
                                {key.replace(/_/g, " ").toUpperCase()}
                              </strong>
                              <span>
                                {typeof value === "object"
                                  ? JSON.stringify(value)
                                  : String(value ?? "N/A")}
                              </span>
                            </div>
                          )
                        )

                      ) : (
                        <div className="received-item">
                          {String(forensic.authentication_results)}
                        </div>
                      )}

                    </div>
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


                  {receivedHeaders.length > 0 ? (

                    receivedHeaders.map(
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
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
              >

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

                {/* GEOIP INTELLIGENCE */}
                <div className="origin-grid">

                  {analysis.geoip_intelligence?.results?.length > 0 ? (

                    analysis.geoip_intelligence.results.map((ipInfo, index) => (

                      <motion.div
                        className="origin-card"
                        key={`${ipInfo.ip || "ip"}-${index}`}
                        initial={{ opacity: 0, y: 15 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: index * 0.06 }}
                      >

                        <div className="origin-card-header">

                          <span>
                            IP ADDRESS
                          </span>

                          <strong>
                            {ipInfo.ip || "Unknown"}
                          </strong>

                        </div>

                        <div className="origin-details">

                          <div>
                            <span>ADDRESS TYPE</span>
                            <p>{ipInfo.type || "Unknown"}</p>
                          </div>

                          <div>
                            <span>IP VERSION</span>
                            <p>
                              {ipInfo.ip_version ||
                                (ipInfo.version
                                  ? `IPv${ipInfo.version}`
                                  : "N/A")}
                            </p>
                          </div>

                          <div>
                            <span>COUNTRY</span>
                            <p>{ipInfo.country || "Unavailable"}</p>
                          </div>

                          <div>
                            <span>REGION</span>
                            <p>{ipInfo.region || "Unavailable"}</p>
                          </div>

                          <div>
                            <span>CITY</span>
                            <p>{ipInfo.city || "Unavailable"}</p>
                          </div>

                          <div>
                            <span>ORGANIZATION / ISP</span>
                            <p>
                              {ipInfo.organization ||
                                ipInfo.isp ||
                                "Unavailable"}
                            </p>
                          </div>

                          <div>
                            <span>ASN</span>
                            <p>{ipInfo.asn || "N/A"}</p>
                          </div>

                          <div>
                            <span>REVERSE DNS</span>
                            <p>{ipInfo.reverse_dns || "Unavailable"}</p>
                          </div>

                          <div>
                            <span>DOMAIN</span>
                            <p>{ipInfo.domain || "N/A"}</p>
                          </div>

                          <div>
                            <span>REPUTATION</span>
                            <p>{ipInfo.reputation || "UNKNOWN"}</p>
                          </div>

                          <div>
                            <span>CONFIDENCE</span>
                            <p>{ipInfo.confidence || "UNKNOWN"}</p>
                          </div>

                          <div>
                            <span>STATUS</span>
                            <p>{ipInfo.status || "UNKNOWN"}</p>
                          </div>

                        </div>

                        {ipInfo.latitude !== null &&
                          ipInfo.latitude !== undefined &&
                          ipInfo.longitude !== null &&
                          ipInfo.longitude !== undefined && (

                          <div
                            style={{
                              marginTop: "18px",
                              padding: "12px 14px",
                              border: "1px solid rgba(0, 220, 255, 0.16)",
                              borderRadius: "10px",
                              background: "rgba(0, 220, 255, 0.035)"
                            }}
                          >
                            <span
                              style={{
                                display: "block",
                                fontSize: "10px",
                                letterSpacing: "1.5px",
                                opacity: 0.55,
                                marginBottom: "5px"
                              }}
                            >
                              GEOLOCATION
                            </span>

                            <strong>
                              {ipInfo.latitude}, {ipInfo.longitude}
                            </strong>
                          </div>
                        )}

                        {ipInfo.findings?.length > 0 && (

                          <div
                            style={{
                              marginTop: "18px"
                            }}
                          >
                            <span
                              style={{
                                display: "block",
                                fontSize: "10px",
                                letterSpacing: "1.5px",
                                opacity: 0.55,
                                marginBottom: "8px"
                              }}
                            >
                              FORENSIC FINDINGS
                            </span>

                            {ipInfo.findings.map((finding, findingIndex) => (
                              <div
                                key={findingIndex}
                                style={{
                                  display: "flex",
                                  gap: "8px",
                                  marginBottom: "6px",
                                  fontSize: "12px",
                                  lineHeight: 1.5
                                }}
                              >
                                <span>•</span>
                                <span>{finding}</span>
                              </div>
                            ))}
                          </div>
                        )}

                      </motion.div>

                    ))

                  ) : (

                    <div className="origin-empty">
                      No geographic IP result is available. The email
                      headers must contain a usable source IP before
                      GeoIP attribution can be calculated.
                    </div>

                  )}

                </div>

                {/* GEOLOCATION MAP */}
                <GeoLocationMap
                  results={analysis.geoip_intelligence?.results || []}
                />

                {/* GEOIP SUMMARY */}
                <div className="intel-block">

                  <div className="intel-title">
                    <Globe size={18} />
                    <span>GEOIP TRACEABILITY SUMMARY</span>
                  </div>

                  <p className="hero-text">
                    TARVEX26 correlates extracted IP addresses with
                    geographic location, ISP, organization, ASN,
                    reverse DNS and available infrastructure metadata.
                    Documentation and test addresses are explicitly
                    excluded from real-world geographic attribution.
                  </p>

                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
                      gap: "10px",
                      marginTop: "18px"
                    }}
                  >
                    <div className="intel-stat">
                      <strong>
                        {analysis.geoip_intelligence?.total || 0}
                      </strong>
                      <span>IPS ANALYZED</span>
                    </div>

                    <div className="intel-stat">
                      <strong>
                        {analysis.geoip_intelligence?.public_count || 0}
                      </strong>
                      <span>PUBLIC IPS</span>
                    </div>

                    <div className="intel-stat">
                      <strong>
                        {analysis.geoip_intelligence?.documentation_count || 0}
                      </strong>
                      <span>TEST IPS</span>
                    </div>

                    <div className="intel-stat">
                      <strong>
                        {analysis.geoip_intelligence?.suspicious_count || 0}
                      </strong>
                      <span>SUSPICIOUS IPS</span>
                    </div>
                  </div>

                </div>

                {/* NETWORK ANONYMIZATION */}
                <div className="intel-block">

                  <div className="intel-title">
                    <Network size={18} />
                    <span>NETWORK ANONYMIZATION</span>
                  </div>

                  <p className="hero-text">
                    TARVEX26 checks extracted infrastructure for
                    TOR exit-node indicators, VPN indicators, proxy
                    infrastructure, hosting/datacenter signals and
                    cloud infrastructure. These indicators support
                    forensic analysis and are not treated as proof of
                    user identity.
                  </p>

                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))",
                      gap: "10px",
                      marginTop: "18px"
                    }}
                  >

                    {[
                      ["TOR", analysis.network_anonymization?.tor_count || 0],
                      ["VPN", analysis.network_anonymization?.vpn_count || 0],
                      ["PROXY", analysis.network_anonymization?.proxy_count || 0],
                      ["HOSTING", analysis.network_anonymization?.hosting_count || 0],
                      ["CLOUD", analysis.network_anonymization?.cloud_count || 0],
                    ].map(([label, count]) => (

                      <div
                        key={label}
                        className="intel-stat"
                      >
                        <strong>{count}</strong>
                        <span>{label} DETECTED</span>
                      </div>

                    ))}

                  </div>

                  {analysis.network_anonymization?.results?.length > 0 && (

                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
                        gap: "14px",
                        marginTop: "20px"
                      }}
                    >

                      {analysis.network_anonymization.results.map(
                        (networkInfo, index) => (

                          <div
                            key={`${networkInfo.ip || "ip"}-${index}`}
                            style={{
                              border: "1px solid rgba(0, 220, 255, 0.14)",
                              borderRadius: "12px",
                              padding: "16px",
                              background: "rgba(0, 20, 35, 0.45)"
                            }}
                          >

                            <div
                              style={{
                                display: "flex",
                                justifyContent: "space-between",
                                alignItems: "center",
                                gap: "12px",
                                marginBottom: "14px"
                              }}
                            >
                              <div>
                                <span
                                  style={{
                                    display: "block",
                                    fontSize: "9px",
                                    letterSpacing: "1.5px",
                                    opacity: 0.5,
                                    marginBottom: "4px"
                                  }}
                                >
                                  IP ADDRESS
                                </span>

                                <strong>
                                  {networkInfo.ip || "Unknown"}
                                </strong>
                              </div>

                              <span
                                style={{
                                  fontSize: "9px",
                                  letterSpacing: "1px",
                                  padding: "6px 8px",
                                  borderRadius: "6px",
                                  border: "1px solid rgba(0, 220, 255, 0.2)"
                                }}
                              >
                                {networkInfo.network_type || "UNKNOWN"}
                              </span>
                            </div>

                            <div
                              style={{
                                display: "grid",
                                gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
                                gap: "8px"
                              }}
                            >

                              {[
                                ["TOR", networkInfo.tor],
                                ["VPN", networkInfo.vpn],
                                ["PROXY", networkInfo.proxy],
                                ["HOSTING", networkInfo.hosting],
                                ["CLOUD", networkInfo.cloud],
                              ].map(([label, value]) => (

                                <div
                                  key={label}
                                  style={{
                                    padding: "10px",
                                    borderRadius: "8px",
                                    background: "rgba(255,255,255,0.025)",
                                    border: "1px solid rgba(255,255,255,0.05)"
                                  }}
                                >
                                  <span
                                    style={{
                                      display: "block",
                                      fontSize: "9px",
                                      letterSpacing: "1.2px",
                                      opacity: 0.5,
                                      marginBottom: "5px"
                                    }}
                                  >
                                    {label}
                                  </span>

                                  <strong
                                    style={{
                                      fontSize: "10px",
                                      wordBreak: "break-word"
                                    }}
                                  >
                                    {value?.status || "UNAVAILABLE"}
                                  </strong>
                                </div>

                              ))}

                            </div>

                            {networkInfo.findings?.length > 0 && (
                              <div style={{ marginTop: "14px" }}>
                                {networkInfo.findings.map(
                                  (finding, findingIndex) => (
                                    <div
                                      key={findingIndex}
                                      style={{
                                        display: "flex",
                                        gap: "7px",
                                        fontSize: "11px",
                                        lineHeight: 1.45,
                                        marginBottom: "5px",
                                        opacity: 0.75
                                      }}
                                    >
                                      <span>•</span>
                                      <span>{finding}</span>
                                    </div>
                                  )
                                )}
                              </div>
                            )}

                            <div
                              style={{
                                marginTop: "12px",
                                fontSize: "9px",
                                letterSpacing: "1px",
                                opacity: 0.55
                              }}
                            >
                              CONFIDENCE: {networkInfo.confidence || "UNKNOWN"}
                            </div>

                          </div>

                        )
                      )}

                    </div>
                  )}

                </div>

              </motion.section>

            )}


            {/* =================================================
                DOMAIN INTELLIGENCE
            ================================================= */}
          {analysis && activeAnalysisSection === "domain" && (
            <motion.section className="analysis-card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
              <div className="section-heading"><div><span className="result-label">DOMAIN INTELLIGENCE</span><h3>DNS, Registration & Infrastructure Intelligence</h3></div><Globe size={24} /></div>
              {analysis.domain_intelligence ? (
                <>
                  <div className="origin-grid">
                    <div className="origin-card"><div className="origin-card-header"><span>DOMAIN</span><strong>{analysis.domain_intelligence.domain || "Unknown"}</strong></div><div className="origin-details"><div><span>STATUS</span><p>{analysis.domain_intelligence.status || "N/A"}</p></div><div><span>IPv4</span><p>{analysis.domain_intelligence.dns?.A?.join(", ") || "None"}</p></div><div><span>IPv6</span><p>{analysis.domain_intelligence.dns?.AAAA?.join(", ") || "None"}</p></div><div><span>MX</span><p>{analysis.domain_intelligence.dns?.MX?.join(", ") || "None"}</p></div><div><span>NAMESERVERS</span><p>{analysis.domain_intelligence.dns?.NS?.join(", ") || "None"}</p></div></div></div>
                    <div className="origin-card"><div className="origin-card-header"><span>EMAIL AUTHENTICATION</span><strong>DNS SECURITY</strong></div><div className="origin-details"><div><span>SPF</span><p>{analysis.domain_intelligence.spf?.status || "UNKNOWN"}</p></div><div><span>DKIM</span><p>{analysis.domain_intelligence.dkim?.status || "UNKNOWN"}</p></div><div><span>DMARC</span><p>{analysis.domain_intelligence.dmarc?.status || "UNKNOWN"}</p></div></div></div>
                    <div className="origin-card"><div className="origin-card-header"><span>REGISTRATION</span><strong>{analysis.domain_intelligence.rdap?.status || "N/A"}</strong></div><div className="origin-details"><div><span>REGISTRAR</span><p>{analysis.domain_intelligence.rdap?.registrar || "Unavailable"}</p></div><div><span>HANDLE</span><p>{analysis.domain_intelligence.rdap?.handle || "N/A"}</p></div><div><span>REGISTERED</span><p>{analysis.domain_intelligence.rdap?.events?.find((e) => e.eventAction === "registration")?.eventDate || "N/A"}</p></div><div><span>EXPIRES</span><p>{analysis.domain_intelligence.rdap?.events?.find((e) => e.eventAction === "expiration")?.eventDate || "N/A"}</p></div></div></div>
                    <div className="origin-card"><div className="origin-card-header"><span>INFRASTRUCTURE</span><strong>{analysis.domain_intelligence.infrastructure?.ipv4_count ?? 0} IPv4</strong></div><div className="origin-details"><div><span>IPv4 COUNT</span><p>{analysis.domain_intelligence.infrastructure?.ipv4_count ?? 0}</p></div><div><span>IPv6 COUNT</span><p>{analysis.domain_intelligence.infrastructure?.ipv6_count ?? 0}</p></div><div><span>MX COUNT</span><p>{analysis.domain_intelligence.infrastructure?.mx_count ?? 0}</p></div><div><span>NS COUNT</span><p>{analysis.domain_intelligence.infrastructure?.nameserver_count ?? 0}</p></div></div></div>
                  </div>
                  <div className="findings-list" style={{ marginTop: "1.5rem" }}><span className="result-label">DOMAIN FINDINGS</span>{(analysis.domain_intelligence.findings || []).length > 0 ? analysis.domain_intelligence.findings.map((finding, index) => <div className="received-item" key={index}>{finding}</div>) : <div className="received-item">No domain findings returned.</div>}</div>
                </>
              ) : <div className="empty-page-state"><Globe size={42}/><h2>No domain intelligence</h2><p>The backend did not return domain intelligence for this case.</p></div>}
            </motion.section>
          )}

          {/* =================================================
                URL INTELLIGENCE
            ================================================= */}
          {analysis && activeAnalysisSection === "urls" && (
            <motion.section className="analysis-card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
              <div className="section-heading"><div><span className="result-label">URL INTELLIGENCE</span><h3>Suspicious Link & Destination Analysis</h3></div><Search size={24}/></div>
              <div className="origin-grid"><div className="origin-card"><div className="origin-card-header"><span>URLS DETECTED</span><strong>{analysis.url_analysis?.total ?? analysis.url_analysis?.urls?.length ?? 0}</strong></div></div><div className="origin-card"><div className="origin-card-header"><span>SUSPICIOUS</span><strong>{analysis.url_analysis?.suspicious_count ?? 0}</strong></div></div><div className="origin-card"><div className="origin-card-header"><span>RISK LEVEL</span><strong>{analysis.url_analysis?.risk_level || "ANALYZED"}</strong></div></div></div>
              <div className="findings-list" style={{ marginTop: "1.5rem" }}><span className="result-label">DETECTED URLS</span>{(analysis.url_analysis?.urls || []).length > 0 ? analysis.url_analysis.urls.map((item, index) => <div className="received-item" key={index}><strong>{typeof item === "string" ? item : (item.url || item.value || item.href || "Unknown URL")}</strong>{typeof item === "object" && (item.suspicious || item.is_suspicious) ? " • SUSPICIOUS" : ""}</div>) : <div className="received-item">No URLs were returned by the analyzer.</div>}{(analysis.url_analysis?.findings || []).map((finding, index) => <div className="received-item" key={`url-finding-${index}`}>{typeof finding === "string" ? finding : JSON.stringify(finding)}</div>)}</div>
            </motion.section>
          )}

          {/* =================================================
                ATTACHMENT INTELLIGENCE
            ================================================= */}
          {analysis && activeAnalysisSection === "attachments" && (
            <motion.section className="analysis-card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
              <div className="section-heading"><div><span className="result-label">ATTACHMENT FORENSICS</span><h3>Attachment Metadata & Risk Analysis</h3></div><FileText size={24}/></div>
              <div className="origin-grid"><div className="origin-card"><div className="origin-card-header"><span>ATTACHMENTS</span><strong>{analysis.attachment_analysis?.total ?? 0}</strong></div></div><div className="origin-card"><div className="origin-card-header"><span>SUSPICIOUS</span><strong>{analysis.attachment_analysis?.suspicious_count ?? 0}</strong></div></div><div className="origin-card"><div className="origin-card-header"><span>RISK LEVEL</span><strong>{analysis.attachment_analysis?.risk_level || "NONE"}</strong></div></div></div>
              <div className="findings-list" style={{ marginTop: "1.5rem" }}><span className="result-label">ATTACHMENT DETAILS</span>{(analysis.attachment_analysis?.attachments || []).length > 0 ? analysis.attachment_analysis.attachments.map((item, index) => <div className="received-item" key={index}><strong>{item.filename || "Unnamed attachment"}</strong> • {item.category || "OTHER"} • {item.extension || "UNKNOWN"} • {item.size_bytes ?? 0} bytes{item.risks?.length ? ` • ${item.risks.join("; ")}` : ""}</div>) : <div className="received-item">No attachments detected.</div>}</div>
            </motion.section>
          )}

          {/* =================================================
                CORRELATION INTELLIGENCE
            ================================================= */}
          {analysis && activeAnalysisSection === "correlation" && (
            <motion.section className="analysis-card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
              <div className="section-heading"><div><span className="result-label">CORRELATION INTELLIGENCE</span><h3>Sender, IP, Domain & Relay Correlation</h3></div><Network size={24}/></div>
              <div className="origin-grid"><div className="origin-card"><div className="origin-card-header"><span>NODES</span><strong>{analysis.correlation?.node_count ?? analysis.infrastructure_graph?.node_count ?? 0}</strong></div></div><div className="origin-card"><div className="origin-card-header"><span>RELATIONSHIPS</span><strong>{analysis.correlation?.relationship_count ?? analysis.infrastructure_graph?.relationship_count ?? 0}</strong></div></div><div className="origin-card"><div className="origin-card-header"><span>CONFIDENCE</span><strong>{analysis.correlation?.confidence ?? analysis.correlation?.attribution_confidence ?? "N/A"}</strong></div></div></div>
              <div className="findings-list" style={{ marginTop: "1.5rem" }}><span className="result-label">CORRELATION FINDINGS</span>{(analysis.correlation?.findings || []).length > 0 ? analysis.correlation.findings.map((finding, index) => <div className="received-item" key={index}>{typeof finding === "string" ? finding : JSON.stringify(finding)}</div>) : <div className="received-item">No additional correlation findings returned. The infrastructure graph remains the primary relationship view.</div>}</div>
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

            {analysis && activeAnalysisSection === "evidence" && (
              <motion.section
                className="analysis-card"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
              >
                <div className="section-heading">
                  <div>
                    <span className="result-label">DIGITAL EVIDENCE</span>
                    <h2>Evidence Preservation & Chain of Custody</h2>
                    <p>
                      Cryptographic verification and forensic preservation of
                      the original uploaded email evidence.
                    </p>
                  </div>
                  <Fingerprint size={24} />
                </div>

                <div className="analysis-grid">
                  <InfoBox label="EVIDENCE ID" value={String(analysis.evidence?.evidence_id ?? "N/A")} />
                  <InfoBox label="FILE NAME" value={String(analysis.evidence?.filename ?? selectedFile?.name ?? "N/A")} />
                  <InfoBox
                    label="FILE SIZE"
                    value={analysis.evidence?.file_size != null ? `${analysis.evidence.file_size} bytes` : "N/A"}
                  />
                  <InfoBox label="EVIDENCE TYPE" value={String(analysis.evidence?.evidence_type ?? "EMAIL")} />
                  <InfoBox label="STATUS" value={String(analysis.evidence?.status ?? "PRESERVED")} />
                  <InfoBox
                    label="PRESERVED AT"
                    value={analysis.evidence?.preserved_at ? new Date(analysis.evidence.preserved_at).toLocaleString() : "N/A"}
                  />
                </div>

                <div className="intel-block">
                  <div className="intel-title">
                    <Hash size={18} />
                    <span>SHA-256 EVIDENCE INTEGRITY</span>
                  </div>
                  <div
                    className="finding-safe"
                    style={{ wordBreak: "break-all", fontFamily: "monospace", lineHeight: 1.7 }}
                  >
                    {String(analysis.evidence?.sha256 ?? "SHA-256 hash unavailable")}
                  </div>
                  <p className="hero-text" style={{ marginTop: "14px" }}>
                    This cryptographic fingerprint is generated from the uploaded
                    email evidence and is used to verify evidence integrity.
                  </p>
                </div>

                <div className="intel-block">
                  <div className="intel-title">
                    <ShieldCheck size={18} />
                    <span>CHAIN OF CUSTODY</span>
                  </div>

                  <div className="finding-safe">
                    <strong>
                      {String(
                        analysis?.chain_of_custody?.continuity ??
                        analysis?.chain_of_custody?.status ??
                        "INTACT"
                      )}
                    </strong>
                    <br />
                    Evidence handling continuity is recorded by TARVEX26.
                  </div>

                  <div className="analysis-grid" style={{ marginTop: "14px" }}>
                    <InfoBox
                      label="CUSTODY EVENTS"
                      value={String(
                        analysis?.chain_of_custody?.event_count ??
                        analysis?.chain_of_custody?.chain_of_custody?.event_count ??
                        analysis?.chain_of_custody?.events?.length ??
                        analysis?.chain_of_custody?.chain_of_custody?.events?.length ??
                        "N/A"
                      )}
                    />
                    <InfoBox
                      label="INTEGRITY"
                      value={String(
                        analysis?.integrity_verification?.status ??
                        analysis?.custody_summary?.integrity_status ??
                        "VERIFIED"
                      )}
                    />
                  </div>
                </div>

                <div className="section-heading" style={{ marginTop: "24px" }}>
                  <div>
                    <span className="result-label">FORENSIC STATUS</span>
                    <h3>Evidence Integrity Verified</h3>
                  </div>
                  <ShieldCheck size={24} />
                </div>

                <div className="finding-safe">
                  ✓ Original email evidence preserved<br />
                  ✓ SHA-256 fingerprint generated<br />
                  ✓ Chain-of-custody continuity maintained<br />
                  ✓ Evidence available for forensic reporting
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