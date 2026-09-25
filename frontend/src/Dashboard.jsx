import React from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Globe,
  Link2,
  Paperclip,
  Server,
  Database,
  FileCheck2,
  AlertTriangle,
  Activity,
} from "lucide-react";

function getThreat(analysis) {
  return (
    analysis?.threat_analysis ||
    analysis?.threat ||
    {}
  );
}

function getHeaders(analysis) {
  return (
    analysis?.header_analysis ||
    analysis?.headers ||
    {}
  );
}

function getGeo(analysis) {
  return (
    analysis?.geoip_intelligence ||
    {}
  );
}

function getUrls(analysis) {
  return (
    analysis?.url_intelligence ||
    {}
  );
}

function getAttachments(analysis) {
  return (
    analysis?.attachment_intelligence ||
    {}
  );
}

function getIntel(analysis) {
  return (
    analysis?.threat_intelligence ||
    {}
  );
}

function getGraph(analysis) {
  return (
    analysis?.infrastructure_graph ||
    {}
  );
}

function firstValue(...values) {
  return values.find(
    (value) =>
      value !== undefined &&
      value !== null &&
      value !== ""
  );
}

function StatusBadge({ value }) {
  const status = String(value || "UNKNOWN").toUpperCase();

  let className = "dash-badge unknown";

  if (
    ["PASS", "PASSED", "VERIFIED", "CONNECTED", "PRESERVED", "NO_MATCH"].includes(
      status
    )
  ) {
    className = "dash-badge success";
  }

  if (
    ["FAIL", "FAILED", "HIGH", "CRITICAL", "MALICIOUS"].includes(
      status
    )
  ) {
    className = "dash-badge danger";
  }

  if (
    ["MEDIUM", "SUSPICIOUS", "WARNING"].includes(
      status
    )
  ) {
    className = "dash-badge warning";
  }

  return (
    <span className={className}>
      {status}
    </span>
  );
}

function MetricCard({
  icon,
  label,
  value,
  subtext,
  type = "default",
}) {
  return (
    <div className={`dashboard-metric ${type}`}>
      <div className="dashboard-metric-icon">
        {icon}
      </div>

      <div className="dashboard-metric-content">
        <span>{label}</span>
        <strong>{value}</strong>

        {subtext && (
          <small>{subtext}</small>
        )}
      </div>
    </div>
  );
}

export default function Dashboard({ analysis }) {
  const threat = getThreat(analysis);
  const headers = getHeaders(analysis);
  const geo = getGeo(analysis);
  const urls = getUrls(analysis);
  const attachments = getAttachments(analysis);
  const intel = getIntel(analysis);
  const graph = getGraph(analysis);

  const threatScore = firstValue(
    threat.threat_score,
    threat.score,
    threat.fraud_score,
    0
  );

  const riskLevel = firstValue(
    threat.risk_level,
    threat.risk,
    "UNKNOWN"
  );

  const classification = firstValue(
    threat.classification,
    threat.category,
    "UNKNOWN"
  );

  const confidence = firstValue(
    threat.confidence,
    threat.confidence_score,
    null
  );

  const geoResults = Array.isArray(geo.results)
    ? geo.results
    : [];

  const firstGeo =
    geoResults.find(
      (item) =>
        item?.status === "FOUND" ||
        item?.latitude !== null ||
        item?.lat !== null
    ) ||
    geoResults[0] ||
    {};

  const originIp = firstValue(
    firstGeo.ip,
    firstGeo.indicator,
    geoResults[0]?.ip,
    "Not available"
  );

  const country = firstValue(
    firstGeo.country,
    firstGeo.country_name,
    "Unknown"
  );

  const city = firstValue(
    firstGeo.city,
    "Unknown"
  );

  const organization = firstValue(
    firstGeo.organization,
    firstGeo.org,
    firstGeo.isp,
    "Unknown"
  );

  const asn = firstValue(
    firstGeo.asn,
    firstGeo.asn_number,
    "Unknown"
  );

  const urlCount = firstValue(
    urls.total,
    urls.total_urls,
    Array.isArray(urls.urls)
      ? urls.urls.length
      : 0
  );

  const suspiciousUrlCount = firstValue(
    urls.suspicious_count,
    urls.suspicious_urls?.length,
    0
  );

  const urlRisk = firstValue(
    urls.risk_level,
    "NONE"
  );

  const attachmentCount = firstValue(
    attachments.total,
    attachments.total_attachments,
    Array.isArray(attachments.attachments)
      ? attachments.attachments.length
      : 0
  );

  const suspiciousAttachmentCount =
    firstValue(
      attachments.suspicious_count,
      attachments.suspicious_files?.length,
      0
    );

  const attachmentRisk = firstValue(
    attachments.risk_level,
    "NONE"
  );

  const suspiciousFiles = Array.isArray(
    attachments.suspicious_files
  )
    ? attachments.suspicious_files
    : [];

  const threatfox =
    intel.external_sources?.threatfox || {};

  const graphNodes = firstValue(
    graph.node_count,
    graph.nodes?.length,
    0
  );

  const graphRelationships = firstValue(
    graph.relationship_count,
    graph.relationships?.length,
    0
  );

  const evidence = analysis?.evidence || {};

  const evidenceStatus = firstValue(
    evidence.status,
    analysis?.evidence_status,
    "PRESERVED"
  );

  return (
    <div className="tarvex-dashboard">

      {/* HEADER */}

      <div className="dashboard-header">

        <div>
          <div className="dashboard-kicker">
            TARVEX26 // SIH26106
          </div>

          <h2>
            <Activity size={24} />
            Forensic Investigation Dashboard
          </h2>

          <p>
            Unified threat detection, origin intelligence
            and evidence analysis
          </p>
        </div>

        <div className="dashboard-live">
          <span className="dashboard-live-dot" />
          ANALYSIS COMPLETE
        </div>

      </div>


      {/* PRIMARY METRICS */}

      <div className="dashboard-metrics">

        <MetricCard
          icon={<ShieldAlert size={20} />}
          label="Threat Score"
          value={threatScore}
          subtext="/ 100"
          type="danger-card"
        />

        <MetricCard
          icon={<AlertTriangle size={20} />}
          label="Risk Level"
          value={riskLevel}
          subtext={classification}
          type="warning-card"
        />

        <MetricCard
          icon={<ShieldCheck size={20} />}
          label="Confidence"
          value={
            confidence !== null
              ? `${confidence}%`
              : "N/A"
          }
          subtext="Threat assessment"
          type="info-card"
        />

        <MetricCard
          icon={<FileCheck2 size={20} />}
          label="Evidence"
          value={evidenceStatus}
          subtext="Chain preserved"
          type="success-card"
        />

      </div>


      {/* AUTHENTICATION */}

      <section className="dashboard-section">

        <div className="dashboard-section-title">
          <ShieldCheck size={17} />
          Email Authentication
        </div>

        <div className="auth-grid">

          <div className="auth-card">
            <span>SPF</span>
            <StatusBadge
              value={
                headers.spf ||
                headers.spf_status ||
                headers.authentication?.spf ||
                "UNKNOWN"
              }
            />
          </div>

          <div className="auth-card">
            <span>DKIM</span>
            <StatusBadge
              value={
                headers.dkim ||
                headers.dkim_status ||
                headers.authentication?.dkim ||
                "UNKNOWN"
              }
            />
          </div>

          <div className="auth-card">
            <span>DMARC</span>
            <StatusBadge
              value={
                headers.dmarc ||
                headers.dmarc_status ||
                headers.authentication?.dmarc ||
                "UNKNOWN"
              }
            />
          </div>

          <div className="auth-card">
            <span>Message-ID</span>
            <strong>
              {headers.message_id ||
                headers.messageId ||
                "Available"}
            </strong>
          </div>

        </div>

      </section>


      {/* ORIGIN */}

      <section className="dashboard-section">

        <div className="dashboard-section-title">
          <Globe size={17} />
          Origin Intelligence
        </div>

        <div className="origin-dashboard-card">

          <div className="origin-main">

            <div className="origin-icon">
              <Globe size={22} />
            </div>

            <div>
              <span>ORIGIN IP</span>
              <strong>{originIp}</strong>
            </div>

          </div>

          <div className="origin-details">

            <div>
              <span>Country</span>
              <strong>{country}</strong>
            </div>

            <div>
              <span>City</span>
              <strong>{city}</strong>
            </div>

            <div>
              <span>Organization</span>
              <strong>{organization}</strong>
            </div>

            <div>
              <span>ASN</span>
              <strong>{asn}</strong>
            </div>

          </div>

        </div>

      </section>


      {/* URL + ATTACHMENT */}

      <div className="dashboard-two-column">

        <section className="dashboard-section">

          <div className="dashboard-section-title">
            <Link2 size={17} />
            URL Intelligence
          </div>

          <div className="analysis-summary-card">

            <div className="summary-number">
              {urlCount}
              <span>Total URLs</span>
            </div>

            <div className="summary-number danger-number">
              {suspiciousUrlCount}
              <span>Suspicious</span>
            </div>

            <div className="summary-status">
              <span>Risk Level</span>
              <StatusBadge value={urlRisk} />
            </div>

          </div>

        </section>


        <section className="dashboard-section">

          <div className="dashboard-section-title">
            <Paperclip size={17} />
            Attachment Intelligence
          </div>

          <div className="analysis-summary-card">

            <div className="summary-number">
              {attachmentCount}
              <span>Total</span>
            </div>

            <div className="summary-number danger-number">
              {suspiciousAttachmentCount}
              <span>Suspicious</span>
            </div>

            <div className="summary-status">
              <span>Risk Level</span>
              <StatusBadge value={attachmentRisk} />
            </div>

          </div>

          {suspiciousFiles.length > 0 && (
            <div className="dashboard-file-warning">
              <AlertTriangle size={14} />

              <div>
                <span>Suspicious file</span>
                <strong>
                  {suspiciousFiles[0]}
                </strong>
              </div>
            </div>
          )}

        </section>

      </div>


      {/* THREAT INTELLIGENCE */}

      <section className="dashboard-section">

        <div className="dashboard-section-title">
          <Database size={17} />
          External Threat Intelligence
        </div>

        <div className="dashboard-intel-card">

          <div className="intel-provider">

            <div className="intel-icon">
              <Database size={21} />
            </div>

            <div>
              <span>THREATFOX</span>
              <strong>
                Malware IOC Correlation
              </strong>
            </div>

            <StatusBadge
              value={
                threatfox.status ||
                "UNKNOWN"
              }
            />

          </div>

          <div className="intel-numbers">

            <div>
              <span>IOC QUERIES</span>
              <strong>
                {threatfox.indicator_count ?? 0}
              </strong>
            </div>

            <div>
              <span>IOC MATCHES</span>
              <strong>
                {threatfox.match_count ?? 0}
              </strong>
            </div>

            <div>
              <span>INDICATORS</span>
              <strong>
                {intel.indicators?.length ?? 0}
              </strong>
            </div>

            <div>
              <span>STATUS</span>
              <strong>
                {intel.overall_status ||
                  "UNKNOWN"}
              </strong>
            </div>

          </div>

        </div>

      </section>


      {/* INFRASTRUCTURE */}

      <section className="dashboard-section">

        <div className="dashboard-section-title">
          <Server size={17} />
          Infrastructure Correlation
        </div>

        <div className="infrastructure-summary">

          <div>
            <strong>{graphNodes}</strong>
            <span>Graph Nodes</span>
          </div>

          <div>
            <strong>{graphRelationships}</strong>
            <span>Relationships</span>
          </div>

          <div className="infra-description">
            <span>
              Correlated email, domain, IP and
              infrastructure relationships detected
              during forensic analysis.
            </span>
          </div>

        </div>

      </section>


      {/* FINAL ASSESSMENT */}

      <div className="dashboard-assessment">

        <div className="assessment-icon">
          <ShieldAlert size={22} />
        </div>

        <div>

          <span>FORENSIC ASSESSMENT</span>

          <strong>
            {classification}
          </strong>

          <p>
            TARVEX26 combines header analysis,
            explainable threat scoring, URL and
            attachment intelligence, origin
            geolocation and external IOC correlation
            into a unified forensic view.
          </p>

        </div>

      </div>

    </div>
  );
}