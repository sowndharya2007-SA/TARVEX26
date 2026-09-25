import React from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Database,
  Globe,
  Search,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Server,
} from "lucide-react";

function statusClass(status) {
  const value = String(status || "UNKNOWN").toUpperCase();

  if (value === "MALICIOUS") return "ti-status malicious";
  if (value === "SUSPICIOUS") return "ti-status suspicious";
  if (value === "NO_MATCH") return "ti-status clean";
  if (value === "NO_INDICATORS") return "ti-status clean";
  if (value === "CONNECTED") return "ti-status connected";

  return "ti-status unknown";
}

function IndicatorCard({ indicator }) {
  const external = indicator?.external_intelligence;
  const matches = external?.matches || [];

  return (
    <div className="ti-indicator-card">
      <div className="ti-indicator-top">
        <div>
          <span className="ti-indicator-type">
            {indicator?.indicator_type || "INDICATOR"}
          </span>

          <h3>{indicator?.indicator || "Unknown indicator"}</h3>
        </div>

        <span className={statusClass(indicator?.reputation_status)}>
          {indicator?.reputation_status || "UNKNOWN"}
        </span>
      </div>

      <div className="ti-indicator-details">
        {indicator?.organization && (
          <div>
            <span>Organization</span>
            <strong>{indicator.organization}</strong>
          </div>
        )}

        {indicator?.asn && (
          <div>
            <span>ASN</span>
            <strong>{indicator.asn}</strong>
          </div>
        )}

        {indicator?.country && (
          <div>
            <span>Country</span>
            <strong>{indicator.country}</strong>
          </div>
        )}

        {indicator?.city && (
          <div>
            <span>City</span>
            <strong>{indicator.city}</strong>
          </div>
        )}
      </div>

      <div className="ti-external">
        <div className="ti-external-header">
          <Database size={16} />
          <span>ThreatFox</span>

          <span
            className={statusClass(
              external?.status || "UNKNOWN"
            )}
          >
            {external?.status || "NOT QUERIED"}
          </span>
        </div>

        {external?.status === "MATCH" && matches.length > 0 ? (
          <div className="ti-match-list">
            {matches.map((match, index) => (
              <div
                className="ti-match"
                key={match.id || index}
              >
                <div>
                  <span>Threat Type</span>
                  <strong>
                    {match.threat_type || "Unknown"}
                  </strong>
                </div>

                <div>
                  <span>IOC Type</span>
                  <strong>
                    {match.ioc_type || "Unknown"}
                  </strong>
                </div>

                {match.malware_printable && (
                  <div>
                    <span>Malware</span>
                    <strong>
                      {match.malware_printable}
                    </strong>
                  </div>
                )}

                {match.confidence_level !== null &&
                  match.confidence_level !== undefined && (
                    <div>
                      <span>Confidence</span>
                      <strong>
                        {match.confidence_level}
                      </strong>
                    </div>
                  )}
              </div>
            ))}
          </div>
        ) : (
          <div className="ti-no-match">
            <CheckCircle2 size={16} />
            <span>
              No ThreatFox IOC match found
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

export default function ThreatIntelligencePanel({
  analysis,
}) {
  const intelligence =
    analysis?.threat_intelligence || {};

  const indicators =
    Array.isArray(intelligence.indicators)
      ? intelligence.indicators
      : [];

  const counts =
    intelligence.counts || {};

  const threatfox =
    intelligence.external_sources?.threatfox || {};

  const findings =
    Array.isArray(intelligence.findings)
      ? intelligence.findings
      : [];

  const confidence =
    intelligence.confidence !== null &&
    intelligence.confidence !== undefined
      ? intelligence.confidence
      : null;

  const overallStatus =
    intelligence.overall_status || "UNKNOWN";

  return (
    <div className="threat-intelligence-panel">

      {/* HEADER */}
      <div className="ti-header">
        <div>
          <div className="ti-kicker">
            TARVEX26 // SIH26106
          </div>

          <h2>
            <ShieldCheck size={24} />
            Threat Intelligence
          </h2>

          <p>
            Reputation & External IOC Correlation
          </p>
        </div>

        <div className={statusClass(overallStatus)}>
          {overallStatus}
        </div>
      </div>

      {/* OVERVIEW */}
      <div className="ti-overview">

        <div className="ti-overview-card">
          <span>Overall Status</span>
          <strong>{overallStatus}</strong>
        </div>

        <div className="ti-overview-card">
          <span>Intelligence Confidence</span>
          <strong>
            {confidence !== null
              ? `${confidence}%`
              : "NOT ESTABLISHED"}
          </strong>
        </div>

        <div className="ti-overview-card">
          <span>Indicators</span>
          <strong>{indicators.length}</strong>
        </div>

      </div>

      {/* EXTERNAL SOURCES */}
      <section className="ti-section">

        <div className="ti-section-title">
          <Database size={18} />
          External Intelligence
        </div>

        <div className="ti-source-card">

          <div className="ti-source-icon">
            <Search size={22} />
          </div>

          <div className="ti-source-main">
            <h3>ThreatFox</h3>

            <p>
              Malware IOC correlation
            </p>
          </div>

          <span
            className={statusClass(
              threatfox.status
            )}
          >
            {threatfox.status || "UNKNOWN"}
          </span>

        </div>

        <div className="ti-stats">

          <div>
            <span>IOC Queries</span>
            <strong>
              {threatfox.indicator_count ?? 0}
            </strong>
          </div>

          <div>
            <span>IOC Matches</span>
            <strong>
              {threatfox.match_count ?? 0}
            </strong>
          </div>

          <div>
            <span>Source</span>
            <strong>ThreatFox</strong>
          </div>

        </div>

      </section>

      {/* COUNTS */}
      <section className="ti-section">

        <div className="ti-section-title">
          <ShieldAlert size={18} />
          Correlation Summary
        </div>

        <div className="ti-count-grid">

          <div className="ti-count malicious-count">
            <span>Malicious</span>
            <strong>{counts.malicious || 0}</strong>
          </div>

          <div className="ti-count suspicious-count">
            <span>Suspicious</span>
            <strong>{counts.suspicious || 0}</strong>
          </div>

          <div className="ti-count clean-count">
            <span>No Indicators</span>
            <strong>{counts.no_indicators || 0}</strong>
          </div>

          <div className="ti-count unknown-count">
            <span>Unknown</span>
            <strong>{counts.unknown || 0}</strong>
          </div>

        </div>

      </section>

      {/* INDICATORS */}
      <section className="ti-section">

        <div className="ti-section-title">
          <Globe size={18} />
          Observed Indicators
        </div>

        {indicators.length > 0 ? (
          <div className="ti-indicator-grid">
            {indicators.map((indicator, index) => (
              <IndicatorCard
                key={
                  `${indicator.indicator}-${index}`
                }
                indicator={indicator}
              />
            ))}
          </div>
        ) : (
          <div className="ti-empty">
            No indicators were available
            for external correlation.
          </div>
        )}

      </section>

      {/* FINDINGS */}
      <section className="ti-section">

        <div className="ti-section-title">
          <AlertTriangle size={18} />
          Investigation Findings
        </div>

        <div className="ti-findings">

          {findings.map((finding, index) => (
            <div
              className="ti-finding"
              key={index}
            >
              <CheckCircle2 size={16} />
              <span>{finding}</span>
            </div>
          ))}

        </div>

      </section>

      {/* ENGINE */}
      <section className="ti-engine">

        <div>
          <Server size={16} />
          <span>Engine</span>
        </div>

        <strong>
          {intelligence.engine?.name ||
            "TARVEX26 Threat Intelligence Engine"}
        </strong>

        <span>
          v
          {intelligence.engine?.version ||
            "2.0"}
        </span>

        <span>
          {intelligence.analyzed_at
            ? new Date(
                intelligence.analyzed_at
              ).toLocaleString()
            : "Analysis time unavailable"}
        </span>

      </section>

      {/* FORENSIC NOTE */}
      <div className="ti-note">
        <Clock size={16} />

        <span>
          Threat intelligence results are
          source-dependent. A no-match result
          does not prove that an indicator is
          benign. Infrastructure attribution
          identifies observed network resources,
          not a specific person.
        </span>
      </div>

    </div>
  );
}