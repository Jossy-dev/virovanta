import { useEffect, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { Link, useParams } from "react-router-dom";
import { motionPreset, formatDateTime, formatBytes, formatVerdictLabel, getDisplayFileType, getRiskMeta } from "../appUtils";

export default function SharedReportPage({ appName, logoAltText, brandMarks, onLoadSharedReport }) {
  const prefersReducedMotion = useReducedMotion();
  const { token } = useParams();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [report, setReport] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      if (!token) {
        setError("Shared report link is invalid.");
        setLoading(false);
        return;
      }

      setLoading(true);
      setError("");

      try {
        const payload = await onLoadSharedReport(token);
        if (!cancelled) {
          setReport(payload?.report || null);
        }
      } catch (requestError) {
        if (!cancelled) {
          setError(requestError.message || "Could not load shared report.");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    void load();

    return () => {
      cancelled = true;
    };
  }, [onLoadSharedReport, token]);

  const riskMeta = getRiskMeta(report?.riskScore);

  return (
    <motion.main className="app-shell centered reset-shell" {...motionPreset(prefersReducedMotion)}>
      <motion.section className="card loading-card reset-card" {...motionPreset(prefersReducedMotion, 0.04)}>
        <div className="brand-lockup">
          <img src={brandMarks.lightSurface} alt={logoAltText} className="brand-mark brand-mark-small" />
          <h1>{appName}</h1>
        </div>

        {loading ? (
          <>
            <h2>Loading shared report</h2>
            <p className="subtext">Verifying link and fetching the report.</p>
          </>
        ) : error ? (
          <>
            <h2>Shared report unavailable</h2>
            <p className="error">{error}</p>
          </>
        ) : report ? (
          <div className="guest-report-box" style={{ width: "100%" }}>
            <div className="report-header">
              <h2>Shared Report</h2>
              <span className={`pill ${riskMeta.tone}`}>{formatVerdictLabel(report.verdict)}</span>
            </div>
            <div className="summary-grid">
              <div>
                <span>Risk Score</span>
                <strong className={`risk-score ${riskMeta.tone}`}>{report.riskScore}/100</strong>
                <small className={`risk-label ${riskMeta.tone}`}>{riskMeta.label}</small>
              </div>
              <div>
                <span>File Type</span>
                <strong>{getDisplayFileType(report.file)}</strong>
              </div>
              <div>
                <span>Completed</span>
                <strong>{formatDateTime(report.completedAt || report.createdAt)}</strong>
              </div>
              <div>
                <span>File Size</span>
                <strong>{formatBytes(report.file?.size)}</strong>
              </div>
            </div>

            {report.findings?.length ? (
              <ul className="guest-findings">
                {report.findings.map((finding) => (
                  <li key={`${finding.id}-${finding.title}`}>
                    <div className="guest-finding-copy">
                      <strong>{finding.title}</strong>
                      <small>{finding.description}</small>
                    </div>
                    <span>{finding.severity}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted">No significant findings were included in this shared report.</p>
            )}

            {report.recommendations?.length ? (
              <div className="password-checklist" style={{ marginTop: "1rem" }}>
                <p className="password-checklist-title">Recommended next steps</p>
                <ul>
                  {report.recommendations.map((item) => (
                    <li key={item} className="pass">
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        ) : (
          <p className="muted">No report data found.</p>
        )}

        <div className="reset-actions">
          <Link className="ghost small" to="/">
            Return home
          </Link>
        </div>
      </motion.section>
    </motion.main>
  );
}
