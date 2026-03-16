import { useRef, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { Link } from "react-router-dom";
import {
  VERDICT_META,
  formatBytes,
  getDisplayFileType,
  getPlainFindingNote,
  getRiskMeta,
  motionPreset
} from "../appUtils";
import PublicSiteFooter from "./public/PublicSiteFooter";
import PublicSiteHeader from "./public/PublicSiteHeader";

export default function LandingPage({
  appName,
  appTagline,
  logoAltText,
  brandMarks,
  heroBackground,
  typedHeroHeadline,
  guestStatus,
  runGuestQuickScan
}) {
  const prefersReducedMotion = useReducedMotion();
  const guestFileInputRef = useRef(null);
  const [guestFile, setGuestFile] = useState(null);
  const [isGuestScanning, setIsGuestScanning] = useState(false);
  const [guestReport, setGuestReport] = useState(null);
  const [guestError, setGuestError] = useState("");
  const [isGuestDragActive, setIsGuestDragActive] = useState(false);

  const guestVerdictMeta = VERDICT_META[guestReport?.verdict] || VERDICT_META.clean;
  const guestRiskMeta = getRiskMeta(guestReport?.riskScore);

  function handleGuestFile(file) {
    if (!file) {
      return;
    }

    if (!guestStatus.enabled) {
      setGuestError("Guest quick scan is currently disabled.");
      return;
    }

    const maxUploadBytes = guestStatus.maxUploadMb * 1024 * 1024;
    if (file.size > maxUploadBytes) {
      setGuestFile(null);
      setGuestReport(null);
      setGuestError(`File exceeds guest limit of ${guestStatus.maxUploadMb} MB.`);
      return;
    }

    setGuestFile(file);
    setGuestReport(null);
    setGuestError("");
  }

  async function handleRunGuestScan() {
    if (!guestFile || isGuestScanning) {
      return;
    }

    setGuestError("");
    setGuestReport(null);
    setIsGuestScanning(true);

    try {
      const report = await runGuestQuickScan(guestFile);
      setGuestReport(report || null);
    } catch (error) {
      setGuestError(error.message || "Quick scan failed.");
    } finally {
      setIsGuestScanning(false);
    }
  }

  return (
    <motion.main className="app-shell landing-shell" {...motionPreset(prefersReducedMotion)}>
      <motion.section
        className="card landing-hero"
        style={{
          "--landing-hero-poster": `url("${heroBackground.posterSrc}")`
        }}
        {...motionPreset(prefersReducedMotion, 0.03)}
      >
        <video
          className="landing-hero-video"
          autoPlay
          muted
          loop
          playsInline
          preload="auto"
          poster={heroBackground.posterSrc}
          aria-hidden="true"
        >
          <source src={heroBackground.videoSrc} type="video/mp4" />
        </video>
        <div className="landing-hero-content">
          <PublicSiteHeader
            appName={appName}
            appTagline={appTagline}
            logoSrc={brandMarks.darkSurface}
            logoAltText={logoAltText}
            variant="hero"
          />
          <div className="landing-copy">
            <p className="eyebrow">Malware and Defect Detection Platform</p>
            <h1 className="hero-typing" aria-label={typedHeroHeadline}>
              <span>{typedHeroHeadline}</span>
              <span className="typing-caret" aria-hidden="true" />
            </h1>
            <p className="subtext">
              {appName} analyzes uploaded files using layered heuristics and security engines, then returns a clear risk
              score, findings, and next-step guidance.
            </p>
            <ul className="hero-points">
              <li>Real-time guest scan for rapid file checks</li>
              <li>Automated verdicts with clear, plain-language findings</li>
              <li>Full account workflow with saved reports and API keys</li>
            </ul>
          </div>
        </div>
      </motion.section>

      <motion.section className="card guest-card" {...motionPreset(prefersReducedMotion, 0.07)}>
        <div className="section-head">
          <h2>Quick Guest Scan</h2>
          <span className="panel-tag">No account needed</span>
        </div>
        <p className="subtext">
          Drop one file and test the scanner instantly. Guest scans are for evaluation and are not saved to account
          history.
        </p>
        <div className="guest-meta">
          <span className={`pill ${guestStatus.enabled ? "clean" : "failed"}`}>
            {guestStatus.loading ? "Checking status..." : guestStatus.enabled ? "Guest scan online" : "Guest scan unavailable"}
          </span>
          <span className="guest-meta-limit">Max upload {guestStatus.maxUploadMb} MB</span>
        </div>
        {guestStatus.message ? <p className="muted">{guestStatus.message}</p> : null}

        <label
          className={`upload-drop guest-drop ${guestFile ? "has-file" : ""} ${isGuestDragActive ? "drag-active" : ""} ${!guestStatus.enabled ? "disabled" : ""}`}
          onDragOver={(event) => {
            if (!guestStatus.enabled) {
              return;
            }
            event.preventDefault();
            setIsGuestDragActive(true);
          }}
          onDragLeave={() => setIsGuestDragActive(false)}
          onDrop={(event) => {
            if (!guestStatus.enabled) {
              return;
            }
            event.preventDefault();
            setIsGuestDragActive(false);
            handleGuestFile(event.dataTransfer.files?.[0] || null);
          }}
        >
          <input
            ref={guestFileInputRef}
            type="file"
            className="file-input-hidden"
            disabled={!guestStatus.enabled}
            onChange={(event) => handleGuestFile(event.target.files?.[0] || null)}
          />
          <span className="drop-title">{guestFile ? guestFile.name : "Drop file here or click to choose"}</span>
          <small>{guestFile ? formatBytes(guestFile.size) : "Fast guest scan with temporary upload processing"}</small>
        </label>

        <div className="upload-actions">
          <button
            type="button"
            className="primary"
            disabled={!guestFile || isGuestScanning || !guestStatus.enabled}
            onClick={handleRunGuestScan}
          >
            {isGuestScanning ? "Scanning..." : "Run Guest Scan"}
          </button>
          <button
            type="button"
            className="ghost"
            disabled={!guestFile || !guestStatus.enabled}
            onClick={() => {
              setGuestFile(null);
              setGuestReport(null);
              if (guestFileInputRef.current) {
                guestFileInputRef.current.value = "";
              }
            }}
          >
            Clear
          </button>
        </div>

        {guestError ? <p className="error">{guestError}</p> : null}

        {guestReport ? (
          <div className="guest-report-box">
            <div className="report-header">
              <h3>Guest Result</h3>
              <span className={`pill ${guestVerdictMeta.tone}`}>{guestVerdictMeta.label}</span>
            </div>
            <div className="summary-grid">
              <div>
                <span>Risk Score</span>
                <strong className={`risk-score ${guestRiskMeta.tone}`}>{guestReport.riskScore}/100</strong>
                <small className={`risk-label ${guestRiskMeta.tone}`}>{guestRiskMeta.label}</small>
              </div>
              <div>
                <span>File Type</span>
                <strong>{getDisplayFileType(guestReport.file)}</strong>
              </div>
            </div>
            {guestReport.findings.length > 0 ? (
              <ul className="guest-findings">
                {guestReport.findings.slice(0, 3).map((finding) => (
                  <li key={`${finding.id}-${finding.title}`}>
                    <div className="guest-finding-copy">
                      <strong>{finding.title}</strong>
                      <small>{getPlainFindingNote(finding)}</small>
                    </div>
                    <span>{finding.severity}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted">No significant findings in guest scan.</p>
            )}
          </div>
        ) : null}
      </motion.section>

      <motion.section className="card auth-card landing-auth-card" {...motionPreset(prefersReducedMotion, 0.1)}>
        <h2 className="auth-title">Create Account for Full Workflow</h2>
        <p className="subtext">Save reports, queue jobs, and generate API keys for automation.</p>

        <div className="auth-switch">
          <Link className="ghost" to="/signin">
            Sign in
          </Link>
          <Link className="primary" to="/signup">
            Create account
          </Link>
        </div>

        <ul className="hero-points">
          <li>Batch uploads for signed-in users</li>
          <li>Saved scan history with shareable reports</li>
          <li>API key management and notifications</li>
        </ul>
      </motion.section>

      <motion.section className="card landing-seo-card" {...motionPreset(prefersReducedMotion, 0.12)}>
        <div className="section-head">
          <h2>What ViroVanta scans</h2>
          <span className="panel-tag">For office and security teams</span>
        </div>
        <div className="landing-seo-grid">
          <article className="landing-seo-item">
            <span className="landing-seo-bullet" aria-hidden="true" />
            <div className="landing-seo-copy">
              <h3>Email attachments and downloads</h3>
              <p>Check suspicious attachments, downloaded files, and unknown documents before users open them.</p>
            </div>
          </article>
          <article className="landing-seo-item">
            <span className="landing-seo-bullet" aria-hidden="true" />
            <div className="landing-seo-copy">
              <h3>Scripts, executables, and archives</h3>
              <p>Inspect scripts, installers, executables, and archive files for malware signals and risky indicators.</p>
            </div>
          </article>
          <article className="landing-seo-item">
            <span className="landing-seo-bullet" aria-hidden="true" />
            <div className="landing-seo-copy">
              <h3>Plain-language risk reports</h3>
              <p>Get a verdict, risk score, findings, hashes, and next-step guidance without requiring deep security expertise.</p>
            </div>
          </article>
        </div>
      </motion.section>

      <motion.section className="card landing-seo-card" {...motionPreset(prefersReducedMotion, 0.13)}>
        <div className="section-head">
          <h2>How ViroVanta works</h2>
          <span className="panel-tag">Three-step workflow</span>
        </div>
        <div className="landing-process-grid">
          <article className="landing-process-step">
            <span>01</span>
            <div className="landing-process-copy">
              <h3>Upload suspicious files</h3>
              <p>Start with a quick guest test or sign in to queue one or many files for analysis.</p>
            </div>
          </article>
          <article className="landing-process-step">
            <span>02</span>
            <div className="landing-process-copy">
              <h3>Run layered analysis</h3>
              <p>The app inspects file structure, entropy, hashes, anomaly signals, and malware-related indicators.</p>
            </div>
          </article>
          <article className="landing-process-step">
            <span>03</span>
            <div className="landing-process-copy">
              <h3>Review the report</h3>
              <p>Use the risk score, findings, recommendations, and history view to decide what to do next.</p>
            </div>
          </article>
        </div>
      </motion.section>

      <motion.div className="landing-footer-wrap" {...motionPreset(prefersReducedMotion, 0.14)}>
        <PublicSiteFooter
          appName={appName}
          appTagline={appTagline}
          logoSrc={brandMarks.lightSurface}
          logoAltText={logoAltText}
        />
      </motion.div>
    </motion.main>
  );
}
