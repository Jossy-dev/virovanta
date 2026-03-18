import { useEffect, useMemo, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { Link } from "react-router-dom";
import { buildApiUrl } from "../appConfig";
import { motionPreset } from "../appUtils";
import PublicSiteFooter from "./public/PublicSiteFooter";
import PublicSiteHeader from "./public/PublicSiteHeader";
import { prefetchRouteModule } from "../routeModules";
import { createInteractiveMotion } from "../ui/motionSystem";
import { SkeletonBlock, SkeletonText } from "../ui/Skeleton";

const DEFAULT_STATUS = Object.freeze({
  status: "unknown",
  timestamp: "",
  reliability: {
    deterministicErrorResponses: true,
    scanSlaTargetMinutes: 5,
    uptimeTargetPercent: "99.9"
  },
  limits: {
    guestQuickScan: {
      maxUploadMb: 8,
      requestsPerWindow: 30,
      windowMinutes: 15
    },
    authenticated: {
      maxUploadMb: 25,
      maxFilesPerBatch: 10,
      dailyScanLimit: 40,
      linkScanRequestsPerWindow: 30,
      linkScanWindowMinutes: 15
    }
  },
  compliance: {
    reportsPrivateByDefault: true,
    userDeleteMode: "delete",
    reportRetentionDays: 90,
    note: "Deleting a report removes it from user history."
  }
});

function formatTimestamp(value) {
  const timestamp = Date.parse(value || "");
  if (!Number.isFinite(timestamp)) {
    return "Unknown";
  }

  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  }).format(new Date(timestamp));
}

export default function StatusPage({ appName, appTagline, logoAltText, brandMarks }) {
  const prefersReducedMotion = useReducedMotion();
  const MotionLink = motion(Link);
  const interactiveMotion = createInteractiveMotion(prefersReducedMotion, {
    hoverScale: 1.012,
    tapScale: 0.985
  });
  const buildPrefetchIntentProps = (path) => ({
    onMouseEnter: () => prefetchRouteModule(path),
    onFocus: () => prefetchRouteModule(path),
    onTouchStart: () => prefetchRouteModule(path)
  });
  const [statusPayload, setStatusPayload] = useState(DEFAULT_STATUS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let mounted = true;

    async function loadStatus() {
      try {
        const response = await fetch(buildApiUrl("/api/public/status"), {
          method: "GET",
          headers: {
            accept: "application/json"
          }
        });

        if (!response.ok) {
          throw new Error("Status endpoint unavailable.");
        }

        const payload = await response.json();
        if (mounted) {
          setStatusPayload({
            ...DEFAULT_STATUS,
            ...payload,
            reliability: {
              ...DEFAULT_STATUS.reliability,
              ...(payload?.reliability || {})
            },
            limits: {
              guestQuickScan: {
                ...DEFAULT_STATUS.limits.guestQuickScan,
                ...(payload?.limits?.guestQuickScan || {})
              },
              authenticated: {
                ...DEFAULT_STATUS.limits.authenticated,
                ...(payload?.limits?.authenticated || {})
              }
            },
            compliance: {
              ...DEFAULT_STATUS.compliance,
              ...(payload?.compliance || {})
            }
          });
          setError("");
        }
      } catch (requestError) {
        if (mounted) {
          setError(requestError?.message || "Could not load status details.");
        }
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    }

    void loadStatus();
    return () => {
      mounted = false;
    };
  }, []);

  const serviceTone = useMemo(() => {
    return String(statusPayload?.status || "").toLowerCase() === "operational" ? "text-emerald-600 dark:text-emerald-300" : "text-amber-600 dark:text-amber-300";
  }, [statusPayload?.status]);

  return (
    <motion.main className="app-shell marketing-shell" {...motionPreset(prefersReducedMotion)}>
      <motion.section className="card marketing-hero" {...motionPreset(prefersReducedMotion, 0.03)}>
        <div className="marketing-grid-bg" aria-hidden="true" />
        <div className="marketing-hero-inner">
          <PublicSiteHeader appName={appName} appTagline={appTagline} logoSrc={brandMarks.lightSurface} logoAltText={logoAltText} />
          <div className="marketing-hero-copy">
            <p className="eyebrow">Reliability and limits</p>
            <h1>Service status and reliability commitments</h1>
            <p className="subtext">
              Track platform health, scan SLA targets, limits, and data-retention behavior in one place.
            </p>
            <p className={`text-sm font-semibold ${serviceTone}`}>Current status: {statusPayload.status || "unknown"}</p>
            <p className="text-xs text-slate-500 dark:text-slate-400">Last updated {formatTimestamp(statusPayload.timestamp)}</p>
          </div>
          <div className="marketing-hero-actions">
            <MotionLink to="/signup" className="primary" {...buildPrefetchIntentProps("/signup")} {...interactiveMotion}>
              Create account
            </MotionLink>
            <MotionLink to="/" className="ghost" {...buildPrefetchIntentProps("/")} {...interactiveMotion}>
              Try guest scan
            </MotionLink>
          </div>
        </div>
      </motion.section>

      <motion.section className="card marketing-section" {...motionPreset(prefersReducedMotion, 0.06)}>
        <div className="section-head">
          <h2>Reliability promises</h2>
          <span className="panel-tag">Operational commitments</span>
        </div>
        <div className="marketing-card-grid">
          <article className="marketing-card">
            <h3>Scan SLA target</h3>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              New scan jobs are targeted for initial processing within {statusPayload.reliability.scanSlaTargetMinutes} minutes.
            </p>
          </article>
          <article className="marketing-card">
            <h3>Uptime target</h3>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              Service objective is {statusPayload.reliability.uptimeTargetPercent}% availability.
            </p>
          </article>
          <article className="marketing-card">
            <h3>Deterministic errors</h3>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              API error responses include stable error codes and request identifiers for support and automation debugging.
            </p>
          </article>
        </div>
      </motion.section>

      <motion.section className="card marketing-section" {...motionPreset(prefersReducedMotion, 0.09)}>
        <div className="section-head">
          <h2>Current limits and quotas</h2>
          <span className="panel-tag">Transparent limits</span>
        </div>
        <div className="marketing-card-grid">
          <article className="marketing-card">
            <h3>Guest quick scan</h3>
            <p>Max upload: {statusPayload.limits.guestQuickScan.maxUploadMb} MB</p>
            <p>Rate limit: {statusPayload.limits.guestQuickScan.requestsPerWindow} requests / {statusPayload.limits.guestQuickScan.windowMinutes} minutes</p>
          </article>
          <article className="marketing-card">
            <h3>Authenticated scanning</h3>
            <p>Max upload: {statusPayload.limits.authenticated.maxUploadMb} MB</p>
            <p>Batch limit: {statusPayload.limits.authenticated.maxFilesPerBatch} files</p>
            <p>Daily quota: {statusPayload.limits.authenticated.dailyScanLimit} scans (rolling 24h)</p>
          </article>
          <article className="marketing-card">
            <h3>Authenticated URL scanning</h3>
            <p>
              Rate limit: {statusPayload.limits.authenticated.linkScanRequestsPerWindow} requests / {statusPayload.limits.authenticated.linkScanWindowMinutes} minutes
            </p>
          </article>
        </div>
      </motion.section>

      <motion.section className="card marketing-section" {...motionPreset(prefersReducedMotion, 0.12)}>
        <div className="section-head">
          <h2>Privacy and retention behavior</h2>
          <span className="panel-tag">Compliance messaging</span>
        </div>
        <div className="marketing-card-grid">
          <article className="marketing-card">
            <h3>Private by default</h3>
            <p>Authenticated reports are account-scoped and are not publicly exposed unless a share link is explicitly created.</p>
          </article>
          <article className="marketing-card">
            <h3>User-initiated report deletion</h3>
            <p>Users can delete reports from dashboard history.</p>
          </article>
          <article className="marketing-card">
            <h3>Retention window</h3>
            <p>{statusPayload.compliance.note}</p>
            <p>Current retention window: {statusPayload.compliance.reportRetentionDays} days.</p>
          </article>
        </div>
      </motion.section>

      {loading ? (
        <motion.section className="card marketing-section" {...motionPreset(prefersReducedMotion, 0.14)} role="status" aria-live="polite" aria-busy="true">
          <div className="grid gap-3">
            <SkeletonBlock className="h-3 w-32" />
            <SkeletonBlock className="h-6 w-52" />
            <div className="rounded-2xl border border-slate-200/80 p-4 dark:border-slate-800/80">
              <SkeletonText lines={3} />
            </div>
          </div>
        </motion.section>
      ) : null}
      {error ? (
        <motion.section className="card marketing-section" {...motionPreset(prefersReducedMotion, 0.14)}>
          <p className="text-sm text-rose-600 dark:text-rose-300">{error}</p>
        </motion.section>
      ) : null}

      <motion.div className="marketing-footer-wrap" {...motionPreset(prefersReducedMotion, 0.16)}>
        <PublicSiteFooter appName={appName} appTagline={appTagline} logoSrc={brandMarks.lightSurface} logoAltText={logoAltText} />
      </motion.div>
    </motion.main>
  );
}
