import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import AuthShell from "./auth/AuthShell";
import { prefetchRouteModule } from "../routeModules";

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || "").trim());
}

export default function ForgotPasswordPage({ appName, appTagline, logoAltText, brandMarks, onRequestForgotPassword }) {
  const [searchParams] = useSearchParams();
  const [email, setEmail] = useState(String(searchParams.get("email") || "").trim());
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const buildPrefetchIntentProps = (path) => ({
    onMouseEnter: () => prefetchRouteModule(path),
    onFocus: () => prefetchRouteModule(path),
    onTouchStart: () => prefetchRouteModule(path)
  });

  useEffect(() => {
    const nextEmail = String(searchParams.get("email") || "").trim();
    if (nextEmail) {
      setEmail(nextEmail);
    }
  }, [searchParams]);

  async function handleSubmit(event) {
    event.preventDefault();
    if (submitting) {
      return;
    }

    const normalizedEmail = String(email || "").trim().toLowerCase();
    if (!normalizedEmail) {
      setError("Enter your email address.");
      setNotice("");
      return;
    }

    if (!isValidEmail(normalizedEmail)) {
      setError("Use a valid email address.");
      setNotice("");
      return;
    }

    setSubmitting(true);
    setError("");
    setNotice("");

    try {
      const payload = await onRequestForgotPassword(normalizedEmail);
      const message = payload?.message || "If the email exists, reset instructions will be sent.";
      setNotice(message);
      toast.success("Reset email sent. Check your inbox.");
    } catch (requestError) {
      const message = requestError.message || "Could not send reset email.";
      setError(message);
      toast.error(message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthShell
      appName={appName}
      appTagline={appTagline}
      logoAltText={logoAltText}
      brandMark={brandMarks.lightSurface}
      eyebrow="Password Recovery"
      title="Forgot your password?"
      description="Enter the email on your account and we will send secure reset instructions if the account exists."
      footer={
        <p className="auth-footer-copy">
          Back to{" "}
          <Link
            className="auth-inline-link"
            to={`/signin${email ? `?email=${encodeURIComponent(email)}` : ""}`}
            {...buildPrefetchIntentProps("/signin")}
          >
            Sign in
          </Link>
        </p>
      }
    >
      <form className="auth-form auth-form-modern" onSubmit={handleSubmit} autoComplete="on" method="post" noValidate>
        <label htmlFor="forgot-password-email" className="auth-field">
          <span className="auth-label-text">Email address</span>
          <div className={`auth-control ${error ? "invalid" : ""}`}>
            <input
              id="forgot-password-email"
              name="email"
              type="email"
              autoComplete="email"
              inputMode="email"
              autoCapitalize="none"
              spellCheck={false}
              value={email}
              onChange={(event) => {
                setEmail(event.target.value);
                if (error) {
                  setError("");
                }
              }}
              placeholder="you@company.com"
              required
              aria-invalid={error ? "true" : "false"}
              aria-describedby={error ? "forgot-password-email-error" : undefined}
            />
          </div>
          {error ? (
            <small id="forgot-password-email-error" className="auth-field-error" role="alert">
              {error}
            </small>
          ) : null}
        </label>

        {notice ? <div className="auth-inline-banner auth-inline-banner-success">{notice}</div> : null}

        <button type="submit" className="primary auth-submit" disabled={submitting}>
          {submitting ? "Sending reset..." : "Send reset email"}
        </button>
      </form>
    </AuthShell>
  );
}
