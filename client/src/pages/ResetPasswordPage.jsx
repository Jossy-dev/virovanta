import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { buildPasswordChecklist } from "../appUtils";
import AuthShell from "./auth/AuthShell";
import PasswordField from "./auth/PasswordField";
import { prefetchRouteModule } from "../routeModules";

export default function ResetPasswordPage({ appName, appTagline, logoAltText, brandMarks, resetAccessToken, resetEmail, onResetPassword }) {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    password: "",
    confirmPassword: ""
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const buildPrefetchIntentProps = (path) => ({
    onMouseEnter: () => prefetchRouteModule(path),
    onFocus: () => prefetchRouteModule(path),
    onTouchStart: () => prefetchRouteModule(path)
  });

  const passwordChecklist = buildPasswordChecklist(form.password, resetEmail, form.confirmPassword);

  useEffect(() => {
    setForm({ password: "", confirmPassword: "" });
    setError("");
    setNotice("");
  }, [resetAccessToken, resetEmail]);

  async function handleSubmit(event) {
    event.preventDefault();
    if (submitting) {
      return;
    }

    setSubmitting(true);
    setError("");
    setNotice("");

    try {
      const failedRule = passwordChecklist.find((rule) => !rule.ok);
      if (failedRule) {
        throw new Error(`Password rule not met: ${failedRule.label}.`);
      }

      if (!resetAccessToken) {
        throw new Error("Reset link is invalid or missing token.");
      }

      const payload = await onResetPassword({
        accessToken: resetAccessToken,
        password: form.password,
        email: resetEmail
      });

      const message = payload?.message || "Password updated successfully. You can now sign in.";
      setNotice(message);
      toast.success(message);

      setTimeout(() => {
        navigate(`/signin${resetEmail ? `?email=${encodeURIComponent(resetEmail)}` : ""}`, { replace: true });
      }, 900);
    } catch (requestError) {
      const message = requestError.message || "Could not update password.";
      setError(message);
      toast.error(message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthShell
      appName={appName}
      appTagline={appTagline || "Reset secure access"}
      logoAltText={logoAltText}
      brandMark={brandMarks.lightSurface}
      eyebrow="Reset Secure Access"
      title="Set a new password"
      description={`Update the password for ${resetEmail || "your account"} and return to the sign-in flow.`}
      footer={
        <p className="auth-footer-copy">
          Back to{" "}
          <Link
            className="auth-inline-link"
            to={`/signin${resetEmail ? `?email=${encodeURIComponent(resetEmail)}` : ""}`}
            {...buildPrefetchIntentProps("/signin")}
          >
            Sign in
          </Link>
        </p>
      }
    >
      {!resetAccessToken ? (
        <div className="auth-inline-banner" role="alert">
          Reset link is invalid or expired. Request a new password reset email.
        </div>
      ) : (
        <form className="auth-form auth-form-modern" onSubmit={handleSubmit} autoComplete="on" method="post" noValidate>
          <label htmlFor="reset-email" className="auth-field">
            <span className="auth-label-text">Account email</span>
            <div className="auth-control auth-control-readonly">
              <input id="reset-email" name="email" type="email" autoComplete="username" value={resetEmail || ""} readOnly />
            </div>
          </label>

          <PasswordField
            id="reset-password"
            label="New password"
            name="newPassword"
            autoComplete="new-password"
            value={form.password}
            onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))}
            placeholder="Create a new password"
            required
            minLength={12}
            maxLength={128}
            error=""
            describedBy="reset-password-rules"
          />

          <PasswordField
            id="reset-confirm-password"
            label="Confirm new password"
            name="confirmNewPassword"
            autoComplete="new-password"
            value={form.confirmPassword}
            onChange={(event) => setForm((current) => ({ ...current, confirmPassword: event.target.value }))}
            placeholder="Confirm your new password"
            required
            minLength={12}
            maxLength={128}
            error=""
          />

          <div className="password-checklist" id="reset-password-rules" aria-live="polite">
            <p className="password-checklist-title">Password requirements</p>
            <ul>
              {passwordChecklist.map((rule) => (
                <li key={`reset-${rule.key}`} className={rule.ok ? "pass" : "fail"}>
                  <span>{rule.label}</span>
                </li>
              ))}
            </ul>
          </div>

          {error ? (
            <div className="auth-inline-banner" role="alert">
              {error}
            </div>
          ) : null}
          {notice ? <div className="auth-inline-banner auth-inline-banner-success">{notice}</div> : null}

          <button type="submit" className="primary auth-submit" disabled={submitting}>
            {submitting ? "Updating..." : "Update password"}
          </button>
        </form>
      )}
    </AuthShell>
  );
}
