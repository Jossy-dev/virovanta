import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import AuthShell from "./auth/AuthShell";
import PasswordField from "./auth/PasswordField";

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || "").trim());
}

export default function SignInPage({ appName, appTagline, logoAltText, brandMarks, onLogin }) {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [form, setForm] = useState({
    email: String(searchParams.get("email") || "").trim(),
    password: "",
    rememberMe: true
  });
  const [errors, setErrors] = useState({});
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    const email = String(searchParams.get("email") || "").trim();
    if (email) {
      setForm((current) => ({ ...current, email }));
    }
  }, [searchParams]);

  useEffect(() => {
    if (searchParams.get("confirmed") !== "1") {
      return;
    }

    const email = String(searchParams.get("email") || "").trim();
    toast.success("Email confirmed. Sign in to continue.");
    navigate(`/signin${email ? `?email=${encodeURIComponent(email)}` : ""}`, { replace: true });
  }, [navigate, searchParams]);

  function updateField(field, value) {
    setForm((current) => ({ ...current, [field]: value }));
    setErrors((current) => {
      if (!current[field] && !current.form) {
        return current;
      }

      return {
        ...current,
        [field]: "",
        form: ""
      };
    });
  }

  function validate() {
    const nextErrors = {};
    const normalizedEmail = String(form.email || "").trim().toLowerCase();

    if (!normalizedEmail) {
      nextErrors.email = "Enter your email address.";
    } else if (!isValidEmail(normalizedEmail)) {
      nextErrors.email = "Use a valid email address.";
    }

    if (!String(form.password || "")) {
      nextErrors.password = "Enter your password.";
    }

    return nextErrors;
  }

  async function handleSubmit(event) {
    event.preventDefault();
    if (submitting) {
      return;
    }

    const nextErrors = validate();
    if (Object.keys(nextErrors).length > 0) {
      setErrors(nextErrors);
      return;
    }

    setSubmitting(true);
    setErrors({});

    try {
      await onLogin({
        email: form.email,
        password: form.password,
        rememberMe: form.rememberMe
      });
      navigate("/app/dashboard", { replace: true });
    } catch (requestError) {
      const message = requestError.message || "Could not sign in.";
      setErrors({ form: message });
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
      eyebrow="Secure Workspace Access"
      title="Sign in"
      description="Access your ViroVanta workspace to continue scans, review report history, and manage automation access."
      footer={
        <p className="auth-footer-copy">
          Don&apos;t have an account?{" "}
          <Link to="/signup" className="auth-inline-link">
            Create one
          </Link>
        </p>
      }
    >
      <form className="auth-form auth-form-modern" onSubmit={handleSubmit} autoComplete="on" method="post" noValidate>
        <label htmlFor="signin-email" className="auth-field">
          <span className="auth-label-text">Email address</span>
          <div className={`auth-control ${errors.email ? "invalid" : ""}`}>
            <input
              id="signin-email"
              name="email"
              type="email"
              autoComplete="username"
              inputMode="email"
              autoCapitalize="none"
              spellCheck={false}
              value={form.email}
              onChange={(event) => updateField("email", event.target.value)}
              placeholder="you@company.com"
              required
              aria-invalid={errors.email ? "true" : "false"}
              aria-describedby={errors.email ? "signin-email-error" : undefined}
            />
          </div>
          {errors.email ? (
            <small id="signin-email-error" className="auth-field-error" role="alert">
              {errors.email}
            </small>
          ) : null}
        </label>

        <PasswordField
          id="signin-password"
          label="Password"
          name="password"
          autoComplete="current-password"
          value={form.password}
          onChange={(event) => updateField("password", event.target.value)}
          placeholder="Enter your password"
          required
          error={errors.password}
        />

        <div className="auth-form-row">
          <label className="auth-checkbox">
            <input
              type="checkbox"
              name="rememberMe"
              checked={form.rememberMe}
              onChange={(event) => setForm((current) => ({ ...current, rememberMe: event.target.checked }))}
            />
            <span>Remember me</span>
          </label>
          <Link className="auth-inline-link" to={`/forgot-password${form.email ? `?email=${encodeURIComponent(form.email)}` : ""}`}>
            Forgot password?
          </Link>
        </div>

        {errors.form ? (
          <div className="auth-inline-banner" role="alert">
            {errors.form}
          </div>
        ) : null}

        <button type="submit" className="primary auth-submit" disabled={submitting}>
          {submitting ? "Signing in..." : "Sign in"}
        </button>
      </form>
    </AuthShell>
  );
}
