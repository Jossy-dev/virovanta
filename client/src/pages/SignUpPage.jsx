import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import {
  USERNAME_CHECK_DEBOUNCE_MS,
  SPRING_EASE,
  buildPasswordChecklist,
  isEmailConflictError
} from "../appUtils";
import AuthShell from "./auth/AuthShell";
import PasswordField from "./auth/PasswordField";

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || "").trim());
}

function getPasswordStrength(password, email) {
  const rules = buildPasswordChecklist(password, email, password).filter((rule) => rule.key !== "match");
  const passed = rules.filter((rule) => rule.ok).length;

  if (!password) {
    return { label: "Add a password", tone: "idle", score: 0 };
  }

  if (passed <= 2) {
    return { label: "Weak", tone: "weak", score: 1 };
  }

  if (passed <= 4) {
    return { label: "Fair", tone: "fair", score: 2 };
  }

  if (passed <= 5) {
    return { label: "Strong", tone: "good", score: 3 };
  }

  return { label: "Very strong", tone: "strong", score: 4 };
}

function AuthModal({ modal, onClose, onForgotPassword, forgotPasswordSubmitting }) {
  const prefersReducedMotion = useReducedMotion();

  return (
    <AnimatePresence>
      {modal.open ? (
        <motion.div
          className="auth-modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="auth-modal-title"
          initial={prefersReducedMotion ? false : { opacity: 0 }}
          animate={prefersReducedMotion ? {} : { opacity: 1 }}
          exit={prefersReducedMotion ? {} : { opacity: 0 }}
          transition={{ duration: 0.24, ease: SPRING_EASE }}
        >
          <motion.div
            className={`auth-modal ${modal.variant === "conflict" ? "conflict" : "success"}`}
            initial={prefersReducedMotion ? false : { opacity: 0, y: 20, scale: 0.97 }}
            animate={prefersReducedMotion ? {} : { opacity: 1, y: 0, scale: 1 }}
            exit={prefersReducedMotion ? {} : { opacity: 0, y: 20, scale: 0.98 }}
            transition={{ duration: 0.28, ease: SPRING_EASE }}
          >
            <div className={`auth-modal-icon ${modal.variant === "conflict" ? "conflict" : "success"}`} aria-hidden="true">
              {modal.variant === "conflict" ? "!" : "✓"}
            </div>
            <h3 id="auth-modal-title">{modal.title}</h3>
            <p>{modal.message}</p>
            <p>
              {modal.variant === "conflict" ? "Email on file: " : "Verification sent to "}
              <strong>{modal.email}</strong>
            </p>
            <div className="auth-modal-actions">
              <Link type="button" className="primary" to={`/signin${modal.email ? `?email=${encodeURIComponent(modal.email)}` : ""}`} onClick={onClose}>
                Sign in
              </Link>
              {modal.variant === "conflict" ? (
                <button type="button" className="ghost" disabled={forgotPasswordSubmitting} onClick={onForgotPassword}>
                  {forgotPasswordSubmitting ? "Sending reset..." : "Forgot password"}
                </button>
              ) : (
                <button type="button" className="ghost" onClick={onClose}>
                  Close
                </button>
              )}
            </div>
          </motion.div>
        </motion.div>
      ) : null}
    </AnimatePresence>
  );
}

export default function SignUpPage({
  appName,
  appTagline,
  logoAltText,
  brandMarks,
  onRegister,
  onCheckUsernameAvailability,
  onRequestForgotPassword
}) {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    email: "",
    username: "",
    password: "",
    confirmPassword: ""
  });
  const [submitting, setSubmitting] = useState(false);
  const [forgotPasswordSubmitting, setForgotPasswordSubmitting] = useState(false);
  const [errors, setErrors] = useState({});
  const [usernameAvailability, setUsernameAvailability] = useState({
    state: "idle",
    message: "",
    suggestions: [],
    checkedUsername: "",
    pending: false
  });
  const [modal, setModal] = useState({
    open: false,
    variant: "success",
    title: "",
    email: "",
    message: ""
  });

  const passwordChecklist = buildPasswordChecklist(form.password, form.email, form.confirmPassword);
  const passwordStrength = useMemo(() => getPasswordStrength(form.password, form.email), [form.email, form.password]);
  const usernameHasInlineIssue = ["invalid", "taken"].includes(usernameAvailability.state) || Boolean(errors.username);
  const usernameIndicatorState = usernameAvailability.pending ? "checking" : usernameAvailability.state;
  const latestUsernameRef = useRef("");
  const usernameRequestRef = useRef({
    sequence: 0,
    username: "",
    promise: null
  });

  const applyUsernameAvailability = useCallback((username, nextState) => {
    if (latestUsernameRef.current !== username) {
      return;
    }

    setUsernameAvailability({
      state: nextState.state,
      message: nextState.message,
      suggestions: nextState.suggestions,
      checkedUsername: username,
      pending: false
    });
  }, []);

  const runUsernameAvailabilityCheck = useCallback(
    async (username, { reusePending = true } = {}) => {
      const normalizedUsername = String(username || "").trim();
      if (normalizedUsername.length < 2) {
        return {
          username: normalizedUsername,
          available: false,
          invalid: true,
          suggestions: []
        };
      }

      if (
        reusePending &&
        usernameRequestRef.current.promise &&
        usernameRequestRef.current.username === normalizedUsername
      ) {
        return usernameRequestRef.current.promise;
      }

      const sequence = usernameRequestRef.current.sequence + 1;
      usernameRequestRef.current.sequence = sequence;
      usernameRequestRef.current.username = normalizedUsername;

      setUsernameAvailability((current) => {
        if (latestUsernameRef.current !== normalizedUsername) {
          return current;
        }

        return {
          ...current,
          pending: true,
          ...(current.checkedUsername === normalizedUsername
            ? {}
            : {
                state: "idle",
                message: "",
                suggestions: [],
                checkedUsername: ""
              })
        };
      });

      const request = onCheckUsernameAvailability(normalizedUsername)
        .then((payload) => {
          const result = {
            username: normalizedUsername,
            available: Boolean(payload?.available),
            suggestions: Array.isArray(payload?.suggestions) ? payload.suggestions.slice(0, 3) : []
          };

          if (usernameRequestRef.current.sequence === sequence) {
            applyUsernameAvailability(normalizedUsername, {
              state: result.available ? "available" : "taken",
              message: result.available ? "Username is available." : "Username is taken.",
              suggestions: result.available ? [] : result.suggestions
            });
          }

          return result;
        })
        .catch((error) => {
          if (usernameRequestRef.current.sequence === sequence && latestUsernameRef.current === normalizedUsername) {
            setUsernameAvailability({
              state: "error",
              message: "Could not verify username right now.",
              suggestions: [],
              checkedUsername: "",
              pending: false
            });
          }

          throw error;
        })
        .finally(() => {
          if (usernameRequestRef.current.sequence === sequence) {
            usernameRequestRef.current.promise = null;
          }
        });

      usernameRequestRef.current.promise = request;
      return request;
    },
    [applyUsernameAvailability, onCheckUsernameAvailability]
  );

  useEffect(() => {
    const username = String(form.username || "").trim();
    if (!username) {
      setUsernameAvailability({
        state: "idle",
        message: "",
        suggestions: [],
        checkedUsername: "",
        pending: false
      });
      return;
    }

    if (username.length < 2) {
      setUsernameAvailability({
        state: "invalid",
        message: "Use at least 2 characters.",
        suggestions: [],
        checkedUsername: "",
        pending: false
      });
      return;
    }

    const timer = setTimeout(async () => {
      try {
        await runUsernameAvailabilityCheck(username, { reusePending: false });
      } catch (_error) {
        return;
      }
    }, USERNAME_CHECK_DEBOUNCE_MS);

    return () => {
      clearTimeout(timer);
    };
  }, [form.username, runUsernameAvailabilityCheck]);

  function updateField(field, value) {
    if (field === "username") {
      latestUsernameRef.current = String(value || "").trim();
      setUsernameAvailability((current) => {
        const nextUsername = latestUsernameRef.current;
        if (!nextUsername) {
          return {
            state: "idle",
            message: "",
            suggestions: [],
            checkedUsername: "",
            pending: false
          };
        }

        if (nextUsername.length < 2) {
          return {
            state: "invalid",
            message: "Use at least 2 characters.",
            suggestions: [],
            checkedUsername: "",
            pending: false
          };
        }

        if (current.checkedUsername === nextUsername) {
          return current;
        }

        return {
          state: "idle",
          message: "",
          suggestions: [],
          checkedUsername: "",
          pending: false
        };
      });
    }

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
    const username = String(form.username || "").trim();
    const password = String(form.password || "");
    const confirmPassword = String(form.confirmPassword || "");

    if (!username) {
      nextErrors.username = "Choose a username.";
    } else if (username.length < 2) {
      nextErrors.username = "Username must be at least 2 characters.";
    } else if (usernameAvailability.checkedUsername === username && usernameAvailability.state === "taken") {
      nextErrors.username = "Username is taken. Pick one of the suggestions.";
    }

    if (!normalizedEmail) {
      nextErrors.email = "Enter your email address.";
    } else if (!isValidEmail(normalizedEmail)) {
      nextErrors.email = "Use a valid email address.";
    }

    if (!password) {
      nextErrors.password = "Create a password.";
    } else {
      const failedRule = buildPasswordChecklist(password, normalizedEmail, confirmPassword).find((rule) => !rule.ok && rule.key !== "match");
      if (failedRule) {
        nextErrors.password = failedRule.label;
      }
    }

    if (!confirmPassword) {
      nextErrors.confirmPassword = "Confirm your password.";
    } else if (password !== confirmPassword) {
      nextErrors.confirmPassword = "Passwords must match.";
    }

    return nextErrors;
  }

  async function sendForgotPassword() {
    const email = String(form.email || "").trim().toLowerCase();
    if (!email) {
      toast.error("Enter your email first.");
      return;
    }

    setForgotPasswordSubmitting(true);

    try {
      await onRequestForgotPassword(email);
      toast.success("Reset email sent. Check your inbox.");
    } catch (requestError) {
      toast.error(requestError.message || "Could not send reset email.");
    } finally {
      setForgotPasswordSubmitting(false);
    }
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
    setModal((current) => ({ ...current, open: false }));

    try {
      const normalizedEmail = String(form.email || "").trim().toLowerCase();
      const normalizedUsername = String(form.username || "").trim();
      let usernameCheckResult = null;

      try {
        usernameCheckResult = await runUsernameAvailabilityCheck(normalizedUsername);
      } catch (_error) {
        setErrors({
          username: "Could not verify username right now. Try again."
        });
        toast.error("Could not verify username right now.");
        return;
      }

      if (!usernameCheckResult?.available) {
        setUsernameAvailability({
          state: "taken",
          message: "Username is taken.",
          suggestions: usernameCheckResult?.suggestions || [],
          checkedUsername: normalizedUsername,
          pending: false
        });
        setErrors({
          username: "Username is taken. Pick one of the suggestions."
        });
        toast.error("This username is already taken.");
        return;
      }

      const payload = await onRegister({
        email: normalizedEmail,
        password: form.password,
        username: normalizedUsername
      });

      if (payload?.requiresEmailConfirmation) {
        setModal({
          open: true,
          variant: "success",
          title: "Account created. Verify your email.",
          email: normalizedEmail,
          message: payload.message || "We sent a verification email. Confirm it, then sign in."
        });
        toast.success("Account created. Check your email to verify and continue.");
        setForm((current) => ({
          ...current,
          email: normalizedEmail,
          password: "",
          confirmPassword: "",
          username: ""
        }));
        latestUsernameRef.current = "";
        setUsernameAvailability({
          state: "idle",
          message: "",
          suggestions: [],
          checkedUsername: "",
          pending: false
        });
        return;
      }

      navigate("/app/dashboard", { replace: true });
    } catch (requestError) {
      if (requestError?.code === "AUTH_USERNAME_EXISTS") {
        const suggestions = Array.isArray(requestError?.details?.suggestions)
          ? requestError.details.suggestions.slice(0, 3)
          : [];
        setUsernameAvailability({
          state: "taken",
          message: "Username is taken.",
          suggestions,
          checkedUsername: String(form.username || "").trim(),
          pending: false
        });
        setErrors((current) => ({
          ...current,
          username: "Username is taken. Pick one of the suggestions."
        }));
      }

      if (isEmailConflictError(requestError)) {
        const normalizedEmail = String(form.email || "").trim().toLowerCase();
        setModal({
          open: true,
          variant: "conflict",
          title: "An account already exists for this email.",
          email: normalizedEmail,
          message: "Use Sign in, or reset your password to continue."
        });
        toast.error("This email is already in use.");
        setSubmitting(false);
        return;
      }

      const message = requestError.message || "Could not create your account.";
      setErrors({ form: message });
      toast.error(message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <AuthShell
        appName={appName}
        appTagline={appTagline}
        logoAltText={logoAltText}
        brandMark={brandMarks.lightSurface}
        eyebrow="Create Secure Access"
        title="Create your account"
        description="Set up your ViroVanta workspace with saved history, notifications, API keys, and batch upload support."
        footer={
          <p className="auth-footer-copy">
            Already have an account?{" "}
            <Link to="/signin" className="auth-inline-link">
              Sign in
            </Link>
          </p>
        }
      >
        <form className="auth-form auth-form-modern" onSubmit={handleSubmit} autoComplete="on" method="post" noValidate>
          <label htmlFor="signup-username" className="auth-field">
            <span className="auth-label-text">Username</span>
            <div className={`auth-control auth-control-with-indicator ${usernameHasInlineIssue ? "invalid" : ""}`}>
              <input
                id="signup-username"
                name="username"
                type="text"
                autoComplete="nickname"
                autoCapitalize="none"
                spellCheck={false}
                value={form.username}
                onChange={(event) => updateField("username", event.target.value)}
                placeholder="your username"
                minLength={2}
                maxLength={80}
                required
                aria-invalid={usernameHasInlineIssue ? "true" : "false"}
                aria-describedby={[
                  errors.username ? "signup-username-error" : "",
                  usernameAvailability.message ? "signup-username-status" : ""
                ]
                  .filter(Boolean)
                  .join(" ") || undefined}
              />
              <span className={`auth-input-indicator ${usernameIndicatorState}`} aria-hidden="true">
                {usernameAvailability.pending ? "…" : null}
                {usernameAvailability.state === "available" ? "✓" : null}
                {usernameAvailability.state === "taken" ? "✕" : null}
              </span>
            </div>

            {usernameAvailability.message ? (
              <small id="signup-username-status" className={`username-status ${usernameAvailability.state}`}>
                {usernameAvailability.message}
              </small>
            ) : null}

            {errors.username ? (
              <small id="signup-username-error" className="auth-field-error" role="alert">
                {errors.username}
              </small>
            ) : null}

            {usernameAvailability.state === "taken" && usernameAvailability.suggestions.length > 0 ? (
              <div className="username-suggestions">
                {usernameAvailability.suggestions.map((suggestion) => (
                  <button
                    key={suggestion}
                    type="button"
                    className="username-suggestion"
                    onClick={() => {
                      setForm((current) => ({ ...current, username: suggestion }));
                      setErrors((current) => ({ ...current, username: "", form: "" }));
                    }}
                  >
                    {suggestion}
                  </button>
                ))}
              </div>
            ) : null}
          </label>

          <label htmlFor="signup-email" className="auth-field">
            <span className="auth-label-text">Email address</span>
            <div className={`auth-control ${errors.email ? "invalid" : ""}`}>
              <input
                id="signup-email"
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
                aria-describedby={errors.email ? "signup-email-error" : undefined}
              />
            </div>
            {errors.email ? (
              <small id="signup-email-error" className="auth-field-error" role="alert">
                {errors.email}
              </small>
            ) : null}
          </label>

          <div className="auth-strength-card">
            <div className="auth-strength-header">
              <span>Password strength</span>
              <strong className={`auth-strength-value ${passwordStrength.tone}`}>{passwordStrength.label}</strong>
            </div>
            <div className="auth-strength-meter" aria-hidden="true">
              {[0, 1, 2, 3].map((segment) => (
                <span
                  key={`strength-${segment}`}
                  className={`auth-strength-segment ${segment < passwordStrength.score ? `active ${passwordStrength.tone}` : ""}`}
                />
              ))}
            </div>
          </div>

          <PasswordField
            id="signup-password"
            label="Password"
            name="password"
            autoComplete="new-password"
            value={form.password}
            onChange={(event) => updateField("password", event.target.value)}
            placeholder="Create a strong password"
            required
            minLength={12}
            maxLength={128}
            error={errors.password}
            describedBy="signup-password-rules"
          />

          <PasswordField
            id="signup-confirm-password"
            label="Confirm password"
            name="confirmPassword"
            autoComplete="new-password"
            value={form.confirmPassword}
            onChange={(event) => updateField("confirmPassword", event.target.value)}
            placeholder="Confirm your password"
            required
            minLength={12}
            maxLength={128}
            error={errors.confirmPassword}
          />

          <div className="password-checklist" id="signup-password-rules" aria-live="polite">
            <p className="password-checklist-title">Password requirements</p>
            <ul>
              {passwordChecklist.map((rule) => (
                <li key={rule.key} className={rule.ok ? "pass" : "fail"}>
                  <span>{rule.label}</span>
                </li>
              ))}
            </ul>
          </div>

          {errors.form ? (
            <div className="auth-inline-banner" role="alert">
              {errors.form}
            </div>
          ) : null}

          <button type="submit" className="primary auth-submit" disabled={submitting}>
            {submitting ? "Creating account..." : "Sign up"}
          </button>
        </form>
      </AuthShell>

      <AuthModal
        modal={modal}
        onClose={() => setModal((current) => ({ ...current, open: false }))}
        onForgotPassword={sendForgotPassword}
        forgotPasswordSubmitting={forgotPasswordSubmitting}
      />
    </>
  );
}
