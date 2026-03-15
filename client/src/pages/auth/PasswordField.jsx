import { Eye, EyeOff } from "lucide-react";
import { useMemo, useState } from "react";

export default function PasswordField({
  id,
  label,
  name,
  autoComplete,
  value,
  onChange,
  placeholder,
  error,
  required = false,
  minLength,
  maxLength,
  describedBy,
  autoCapitalize = "none",
  spellCheck = false
}) {
  const [visible, setVisible] = useState(false);
  const resolvedDescribedBy = useMemo(
    () => [describedBy, error ? `${id}-error` : ""].filter(Boolean).join(" "),
    [describedBy, error, id]
  );

  return (
    <label htmlFor={id} className="auth-field">
      <span className="auth-label-text">{label}</span>
      <div className={`auth-control ${error ? "invalid" : ""}`}>
        <input
          id={id}
          name={name}
          type={visible ? "text" : "password"}
          autoComplete={autoComplete}
          autoCapitalize={autoCapitalize}
          spellCheck={spellCheck}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          required={required}
          minLength={minLength}
          maxLength={maxLength}
          aria-invalid={error ? "true" : "false"}
          aria-describedby={resolvedDescribedBy || undefined}
        />
        <button
          type="button"
          className="password-visibility-toggle"
          onClick={() => setVisible((current) => !current)}
          aria-label={`${visible ? "Hide" : "Show"} ${label.toLowerCase()}`}
        >
          {visible ? <EyeOff size={16} aria-hidden="true" /> : <Eye size={16} aria-hidden="true" />}
        </button>
      </div>
      {error ? (
        <small id={`${id}-error`} className="auth-field-error" role="alert">
          {error}
        </small>
      ) : null}
    </label>
  );
}
