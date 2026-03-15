import { motion, useReducedMotion } from "framer-motion";
import { Link } from "react-router-dom";
import { motionPreset } from "../../appUtils";

export default function AuthShell({
  appName,
  appTagline,
  logoAltText,
  brandMark,
  eyebrow,
  title,
  description,
  children,
  footer,
  aside
}) {
  const prefersReducedMotion = useReducedMotion();

  return (
    <motion.main className="auth-page" {...motionPreset(prefersReducedMotion)}>
      <div className="auth-page-grid" aria-hidden="true" />
      <div className="auth-page-inner">
        <Link to="/" className="auth-brand-lockup" aria-label={`${appName} homepage`}>
          <img src={brandMark} alt={logoAltText} className="auth-brand-mark" />
          <span className="auth-brand-text">
            <strong>{appName}</strong>
            <small>{appTagline}</small>
          </span>
        </Link>

        <motion.section className="auth-panel auth-panel-main" {...motionPreset(prefersReducedMotion, 0.04)}>
          {eyebrow ? <p className="auth-panel-eyebrow">{eyebrow}</p> : null}
          <header className="auth-panel-header">
            <h1>{title}</h1>
            <p>{description}</p>
          </header>
          {children}
        </motion.section>

        {aside ? (
          <motion.aside className="auth-panel auth-panel-support" {...motionPreset(prefersReducedMotion, 0.08)}>
            {aside}
          </motion.aside>
        ) : null}

        {footer ? <div className="auth-page-footer">{footer}</div> : null}
      </div>
    </motion.main>
  );
}
