import { Link } from "react-router-dom";

export default function PublicSiteHeader({
  appName,
  appTagline,
  logoSrc,
  logoAltText,
  variant = "default"
}) {
  return (
    <header className={`public-site-header ${variant === "hero" ? "hero" : ""}`}>
      <Link className="public-site-brand" to="/">
        <img src={logoSrc} alt={logoAltText} className="public-site-logo" />
        <span className="public-site-brand-copy">
          <strong>{appName}</strong>
          <small>{appTagline}</small>
        </span>
      </Link>

      <div className="public-site-actions">
        <Link to="/signin" className="public-site-link">
          Sign in
        </Link>
        <Link to="/signup" className="public-site-link primary-link">
          Create account
        </Link>
      </div>
    </header>
  );
}
