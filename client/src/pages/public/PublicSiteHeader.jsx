import { Link } from "react-router-dom";
import { prefetchRouteModule } from "../../routeModules";

export default function PublicSiteHeader({
  appName,
  appTagline,
  logoSrc,
  logoAltText,
  variant = "default"
}) {
  const buildPrefetchIntentProps = (path) => ({
    onMouseEnter: () => prefetchRouteModule(path),
    onFocus: () => prefetchRouteModule(path),
    onTouchStart: () => prefetchRouteModule(path)
  });

  return (
    <header className={`public-site-header ${variant === "hero" ? "hero" : ""}`}>
      <Link className="public-site-brand" to="/" {...buildPrefetchIntentProps("/")}>
        <img src={logoSrc} alt={logoAltText} className="public-site-logo" />
        <span className="public-site-brand-copy">
          <strong>{appName}</strong>
          <small>{appTagline}</small>
        </span>
      </Link>

      <div className="public-site-actions">
        <Link to="/signin" className="public-site-link" {...buildPrefetchIntentProps("/signin")}>
          Sign in
        </Link>
        <Link to="/signup" className="public-site-link primary-link" {...buildPrefetchIntentProps("/signup")}>
          Create account
        </Link>
      </div>
    </header>
  );
}
