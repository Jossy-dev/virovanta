import { Link } from "react-router-dom";
import { prefetchRouteModule } from "../../routeModules";

export default function PublicSiteHeader({
  appName,
  appTagline,
  logoSrc,
  logoAltText,
  variant = "default"
}) {
  const actionBaseClass =
    "inline-flex min-h-10 touch-manipulation select-none items-center justify-center rounded-full border px-4 text-sm font-semibold transition duration-150 ease-out active:scale-[0.985]";
  const secondaryActionClass =
    variant === "hero"
      ? `${actionBaseClass} border-white/20 bg-emerald-950/40 text-white shadow-[0_12px_28px_rgba(7,28,20,0.24)] hover:border-white/45 hover:bg-emerald-900/60`
      : `${actionBaseClass} border-slate-200 bg-white/90 text-slate-800 shadow-[0_10px_24px_rgba(15,23,42,0.08)] hover:border-viro-200 hover:bg-viro-50 hover:text-viro-800`;
  const primaryActionClass =
    `${actionBaseClass} border-viro-500 bg-viro-500 text-white shadow-[0_14px_32px_rgba(45,163,100,0.26)] hover:border-viro-600 hover:bg-viro-600`;

  const buildPrefetchIntentProps = (path) => ({
    onMouseEnter: () => prefetchRouteModule(path),
    onFocus: () => prefetchRouteModule(path)
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
        <Link to="/signin" className={secondaryActionClass} {...buildPrefetchIntentProps("/signin")}>
          Sign in
        </Link>
        <Link to="/signup" className={primaryActionClass} {...buildPrefetchIntentProps("/signup")}>
          Create account
        </Link>
      </div>
    </header>
  );
}
