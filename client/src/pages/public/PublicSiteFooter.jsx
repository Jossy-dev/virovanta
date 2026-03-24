import { Link } from "react-router-dom";
import { MARKETING_FOOTER_GROUPS } from "../../marketing/marketingContent";
import { prefetchRouteModule } from "../../routeModules";

export default function PublicSiteFooter({ appName, appTagline, logoSrc, logoAltText }) {
  const footerButtonBaseClass =
    "inline-flex min-h-10 touch-manipulation select-none items-center justify-center rounded-full border px-4 text-sm font-semibold transition duration-150 ease-out active:scale-[0.985]";
  const footerPrimaryButtonClass =
    `${footerButtonBaseClass} border-viro-500 bg-viro-500 text-white shadow-[0_16px_34px_rgba(45,163,100,0.22)] hover:border-viro-600 hover:bg-viro-600`;
  const footerSecondaryButtonClass =
    `${footerButtonBaseClass} border-emerald-100/20 bg-white/[0.04] text-emerald-50 hover:border-emerald-100/35 hover:bg-white/[0.08]`;
  const buildPrefetchIntentProps = (path) => ({
    onMouseEnter: () => prefetchRouteModule(path),
    onFocus: () => prefetchRouteModule(path)
  });

  return (
    <footer className="public-site-footer">
      <div className="public-site-footer-main">
        <div className="public-site-footer-brand">
          <Link className="public-site-brand" to="/" {...buildPrefetchIntentProps("/")}>
            <img src={logoSrc} alt={logoAltText} className="public-site-logo" />
            <span className="public-site-brand-copy">
              <strong>{appName}</strong>
              <small>{appTagline}</small>
            </span>
          </Link>
          <p className="public-site-footer-copy">
            Plain-language malware and anomaly scanning for suspicious files, attachments, and downloaded artifacts.
          </p>
          <div className="public-site-footer-actions">
            <Link to="/" className={footerSecondaryButtonClass} {...buildPrefetchIntentProps("/")}>
              Try guest scan
            </Link>
            <Link to="/signup" className={footerPrimaryButtonClass} {...buildPrefetchIntentProps("/signup")}>
              Create account
            </Link>
          </div>
        </div>

        <div className="public-site-footer-links">
          {MARKETING_FOOTER_GROUPS.map((group) => (
            <div key={group.title} className="public-site-footer-group">
              <h2>{group.title}</h2>
              <div className="public-site-footer-list">
                {group.links.map((item) => (
                  <Link
                    key={item.path}
                    to={item.path}
                    className="public-site-footer-link"
                    {...buildPrefetchIntentProps(item.path)}
                  >
                    {item.label}
                  </Link>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="public-site-footer-bar">
        <span>&copy; {new Date().getFullYear()} {appName}</span>
        <span>Built for secure file review workflows.</span>
      </div>
    </footer>
  );
}
