import { motion, useReducedMotion } from "framer-motion";
import { Link, Navigate } from "react-router-dom";
import { getMarketingPageByPath } from "../marketing/marketingContent";
import { motionPreset } from "../appUtils";
import PublicSiteFooter from "./public/PublicSiteFooter";
import PublicSiteHeader from "./public/PublicSiteHeader";
import { prefetchRouteModule } from "../routeModules";
import { createInteractiveMotion } from "../ui/motionSystem";

function renderSection(section) {
  if (section.layout === "steps") {
    return (
      <div className="marketing-steps">
        {section.items.map((item) => (
          <article key={`${section.title}-${item.title}`} className="marketing-card marketing-step-card">
            <span className="marketing-step-index">{item.eyebrow}</span>
            <h3>{item.title}</h3>
            <p>{item.description}</p>
          </article>
        ))}
      </div>
    );
  }

  if (section.layout === "list") {
    return (
      <div className="marketing-list-grid">
        {section.items.map((item) => (
          <article key={`${section.title}-${item.title}`} className="marketing-list-item">
            <div className="marketing-list-marker" aria-hidden="true" />
            <div className="marketing-list-copy">
              <h3>{item.title}</h3>
              <p>{item.description}</p>
            </div>
          </article>
        ))}
      </div>
    );
  }

  return (
    <div className="marketing-card-grid">
      {section.items.map((item) => (
        <article key={`${section.title}-${item.title}`} className="marketing-card">
          <h3>{item.title}</h3>
          <p>{item.description}</p>
        </article>
      ))}
    </div>
  );
}

export default function MarketingPage({ appName, appTagline, logoAltText, brandMarks, routePath }) {
  const prefersReducedMotion = useReducedMotion();
  const page = getMarketingPageByPath(routePath);
  const MotionLink = motion(Link);
  const interactiveMotion = createInteractiveMotion(prefersReducedMotion, {
    hoverScale: 1.012,
    tapScale: 0.985
  });

  const buildPrefetchIntentProps = (path) => ({
    onMouseEnter: () => prefetchRouteModule(path),
    onFocus: () => prefetchRouteModule(path),
    onTouchStart: () => prefetchRouteModule(path)
  });

  if (!page) {
    return <Navigate to="/" replace />;
  }

  return (
    <motion.main className="app-shell marketing-shell" {...motionPreset(prefersReducedMotion)}>
      <motion.section className="card marketing-hero" {...motionPreset(prefersReducedMotion, 0.03)}>
        <div className="marketing-grid-bg" aria-hidden="true" />
        <div className="marketing-hero-inner">
          <PublicSiteHeader
            appName={appName}
            appTagline={appTagline}
            logoSrc={brandMarks.lightSurface}
            logoAltText={logoAltText}
          />

          <div className="marketing-hero-copy">
            <p className="eyebrow">{page.eyebrow}</p>
            <h1>{page.heroTitle}</h1>
            <p className="subtext">{page.heroDescription}</p>
          </div>

          <div className="marketing-hero-actions">
            <MotionLink
              to={page.cta.primary.path}
              className="primary"
              {...buildPrefetchIntentProps(page.cta.primary.path)}
              {...interactiveMotion}
            >
              {page.cta.primary.label}
            </MotionLink>
            <MotionLink
              to={page.cta.secondary.path}
              className="ghost"
              {...buildPrefetchIntentProps(page.cta.secondary.path)}
              {...interactiveMotion}
            >
              {page.cta.secondary.label}
            </MotionLink>
          </div>

          <div className="marketing-hero-points">
            {page.heroPoints.map((point) => (
              <div key={point} className="marketing-inline-pill">
                {point}
              </div>
            ))}
          </div>
        </div>
      </motion.section>

      {page.sections.map((section, index) => (
        <motion.section
          key={section.title}
          className="card marketing-section"
          {...motionPreset(prefersReducedMotion, 0.05 + index * 0.03)}
        >
          <div className="section-head">
            <h2>{section.title}</h2>
            <span className="panel-tag">{section.tag}</span>
          </div>
          {renderSection(section)}
        </motion.section>
      ))}

      <motion.section className="card marketing-cta-card" {...motionPreset(prefersReducedMotion, 0.16)}>
        <div className="marketing-cta-copy">
          <p className="eyebrow">Next step</p>
          <h2>{page.cta.title}</h2>
          <p className="subtext">{page.cta.description}</p>
        </div>
        <div className="marketing-cta-actions">
          <MotionLink
            to={page.cta.primary.path}
            className="primary"
            {...buildPrefetchIntentProps(page.cta.primary.path)}
            {...interactiveMotion}
          >
            {page.cta.primary.label}
          </MotionLink>
          <MotionLink
            to={page.cta.secondary.path}
            className="ghost"
            {...buildPrefetchIntentProps(page.cta.secondary.path)}
            {...interactiveMotion}
          >
            {page.cta.secondary.label}
          </MotionLink>
        </div>
      </motion.section>

      <motion.div className="marketing-footer-wrap" {...motionPreset(prefersReducedMotion, 0.18)}>
        <PublicSiteFooter
          appName={appName}
          appTagline={appTagline}
          logoSrc={brandMarks.lightSurface}
          logoAltText={logoAltText}
        />
      </motion.div>
    </motion.main>
  );
}
