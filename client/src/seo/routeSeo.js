import { APP_NAME, APP_TAGLINE, SEO_SOCIAL_IMAGE_PATH, buildSiteUrl } from "../appConfig.js";
import { MARKETING_PAGES } from "../marketing/marketingContent.js";

const INDEX_ROBOTS = "index,follow,max-image-preview:large,max-snippet:-1,max-video-preview:-1";
const AUTH_ROBOTS = "noindex,follow,max-image-preview:large";
const PRIVATE_ROBOTS = "noindex,nofollow,noarchive";
const SITE_ROOT = buildSiteUrl("/");
const DEFAULT_IMAGE_URL = buildSiteUrl(SEO_SOCIAL_IMAGE_PATH);
const LOGO_URL = buildSiteUrl("/logo.png");
const FAVICON_URL = buildSiteUrl("/favicon-48x48.png");
const DEFAULT_LOCALE = "en_US";

function normalizePathname(pathname = "/") {
  const normalized = String(pathname || "/").trim();
  if (!normalized || normalized === "/") {
    return "/";
  }

  return normalized.replace(/\/+$/, "") || "/";
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function buildSnapshotLayout({ heading, description, body, actions = [] }) {
  const actionMarkup = actions.length
    ? `<nav class="seo-links">${actions
        .map((action) => `<a href="${escapeHtml(action.href)}">${escapeHtml(action.label)}</a>`)
        .join("")}</nav>`
    : "";

  return `<main class="seo-shell"><header class="seo-hero"><p class="seo-eyebrow">${escapeHtml(APP_TAGLINE)}</p><h1>${escapeHtml(
    heading
  )}</h1><p>${escapeHtml(description)}</p>${actionMarkup}</header>${body}</main>`;
}

function buildHomeSnapshot() {
  return buildSnapshotLayout({
    heading: `${APP_NAME} malware scanner for suspicious files`,
    description:
      "Upload suspicious files, email attachments, scripts, documents, or archives and get plain-language malware and anomaly reports with clear risk scores.",
    actions: [
      { href: "/features", label: "Explore features" },
      { href: "/how-it-works", label: "How it works" },
      { href: "/signup", label: "Create free account" },
      { href: "/signin", label: "Sign in" }
    ],
    body: `
      <section class="seo-section">
        <h2>What ${escapeHtml(APP_NAME)} does</h2>
        <p>${escapeHtml(
          `${APP_NAME} checks suspicious uploads for malware indicators, risky anomalies, and file defects, then returns clear verdicts and next-step guidance.`
        )}</p>
        <ul>
          <li>Guest quick scan for test uploads</li>
          <li>Plain-language findings and risk scoring</li>
          <li>Saved report history for signed-in users</li>
          <li>Batch upload support for operational workflows</li>
        </ul>
      </section>
      <section class="seo-section">
        <h2>How file scanning works</h2>
        <ol>
          <li>Upload a file or batch of files for analysis.</li>
          <li>Run layered checks for malware signals, suspicious behavior, and anomalies.</li>
          <li>Review a report with risk score, findings, hashes, and recommendations.</li>
        </ol>
      </section>
      <section class="seo-section">
        <h2>Who uses ${escapeHtml(APP_NAME)}</h2>
        <p>Security teams, office operators, support teams, and anyone who needs a fast way to inspect unknown files before they are opened inside the business.</p>
      </section>
    `
  });
}

function buildMarketingSnapshot(page) {
  const sectionsMarkup = page.sections
    .map((section) => {
      const itemsMarkup = section.items
        .map((item) => {
          const eyebrowMarkup = item.eyebrow ? `<p class="seo-eyebrow">${escapeHtml(item.eyebrow)}</p>` : "";
          return `<article class="seo-section"><div>${eyebrowMarkup}<h3>${escapeHtml(item.title)}</h3><p>${escapeHtml(
            item.description
          )}</p></div></article>`;
        })
        .join("");

      return `<section class="seo-section"><p class="seo-eyebrow">${escapeHtml(section.tag)}</p><h2>${escapeHtml(
        section.title
      )}</h2><div class="seo-grid">${itemsMarkup}</div></section>`;
    })
    .join("");

  return buildSnapshotLayout({
    heading: page.heroTitle,
    description: page.heroDescription,
    actions: [
      { href: page.cta.primary.path, label: page.cta.primary.label },
      { href: page.cta.secondary.path, label: page.cta.secondary.label }
    ],
    body: `
      <section class="seo-section">
        <h2>Key points</h2>
        <ul>
          ${page.heroPoints.map((point) => `<li>${escapeHtml(point)}</li>`).join("")}
        </ul>
      </section>
      ${sectionsMarkup}
      <section class="seo-section">
        <p class="seo-eyebrow">Next step</p>
        <h2>${escapeHtml(page.cta.title)}</h2>
        <p>${escapeHtml(page.cta.description)}</p>
      </section>
    `
  });
}

function buildAuthSnapshot({ heading, description, href, hrefLabel }) {
  return buildSnapshotLayout({
    heading,
    description,
    actions: href ? [{ href, label: hrefLabel }] : [],
    body: `
      <section class="seo-section">
        <h2>Workspace access</h2>
        <p>Use this page to continue into your ${escapeHtml(APP_NAME)} workspace. Auth pages are not intended to appear in search results.</p>
      </section>
    `
  });
}

function buildPrivateSnapshot({ heading, description }) {
  return buildSnapshotLayout({
    heading,
    description,
    actions: [{ href: "/signin", label: "Sign in" }],
    body: `
      <section class="seo-section">
        <h2>Secure workspace route</h2>
        <p>This route is part of the authenticated ${escapeHtml(APP_NAME)} application and requires an active account session.</p>
      </section>
    `
  });
}

function buildMarketingStructuredData(page) {
  const canonicalUrl = buildSiteUrl(page.path);

  return [
    {
      "@context": "https://schema.org",
      "@graph": [
        {
          "@type": "WebPage",
          "@id": `${canonicalUrl}#webpage`,
          url: canonicalUrl,
          name: page.seoTitle,
          description: page.seoDescription,
          isPartOf: {
            "@id": `${SITE_ROOT}#website`
          },
          about: {
            "@id": `${SITE_ROOT}#organization`
          }
        },
        {
          "@type": "BreadcrumbList",
          "@id": `${canonicalUrl}#breadcrumbs`,
          itemListElement: [
            {
              "@type": "ListItem",
              position: 1,
              name: APP_NAME,
              item: SITE_ROOT
            },
            {
              "@type": "ListItem",
              position: 2,
              name: page.navLabel,
              item: canonicalUrl
            }
          ]
        }
      ]
    }
  ];
}

const MARKETING_ROUTES = MARKETING_PAGES.map((page) => ({
  id: page.id,
  path: page.path,
  title: page.seoTitle,
  description: page.seoDescription,
  robots: INDEX_ROBOTS,
  indexable: true,
  staticRender: true,
  snapshotHtml: buildMarketingSnapshot(page),
  structuredData: () => buildMarketingStructuredData(page)
}));

const ROUTES = [
  {
    id: "home",
    path: "/",
    title: `${APP_NAME} | Malware Scanner for Suspicious Files`,
    description:
      "Upload suspicious files, email attachments, scripts, documents, or archives and get plain-language malware and anomaly reports with clear risk scores.",
    robots: INDEX_ROBOTS,
    indexable: true,
    staticRender: true,
    snapshotHtml: buildHomeSnapshot(),
    structuredData: ({ title, description }) => [
      {
        "@context": "https://schema.org",
        "@graph": [
          {
            "@type": "Organization",
            "@id": `${SITE_ROOT}#organization`,
            name: APP_NAME,
            url: SITE_ROOT,
            logo: {
              "@type": "ImageObject",
              url: LOGO_URL,
              width: 487,
              height: 454
            }
          },
          {
            "@type": "WebSite",
            "@id": `${SITE_ROOT}#website`,
            url: SITE_ROOT,
            name: APP_NAME,
            description,
            inLanguage: "en-US",
            publisher: {
              "@id": `${SITE_ROOT}#organization`
            }
          },
          {
            "@type": "SoftwareApplication",
            "@id": `${SITE_ROOT}#application`,
            name: APP_NAME,
            applicationCategory: "SecurityApplication",
            operatingSystem: "Web",
            url: SITE_ROOT,
            image: DEFAULT_IMAGE_URL,
            description,
            headline: title,
            offers: {
              "@type": "Offer",
              price: "0",
              priceCurrency: "USD"
            },
            publisher: {
              "@id": `${SITE_ROOT}#organization`
            }
          }
        ]
      }
    ]
  },
  ...MARKETING_ROUTES,
  {
    id: "status",
    path: "/status",
    title: `Status | ${APP_NAME}`,
    description: `View ${APP_NAME} service status, scan SLA targets, deterministic error behavior, and active scan limits.`,
    robots: INDEX_ROBOTS,
    indexable: true,
    staticRender: true,
    snapshotHtml: buildSnapshotLayout({
      heading: `${APP_NAME} service status`,
      description: "Live operational status, SLA commitments, limits, and retention behavior for scan workflows.",
      actions: [
        { href: "/", label: "Try guest scan" },
        { href: "/signup", label: "Create account" }
      ],
      body: `
      <section class="seo-section">
        <h2>Reliability commitments</h2>
        <ul>
          <li>Published scan SLA targets</li>
          <li>Deterministic API error codes</li>
          <li>Transparent usage limits and quotas</li>
        </ul>
      </section>
      <section class="seo-section">
        <h2>Privacy and retention</h2>
        <p>Reports remain private by default. Users can delete reports from workspace history at any time.</p>
      </section>
      `
    })
  },
  {
    id: "signin",
    path: "/signin",
    title: `Sign In | ${APP_NAME}`,
    description: `Sign in to ${APP_NAME} to manage scans, reports, notifications, and API keys.`,
    robots: AUTH_ROBOTS,
    indexable: false,
    staticRender: true,
    snapshotHtml: buildAuthSnapshot({
      heading: `Sign in to ${APP_NAME}`,
      description: `Use your ${APP_NAME} account to access saved reports, notifications, and dashboard workflows.`,
      href: "/signup",
      hrefLabel: "Create account"
    })
  },
  {
    id: "signup",
    path: "/signup",
    title: `Create Account | ${APP_NAME}`,
    description: `Create a ${APP_NAME} account to save reports, queue batch scans, and manage API keys.`,
    robots: AUTH_ROBOTS,
    indexable: false,
    staticRender: true,
    snapshotHtml: buildAuthSnapshot({
      heading: `Create a ${APP_NAME} account`,
      description: `Register for saved scan history, report sharing, notifications, and batch uploads.`,
      href: "/signin",
      hrefLabel: "Sign in"
    })
  },
  {
    id: "forgot-password",
    path: "/forgot-password",
    title: `Forgot Password | ${APP_NAME}`,
    description: `Request a secure password reset email for your ${APP_NAME} account.`,
    robots: AUTH_ROBOTS,
    indexable: false,
    staticRender: true,
    snapshotHtml: buildAuthSnapshot({
      heading: `Reset your ${APP_NAME} password`,
      description: `Request password reset instructions for your secure workspace account.`,
      href: "/signin",
      hrefLabel: "Back to sign in"
    })
  },
  {
    id: "reset-password",
    path: "/reset-password",
    title: `Reset Password | ${APP_NAME}`,
    description: `Set a new password for your ${APP_NAME} account.`,
    robots: AUTH_ROBOTS,
    indexable: false,
    staticRender: true,
    snapshotHtml: buildAuthSnapshot({
      heading: `Set a new ${APP_NAME} password`,
      description: `Use the secure reset link from your email to update your password.`,
      href: "/forgot-password",
      hrefLabel: "Request another reset"
    })
  },
  {
    id: "app-dashboard",
    path: "/app/dashboard",
    title: `Dashboard | ${APP_NAME}`,
    description: `Authenticated ${APP_NAME} workspace dashboard.`,
    robots: PRIVATE_ROBOTS,
    indexable: false,
    staticRender: true,
    snapshotHtml: buildPrivateSnapshot({
      heading: `${APP_NAME} dashboard`,
      description: "Review active jobs, quota usage, and recent scan activity after signing in."
    })
  },
  {
    id: "app-projects",
    path: "/app/projects",
    title: `Projects | ${APP_NAME}`,
    description: `Authenticated ${APP_NAME} scan intake and queue workspace.`,
    robots: PRIVATE_ROBOTS,
    indexable: false,
    staticRender: true,
    snapshotHtml: buildPrivateSnapshot({
      heading: `${APP_NAME} projects workspace`,
      description: "Queue one or more files for scanning after signing in."
    })
  },
  {
    id: "app-history",
    path: "/app/history",
    title: `History | ${APP_NAME}`,
    description: `Authenticated ${APP_NAME} report history.`,
    robots: PRIVATE_ROBOTS,
    indexable: false,
    staticRender: true,
    snapshotHtml: buildPrivateSnapshot({
      heading: `${APP_NAME} scan history`,
      description: "Review completed reports, findings, and share links after signing in."
    })
  },
  {
    id: "app-analytics",
    path: "/app/analytics",
    title: `Analytics | ${APP_NAME}`,
    description: `Authenticated ${APP_NAME} analytics workspace.`,
    robots: PRIVATE_ROBOTS,
    indexable: false,
    staticRender: true,
    snapshotHtml: buildPrivateSnapshot({
      heading: `${APP_NAME} analytics`,
      description: "Inspect verdict trends and workspace analytics after signing in."
    })
  },
  {
    id: "app-settings",
    path: "/app/settings",
    title: `Settings | ${APP_NAME}`,
    description: `Authenticated ${APP_NAME} settings and API key management.`,
    robots: PRIVATE_ROBOTS,
    indexable: false,
    staticRender: true,
    snapshotHtml: buildPrivateSnapshot({
      heading: `${APP_NAME} settings`,
      description: "Manage API keys and dashboard preferences after signing in."
    })
  },
  {
    id: "app-docs",
    path: "/app/docs",
    title: `Docs | ${APP_NAME}`,
    description: `Authenticated ${APP_NAME} API reference and integration guides.`,
    robots: PRIVATE_ROBOTS,
    indexable: false,
    staticRender: true,
    snapshotHtml: buildPrivateSnapshot({
      heading: `${APP_NAME} API docs`,
      description: "Read authentication, endpoints, and integration examples after signing in."
    })
  },
  {
    id: "report-base",
    path: "/report",
    title: `Shared Report | ${APP_NAME}`,
    description: `View a shared ${APP_NAME} malware and anomaly report link.`,
    robots: PRIVATE_ROBOTS,
    indexable: false,
    staticRender: true,
    snapshotHtml: buildPrivateSnapshot({
      heading: `${APP_NAME} shared report`,
      description: "Shared report links are generated per completed scan."
    })
  }
];

const FALLBACK_ROUTE = {
  id: "fallback",
  path: "/",
  title: `${APP_NAME} | Malware Scanner for Suspicious Files`,
  description:
    "Upload suspicious files, email attachments, scripts, documents, or archives and get plain-language malware and anomaly reports with clear risk scores.",
  robots: INDEX_ROBOTS,
  indexable: true,
  staticRender: false,
  snapshotHtml: buildHomeSnapshot()
};

function resolveDynamicRoute(pathname) {
  const normalizedPath = normalizePathname(pathname);

  if (/^\/report\/[^/]+$/i.test(normalizedPath)) {
    return {
      ...ROUTES.find((route) => route.id === "report-base"),
      path: normalizedPath,
      title: `Shared Threat Report | ${APP_NAME}`,
      description: `View a shared ${APP_NAME} report for a scanned file.`,
      robots: PRIVATE_ROBOTS,
      indexable: false,
      staticRender: false
    };
  }

  return null;
}

export function getSeoForPath(pathname = "/") {
  const normalizedPath = normalizePathname(pathname);
  const exactMatch = ROUTES.find((route) => route.path === normalizedPath);
  const route = exactMatch || resolveDynamicRoute(normalizedPath) || FALLBACK_ROUTE;
  const canonicalPath = route.path === "/" ? "/" : normalizedPath;

  return {
    ...route,
    canonicalUrl: buildSiteUrl(canonicalPath),
    locale: DEFAULT_LOCALE,
    ogType: "website",
    imageUrl: DEFAULT_IMAGE_URL,
    imageAlt: `${APP_NAME} branded malware scanning preview card`,
    faviconUrl: FAVICON_URL,
    logoUrl: LOGO_URL,
    structuredDataGraph: typeof route.structuredData === "function" ? route.structuredData(route) : []
  };
}

export function getStaticSeoRoutes() {
  return ROUTES.filter((route) => route.staticRender).map((route) => getSeoForPath(route.path));
}

export function getSitemapEntries() {
  return ROUTES.filter((route) => route.indexable).map((route) => getSeoForPath(route.path));
}

export function getRobotsContent(pathname = "/") {
  return getSeoForPath(pathname).robots;
}
