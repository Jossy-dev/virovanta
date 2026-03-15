import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { getSeoForPath, getSitemapEntries, getStaticSeoRoutes } from "../src/seo/routeSeo.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const distDir = path.resolve(__dirname, "..", "dist");
const distIndexPath = path.join(distDir, "index.html");
const buildDate = new Date().toISOString().slice(0, 10);

function replaceTitle(html, title) {
  return html.replace(/<title>[\s\S]*?<\/title>/i, `<title>${title}</title>`);
}

function upsertMeta(html, attribute, key, content) {
  const pattern = new RegExp(`<meta[^>]+${attribute}=["']${key}["'][^>]*>`, "i");
  const tag = `<meta ${attribute}="${key}" content="${content}" />`;
  return pattern.test(html) ? html.replace(pattern, tag) : html.replace("</head>", `  ${tag}\n  </head>`);
}

function upsertLink(html, rel, href, options = {}) {
  const extra = options.hreflang ? ` hreflang="${options.hreflang}"` : "";
  const selector = options.hreflang
    ? new RegExp(`<link[^>]+rel=["']${rel}["'][^>]+hreflang=["']${options.hreflang}["'][^>]*>`, "i")
    : new RegExp(`<link[^>]+rel=["']${rel}["'][^>]*>`, "i");
  const tag = `<link rel="${rel}" href="${href}"${extra} />`;
  return selector.test(html) ? html.replace(selector, tag) : html.replace("</head>", `  ${tag}\n  </head>`);
}

function replaceStructuredData(html, graph) {
  const tag = `<script id="virovanta-structured-data" type="application/ld+json">${JSON.stringify(graph[0])}</script>`;
  const pattern = /<script id="virovanta-structured-data" type="application\/ld\+json">[\s\S]*?<\/script>/i;
  return pattern.test(html) ? html.replace(pattern, tag) : html.replace("</head>", `  ${tag}\n  </head>`);
}

function removeStructuredData(html) {
  return html.replace(/\s*<script id="virovanta-structured-data" type="application\/ld\+json">[\s\S]*?<\/script>/i, "");
}

function replaceRootSnapshot(html, snapshotHtml) {
  return html.replace(/<div id="root">[\s\S]*?<\/div>/i, `<div id="root">${snapshotHtml}</div>`);
}

function routeOutputPath(routePath) {
  if (routePath === "/") {
    return distIndexPath;
  }

  const relativePath = routePath.replace(/^\//, "");
  return path.join(distDir, relativePath, "index.html");
}

function applySeo(html, seo) {
  let next = html;
  next = replaceTitle(next, seo.title);
  next = upsertMeta(next, "name", "description", seo.description);
  next = upsertMeta(next, "name", "robots", seo.robots);
  next = upsertMeta(next, "name", "googlebot", seo.robots);
  next = upsertMeta(next, "name", "theme-color", "#1f8f5c");
  next = upsertMeta(next, "property", "og:type", seo.ogType);
  next = upsertMeta(next, "property", "og:site_name", "ViroVanta");
  next = upsertMeta(next, "property", "og:locale", seo.locale);
  next = upsertMeta(next, "property", "og:title", seo.title);
  next = upsertMeta(next, "property", "og:description", seo.description);
  next = upsertMeta(next, "property", "og:url", seo.canonicalUrl);
  next = upsertMeta(next, "property", "og:image", seo.imageUrl);
  next = upsertMeta(next, "property", "og:image:secure_url", seo.imageUrl);
  next = upsertMeta(next, "property", "og:image:width", "1200");
  next = upsertMeta(next, "property", "og:image:height", "630");
  next = upsertMeta(next, "property", "og:image:alt", seo.imageAlt);
  next = upsertMeta(next, "name", "twitter:card", "summary_large_image");
  next = upsertMeta(next, "name", "twitter:title", seo.title);
  next = upsertMeta(next, "name", "twitter:description", seo.description);
  next = upsertMeta(next, "name", "twitter:image", seo.imageUrl);
  next = upsertMeta(next, "name", "twitter:image:alt", seo.imageAlt);
  next = upsertLink(next, "canonical", seo.canonicalUrl);
  next = upsertLink(next, "alternate", seo.canonicalUrl, { hreflang: "en" });
  next = upsertLink(next, "alternate", seo.canonicalUrl, { hreflang: "x-default" });
  next = upsertLink(next, "icon", seo.faviconUrl);
  next = upsertLink(next, "apple-touch-icon", seo.logoUrl);
  next = replaceRootSnapshot(next, seo.snapshotHtml);

  if (seo.structuredDataGraph?.length) {
    next = replaceStructuredData(next, seo.structuredDataGraph);
  } else {
    next = removeStructuredData(next);
  }

  return next;
}

function buildSitemap(entries) {
  const urls = entries
    .map(
      (entry) => `  <url>\n    <loc>${entry.canonicalUrl}</loc>\n    <lastmod>${buildDate}</lastmod>\n  </url>`
    )
    .join("\n");

  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`;
}

function buildRobots() {
  return `User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: https://www.virovanta.com/sitemap.xml\n`;
}

async function main() {
  const baseHtml = await fs.readFile(distIndexPath, "utf8");
  const routes = getStaticSeoRoutes();

  for (const route of routes) {
    const outputPath = routeOutputPath(route.path);
    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await fs.writeFile(outputPath, applySeo(baseHtml, route), "utf8");
  }

  await fs.writeFile(path.join(distDir, "sitemap.xml"), buildSitemap(getSitemapEntries()), "utf8");
  await fs.writeFile(path.join(distDir, "robots.txt"), buildRobots(), "utf8");

  const fallbackSeo = getSeoForPath("/");
  await fs.writeFile(distIndexPath, applySeo(baseHtml, fallbackSeo), "utf8");
}

main().catch((error) => {
  console.error("SEO postbuild failed", error);
  process.exitCode = 1;
});
