import { describe, expect, it } from "vitest";
import { getSeoForPath, getSitemapEntries, getStaticSeoRoutes } from "./routeSeo";

describe("routeSeo", () => {
  it("returns indexable metadata for the homepage", () => {
    const seo = getSeoForPath("/");

    expect(seo.title).toMatch(/Malware Scanner/i);
    expect(seo.robots).toMatch(/^index,follow/i);
    expect(seo.canonicalUrl).toBe("https://www.virovanta.com/");
    expect(seo.structuredDataGraph.length).toBeGreaterThan(0);
  });

  it("marks auth and app routes as noindex", () => {
    expect(getSeoForPath("/signin").robots).toMatch(/^noindex/i);
    expect(getSeoForPath("/app/dashboard").robots).toMatch(/^noindex/i);
    expect(getSeoForPath("/report/example-token").robots).toMatch(/^noindex/i);
  });

  it("keeps only indexable marketing routes in the sitemap and includes static route html targets", () => {
    const sitemapEntries = getSitemapEntries();
    const staticRoutes = getStaticSeoRoutes();

    expect(sitemapEntries.map((entry) => entry.path)).toEqual(
      expect.arrayContaining(["/", "/features", "/how-it-works", "/use-cases", "/security", "/pricing", "/about"])
    );
    expect(sitemapEntries).toHaveLength(7);
    expect(staticRoutes.some((route) => route.path === "/app/dashboard")).toBe(true);
    expect(staticRoutes.some((route) => route.path === "/signup")).toBe(true);
    expect(staticRoutes.some((route) => route.path === "/features")).toBe(true);
  });
});
