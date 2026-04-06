import fs from "fs/promises";
import os from "os";
import path from "path";
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { registerProductionClientRoutes } from "../src/app/registerProductionClientRoutes.js";

const tempRoots = [];

async function createTempDist() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "virovanta-client-dist-"));
  const distDir = path.join(root, "dist");
  tempRoots.push(root);

  await fs.mkdir(path.join(distDir, "features"), { recursive: true });
  await fs.mkdir(path.join(distDir, "assets"), { recursive: true });
  await fs.writeFile(path.join(distDir, "index.html"), "<html><body>app shell</body></html>");
  await fs.writeFile(path.join(distDir, "features", "index.html"), "<html><body>features page</body></html>");
  await fs.writeFile(path.join(distDir, "assets", "app.js"), "console.log('asset');");

  return distDir;
}

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => fs.rm(root, { recursive: true, force: true })));
});

describe("production client routes", () => {
  it("serves the SPA shell for dashboard refresh routes", async () => {
    const distDir = await createTempDist();
    const app = express();

    registerProductionClientRoutes(app, distDir);

    const response = await request(app).get("/app/website-safety");

    expect(response.status).toBe(200);
    expect(response.text).toContain("app shell");
  });

  it("keeps pre-rendered static pages and assets working", async () => {
    const distDir = await createTempDist();
    const app = express();

    registerProductionClientRoutes(app, distDir);

    const page = await request(app).get("/features/");
    const asset = await request(app).get("/assets/app.js");

    expect(page.status).toBe(200);
    expect(page.text).toContain("features page");
    expect(asset.status).toBe(200);
    expect(asset.text).toContain("asset");
  });

  it("does not rewrite missing asset-like paths into the SPA shell", async () => {
    const distDir = await createTempDist();
    const app = express();

    registerProductionClientRoutes(app, distDir);

    const response = await request(app).get("/assets/missing.js");

    expect(response.status).toBe(404);
    expect(response.text).not.toContain("app shell");
  });
});
