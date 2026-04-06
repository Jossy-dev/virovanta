import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { cleanupTestRoots, registerAndGetToken, setupTestApp, waitForJobCompletion } from "./helpers/testApp.js";

afterEach(async () => {
  await cleanupTestRoots();
});

describe("core workflow smoke coverage", () => {
  it("covers guest quick scan plus authenticated file, URL, website, history, analytics, and PDF report flows", async () => {
    const app = await setupTestApp();

    const guestQuickScan = await request(app)
      .post("/api/public/quick-scan")
      .attach("file", Buffer.from("guest smoke"), "guest-smoke.txt");

    expect(guestQuickScan.status).toBe(200);
    expect(guestQuickScan.body.report.verdict).toBe("clean");

    const session = await registerAndGetToken(app, "smoke@example.com", "StrongPass!123", "SmokeUser");

    const fileSubmit = await request(app)
      .post("/api/scans/jobs")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .attach("file", Buffer.from("file smoke"), "smoke-file.txt");

    expect(fileSubmit.status).toBe(202);

    const urlSubmit = await request(app)
      .post("/api/scans/links/jobs")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .send({
        message: `
          We need you to validate your account.
          Go to https://example.com/phish-check to review the request.
        `
      });

    expect(urlSubmit.status).toBe(202);

    const websiteSubmit = await request(app)
      .post("/api/scans/website/jobs")
      .set("Authorization", `Bearer ${session.accessToken}`)
      .send({ url: "https://example.com/security-posture" });

    expect(websiteSubmit.status).toBe(202);

    const fileJob = await waitForJobCompletion(app, session.accessToken, fileSubmit.body.job.id);
    const urlJob = await waitForJobCompletion(app, session.accessToken, urlSubmit.body.job.id);
    const websiteJob = await waitForJobCompletion(app, session.accessToken, websiteSubmit.body.job.id);

    expect(fileJob.status).toBe("completed");
    expect(urlJob.status).toBe("completed");
    expect(websiteJob.status).toBe("completed");

    const history = await request(app)
      .get("/api/scans/reports?limit=20")
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(history.status).toBe(200);
    expect(history.body.reports).toHaveLength(3);

    const sourceTypes = new Set(history.body.reports.map((report) => report.sourceType));
    expect(sourceTypes).toEqual(new Set(["file", "url", "website"]));

    const fileReport = await request(app)
      .get(`/api/scans/reports/${fileJob.reportId}`)
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(fileReport.status).toBe(200);
    expect(fileReport.body.report.file.originalName).toBe("smoke-file.txt");

    const websiteReport = await request(app)
      .get(`/api/scans/reports/${websiteJob.reportId}`)
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(websiteReport.status).toBe(200);
    expect(websiteReport.body.report.sourceType).toBe("website");
    expect(websiteReport.body.report.findings[0].title).toBe("Missing security headers");

    const pdf = await request(app)
      .get(`/api/scans/reports/${fileJob.reportId}/pdf`)
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(pdf.status).toBe(200);
    expect(pdf.headers["content-type"]).toContain("application/pdf");

    const analytics = await request(app)
      .get("/api/scans/analytics")
      .set("Authorization", `Bearer ${session.accessToken}`);

    expect(analytics.status).toBe(200);
    expect(analytics.body.analytics.summary.totalReports).toBe(3);
    expect(analytics.body.analytics.summary.cleanReports).toBe(3);
    expect(analytics.body.analytics.summary.suspiciousReports).toBe(0);
    expect(analytics.body.analytics.summary.maliciousReports).toBe(0);
  });
});
