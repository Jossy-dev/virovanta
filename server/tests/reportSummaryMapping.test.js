import { describe, expect, it } from "vitest";
import { PersistentStore } from "../src/store/persistentStore.js";

describe("report summary mapping", () => {
  it("hydrates top-level fileName from the Postgres row when the payload only has nested file data", async () => {
    const store = new PersistentStore({
      filePath: "/tmp/virovanta-report-summary-mapping.json",
      reportTtlMs: 60_000,
      maxReports: 100,
      driver: "postgres"
    });

    store.pool = {
      async query() {
        return {
          rowCount: 1,
          rows: [
            {
              id: "report_1",
              owner_user_id: "user_1",
              source_type: "file",
              queued_job_id: "job_1",
              created_at: "2026-06-16T10:00:00.000Z",
              completed_at: "2026-06-16T10:01:00.000Z",
              verdict: "suspicious",
              risk_score: 71,
              file_name: "invoice-review.pdf",
              file_size: 24576,
              deleted_at: null,
              deleted_by_user_id: null,
              payload: {
                id: "report_1",
                sourceType: "file",
                verdict: "suspicious",
                riskScore: 71,
                file: {
                  originalName: "invoice-review.pdf",
                  size: 24576
                }
              }
            }
          ]
        };
      }
    };

    const reports = await store.listReportsForUser({ id: "user_1", role: "user" }, 20);

    expect(reports).toHaveLength(1);
    expect(reports[0].fileName).toBe("invoice-review.pdf");
    expect(reports[0].fileSize).toBe(24576);
    expect(reports[0].createdAt).toBe("2026-06-16T10:00:00.000Z");
    expect(reports[0].completedAt).toBe("2026-06-16T10:01:00.000Z");
  });

  it("falls back to nested URL fields when the stored payload has no top-level summary name", async () => {
    const store = new PersistentStore({
      filePath: "/tmp/virovanta-report-summary-mapping-url.json",
      reportTtlMs: 60_000,
      maxReports: 100,
      driver: "postgres"
    });

    store.pool = {
      async query() {
        return {
          rowCount: 1,
          rows: [
            {
              id: "report_2",
              owner_user_id: "user_1",
              source_type: "website",
              queued_job_id: "job_2",
              created_at: "2026-06-16T12:00:00.000Z",
              completed_at: "2026-06-16T12:02:00.000Z",
              verdict: "clean",
              risk_score: 18,
              file_name: "",
              file_size: 0,
              deleted_at: null,
              deleted_by_user_id: null,
              payload: {
                id: "report_2",
                sourceType: "website",
                url: {
                  final: "https://docs.djangoproject.com/en/4.1/"
                }
              }
            }
          ]
        };
      }
    };

    const reports = await store.listReportsForUser({ id: "user_1", role: "user" }, 20);

    expect(reports).toHaveLength(1);
    expect(reports[0].fileName).toBe("https://docs.djangoproject.com/en/4.1/");
    expect(reports[0].sourceType).toBe("website");
  });
});
