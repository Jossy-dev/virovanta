export const DOCS_NAV_SECTIONS = Object.freeze([
  { id: "landing", label: "Landing" },
  { id: "quickstart", label: "Quickstart" },
  { id: "authentication", label: "Authentication" },
  { id: "api-reference", label: "API Reference" },
  { id: "errors", label: "Error Handling" },
  { id: "rate-limits", label: "Rate Limits" },
  { id: "sdks", label: "SDKs" },
  { id: "webhooks", label: "Webhooks" },
  { id: "try-it", label: "Try It" }
]);

export const DOCS_LANDING = Object.freeze({
  title: "ViroVanta API",
  tagline: "Scan files and suspicious links programmatically with scoped API keys.",
  value:
    "Queue file and URL scans, poll job status, retrieve risk reports, and automate security triage from your own application.",
  quickstartPath: "#quickstart",
  authSummary: "API requests are authenticated using a per-user API key sent in the x-api-key header."
});

export const DOCS_LANDING_SNIPPETS = Object.freeze({
  curl: `curl -X POST "<API_BASE_URL>/api/scans/links/jobs" \\
  -H "x-api-key: <API_KEY>" \\
  -H "Content-Type: application/json" \\
  -d '{"url":"https://example.com/login"}'`,
  javascript: `const response = await fetch("<API_BASE_URL>/api/scans/links/jobs", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "x-api-key": process.env.VIROVANTA_API_KEY
  },
  body: JSON.stringify({ url: "https://example.com/login" })
});

const data = await response.json();
console.log(data.job.id, data.job.status);`
});

export const DOCS_QUICKSTART_STEPS = Object.freeze([
  {
    title: "Create account and API key",
    detail:
      "Sign in to ViroVanta, open Settings, create an API key, and select only the scopes your integration needs."
  },
  {
    title: "Store your API key securely",
    detail:
      "Save keys in environment variables or a secret manager. Never hardcode keys in frontend bundles or repositories."
  },
  {
    title: "Make your first request",
    detail: "Submit a URL scan job, poll the job status endpoint, then fetch the final report when complete."
  }
]);

export const DOCS_QUICKSTART_SAMPLES = Object.freeze({
  curl: `curl -X GET "<API_BASE_URL>/api/scans/jobs?limit=10" \\
  -H "x-api-key: <API_KEY>"`,
  javascript: `import axios from "axios";

const client = axios.create({
  baseURL: process.env.VIROVANTA_API_BASE_URL,
  headers: { "x-api-key": process.env.VIROVANTA_API_KEY }
});

const jobs = await client.get("/api/scans/jobs", { params: { limit: 10 } });
console.log(jobs.data.jobs);`,
  python: `import os
import requests

base_url = os.getenv("VIROVANTA_API_BASE_URL")
api_key = os.getenv("VIROVANTA_API_KEY")

resp = requests.get(
    f"{base_url}/api/scans/jobs",
    headers={"x-api-key": api_key},
    params={"limit": 10},
    timeout=20,
)
resp.raise_for_status()
print(resp.json()["jobs"])`
});

export const DOCS_AUTH_TEXT = Object.freeze({
  headerName: "x-api-key",
  headerFormat: "x-api-key: <API_KEY>",
  notes: [
    "Generate keys in Settings and scope them to the minimum required permissions.",
    "Rotate keys regularly and revoke immediately if exposed.",
    "Send API requests from trusted backend services whenever possible.",
    "Use HTTPS only; never send API keys over insecure transport."
  ]
});

export const API_ENDPOINTS = Object.freeze([
  {
    id: "list-jobs",
    name: "List Jobs",
    method: "GET",
    path: "/api/scans/jobs",
    description: "Returns recent scan jobs for the authenticated user account.",
    authRequired: true,
    scopes: ["jobs:read"],
    pathParams: [],
    queryParams: [
      {
        name: "limit",
        type: "integer",
        required: false,
        description: "Number of jobs to return (1-100).",
        example: "20"
      }
    ],
    bodySchema: null,
    successExample: {
      jobs: [
        {
          id: "job_9f3de6a0",
          sourceType: "url",
          status: "completed",
          createdAt: "2026-03-16T18:02:13.411Z",
          startedAt: "2026-03-16T18:02:13.812Z",
          completedAt: "2026-03-16T18:02:15.071Z",
          originalName: "https://example.com/login",
          fileSize: 0,
          targetUrl: "https://example.com/login",
          reportId: "scan_a13fdf22",
          errorMessage: null
        }
      ]
    },
    errorExample: {
      error: {
        code: "AUTH_API_KEY_SCOPE_REQUIRED",
        message: "API key does not include required scope permissions.",
        details: {
          requiredScopes: ["jobs:read"],
          grantedScopes: ["reports:read"]
        }
      },
      requestId: "9d05fd59-4ea1-41d7-80b8-8aab6a56fb0e"
    },
    statusCodes: [
      { code: 200, meaning: "Jobs returned successfully." },
      { code: 401, meaning: "Missing or invalid API credentials." },
      { code: 403, meaning: "API key scope is insufficient." }
    ],
    codeSamples: {
      curl: `curl -X GET "<API_BASE_URL>/api/scans/jobs?limit=20" \\
  -H "x-api-key: <API_KEY>"`,
      javascript: `const res = await fetch("<API_BASE_URL>/api/scans/jobs?limit=20", {
  headers: { "x-api-key": process.env.VIROVANTA_API_KEY }
});
const data = await res.json();`,
      python: `import requests
res = requests.get(
    "<API_BASE_URL>/api/scans/jobs",
    params={"limit": 20},
    headers={"x-api-key": "<API_KEY>"},
    timeout=20
)
print(res.json())`
    },
    tryIt: {
      enabled: true,
      body: ""
    }
  },
  {
    id: "submit-url-job",
    name: "Create URL Scan Job",
    method: "POST",
    path: "/api/scans/links/jobs",
    description: "Queues a URL scan job and returns job metadata plus quota state.",
    authRequired: true,
    scopes: ["jobs:write"],
    pathParams: [],
    queryParams: [],
    bodySchema: {
      url: "string (required, http/https)"
    },
    successExample: {
      job: {
        id: "job_2ad6d7b4",
        sourceType: "url",
        status: "queued",
        createdAt: "2026-03-16T18:08:06.410Z",
        startedAt: null,
        completedAt: null,
        originalName: "https://example.com/reset",
        fileSize: 0,
        targetUrl: "https://example.com/reset",
        reportId: null,
        errorMessage: null
      },
      quota: {
        allowed: true,
        limit: 40,
        used: 7,
        remaining: 33,
        windowStartedAt: "2026-03-15T19:18:06.304Z"
      }
    },
    errorExample: {
      error: {
        code: "SCAN_QUOTA_EXCEEDED",
        message: "Daily scan quota exceeded for URL scans.",
        details: {
          allowed: false,
          limit: 40,
          used: 40,
          remaining: 0
        }
      },
      requestId: "9f0e83ed-ef0f-46f1-a191-51e3326d3409"
    },
    statusCodes: [
      { code: 202, meaning: "Job accepted and queued." },
      { code: 400, meaning: "Invalid URL payload." },
      { code: 429, meaning: "Quota or URL-scan rate limit exceeded." }
    ],
    codeSamples: {
      curl: `curl -X POST "<API_BASE_URL>/api/scans/links/jobs" \\
  -H "x-api-key: <API_KEY>" \\
  -H "Content-Type: application/json" \\
  -d '{"url":"https://example.com/reset"}'`,
      javascript: `const response = await fetch("<API_BASE_URL>/api/scans/links/jobs", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "x-api-key": process.env.VIROVANTA_API_KEY
  },
  body: JSON.stringify({ url: "https://example.com/reset" })
});

const payload = await response.json();`,
      python: `import requests
payload = {"url": "https://example.com/reset"}
res = requests.post(
    "<API_BASE_URL>/api/scans/links/jobs",
    headers={"x-api-key": "<API_KEY>"},
    json=payload,
    timeout=20
)
print(res.json())`
    },
    tryIt: {
      enabled: true,
      body: `{
  "url": "https://example.com/reset"
}`
    }
  },
  {
    id: "get-job",
    name: "Get Job By ID",
    method: "GET",
    path: "/api/scans/jobs/{jobId}",
    description: "Returns a single scan job and current processing state.",
    authRequired: true,
    scopes: ["jobs:read"],
    pathParams: [
      {
        name: "jobId",
        type: "string",
        required: true,
        description: "Scan job identifier returned when the job was created.",
        example: "job_2ad6d7b4"
      }
    ],
    queryParams: [],
    bodySchema: null,
    successExample: {
      job: {
        id: "job_2ad6d7b4",
        sourceType: "url",
        status: "completed",
        createdAt: "2026-03-16T18:08:06.410Z",
        startedAt: "2026-03-16T18:08:06.802Z",
        completedAt: "2026-03-16T18:08:08.310Z",
        originalName: "https://example.com/reset",
        fileSize: 0,
        targetUrl: "https://example.com/reset",
        reportId: "scan_ef92183c",
        errorMessage: null
      }
    },
    errorExample: {
      error: {
        code: "SCAN_JOB_NOT_FOUND",
        message: "Scan job not found.",
        details: null
      },
      requestId: "fe2ec718-a2a9-4586-ab59-8cf45a3ab437"
    },
    statusCodes: [
      { code: 200, meaning: "Job returned successfully." },
      { code: 404, meaning: "Job ID does not exist or is not visible to this user." }
    ],
    codeSamples: {
      curl: `curl -X GET "<API_BASE_URL>/api/scans/jobs/job_2ad6d7b4" \\
  -H "x-api-key: <API_KEY>"`,
      javascript: `const jobId = "job_2ad6d7b4";
const response = await fetch(\`<API_BASE_URL>/api/scans/jobs/\${jobId}\`, {
  headers: { "x-api-key": process.env.VIROVANTA_API_KEY }
});
const data = await response.json();`,
      python: `job_id = "job_2ad6d7b4"
res = requests.get(
    f"<API_BASE_URL>/api/scans/jobs/{job_id}",
    headers={"x-api-key": "<API_KEY>"},
    timeout=20
)
print(res.json())`
    },
    tryIt: {
      enabled: false,
      body: ""
    }
  },
  {
    id: "list-reports",
    name: "List Reports",
    method: "GET",
    path: "/api/scans/reports",
    description: "Returns report summaries for non-deleted reports owned by the user.",
    authRequired: true,
    scopes: ["reports:read"],
    pathParams: [],
    queryParams: [
      {
        name: "limit",
        type: "integer",
        required: false,
        description: "Number of reports to return (1-100).",
        example: "20"
      }
    ],
    bodySchema: null,
    successExample: {
      reports: [
        {
          id: "scan_ef92183c",
          sourceType: "url",
          createdAt: "2026-03-16T18:08:08.311Z",
          completedAt: "2026-03-16T18:08:08.311Z",
          verdict: "suspicious",
          riskScore: 58,
          fileName: "https://example.com/reset",
          fileSize: 0,
          findingCount: 4,
          topFinding: "Phishing-style language detected",
          intel: {
            hashSeenBefore: false,
            previousMatches: 0
          },
          iocCount: 3
        }
      ]
    },
    errorExample: {
      error: {
        code: "AUTH_API_KEY_SCOPE_REQUIRED",
        message: "API key does not include required scope permissions.",
        details: {
          requiredScopes: ["reports:read"],
          grantedScopes: ["jobs:read", "jobs:write"]
        }
      },
      requestId: "1ca916b8-c8e5-4362-a164-4ef6fdc1f8ea"
    },
    statusCodes: [
      { code: 200, meaning: "Reports returned successfully." },
      { code: 403, meaning: "API key lacks report read scope." }
    ],
    codeSamples: {
      curl: `curl -X GET "<API_BASE_URL>/api/scans/reports?limit=20" \\
  -H "x-api-key: <API_KEY>"`,
      javascript: `const res = await fetch("<API_BASE_URL>/api/scans/reports?limit=20", {
  headers: { "x-api-key": process.env.VIROVANTA_API_KEY }
});
const { reports } = await res.json();`,
      python: `res = requests.get(
    "<API_BASE_URL>/api/scans/reports",
    params={"limit": 20},
    headers={"x-api-key": "<API_KEY>"},
    timeout=20
)
print(res.json()["reports"])`
    },
    tryIt: {
      enabled: true,
      body: ""
    }
  },
  {
    id: "get-report",
    name: "Get Report By ID",
    method: "GET",
    path: "/api/scans/reports/{reportId}",
    description: "Returns the full report object with findings, engines, and recommendations.",
    authRequired: true,
    scopes: ["reports:read"],
    pathParams: [
      {
        name: "reportId",
        type: "string",
        required: true,
        description: "Report identifier from list reports/job completion.",
        example: "scan_ef92183c"
      }
    ],
    queryParams: [],
    bodySchema: null,
    successExample: {
      report: {
        id: "scan_ef92183c",
        verdict: "suspicious",
        riskScore: 58,
        findings: [
          {
            id: "url_phishing_language",
            severity: "medium",
            title: "Phishing-style language detected",
            description: "The page uses urgent account-verification language commonly seen in scam pages.",
            evidence: "Sign in to keep your account active"
          }
        ],
        recommendations: [
          "Do not submit credentials until domain ownership is validated.",
          "Cross-check URL reputation across internal and external intelligence feeds."
        ]
      }
    },
    errorExample: {
      error: {
        code: "SCAN_REPORT_NOT_FOUND",
        message: "Scan report not found.",
        details: null
      },
      requestId: "c44f4907-5baa-4a95-b8cb-0c8eb2f79576"
    },
    statusCodes: [
      { code: 200, meaning: "Report returned successfully." },
      { code: 404, meaning: "Report not found." }
    ],
    codeSamples: {
      curl: `curl -X GET "<API_BASE_URL>/api/scans/reports/scan_ef92183c" \\
  -H "x-api-key: <API_KEY>"`,
      javascript: `const reportId = "scan_ef92183c";
const response = await fetch(\`<API_BASE_URL>/api/scans/reports/\${reportId}\`, {
  headers: { "x-api-key": process.env.VIROVANTA_API_KEY }
});
const data = await response.json();`,
      python: `report_id = "scan_ef92183c"
res = requests.get(
    f"<API_BASE_URL>/api/scans/reports/{report_id}",
    headers={"x-api-key": "<API_KEY>"},
    timeout=20
)
print(res.json())`
    },
    tryIt: {
      enabled: false,
      body: ""
    }
  },
  {
    id: "create-share-link",
    name: "Create Report Share Link",
    method: "POST",
    path: "/api/scans/reports/{reportId}/share",
    description: "Generates a time-limited public report token and URL.",
    authRequired: true,
    scopes: ["reports:share"],
    pathParams: [
      {
        name: "reportId",
        type: "string",
        required: true,
        description: "Report identifier to share.",
        example: "scan_ef92183c"
      }
    ],
    queryParams: [],
    bodySchema: null,
    successExample: {
      shareToken: "eyJhbGciOi...",
      expiresAt: "2026-03-17T00:08:08.311Z",
      publicApiPath: "/api/public/shared-reports/eyJhbGciOi...",
      shareUrl: "https://www.virovanta.com/api/public/shared-reports/eyJhbGciOi..."
    },
    errorExample: {
      error: {
        code: "SCAN_REPORT_NOT_FOUND",
        message: "Scan report not found.",
        details: null
      },
      requestId: "f4024d0f-5c60-4d13-bbbd-832c27a3d84a"
    },
    statusCodes: [
      { code: 200, meaning: "Share link created." },
      { code: 403, meaning: "API key lacks reports:share scope." },
      { code: 404, meaning: "Report not found." }
    ],
    codeSamples: {
      curl: `curl -X POST "<API_BASE_URL>/api/scans/reports/scan_ef92183c/share" \\
  -H "x-api-key: <API_KEY>"`,
      javascript: `const reportId = "scan_ef92183c";
const res = await fetch(\`<API_BASE_URL>/api/scans/reports/\${reportId}/share\`, {
  method: "POST",
  headers: { "x-api-key": process.env.VIROVANTA_API_KEY }
});
console.log(await res.json());`,
      python: `report_id = "scan_ef92183c"
res = requests.post(
    f"<API_BASE_URL>/api/scans/reports/{report_id}/share",
    headers={"x-api-key": "<API_KEY>"},
    timeout=20
)
print(res.json())`
    },
    tryIt: {
      enabled: false,
      body: ""
    }
  },
  {
    id: "delete-report",
    name: "Delete Report",
    method: "DELETE",
    path: "/api/scans/reports/{reportId}",
    description: "Deletes a report from the user workspace.",
    authRequired: true,
    scopes: ["reports:delete"],
    pathParams: [
      {
        name: "reportId",
        type: "string",
        required: true,
        description: "Report identifier to delete.",
        example: "scan_ef92183c"
      }
    ],
    queryParams: [],
    bodySchema: null,
    successExample: {
      deleted: true,
      reportId: "scan_ef92183c",
      deletedAt: "2026-03-16T18:30:22.820Z",
      retentionExpiresAt: "2026-06-14T18:08:08.311Z",
      alreadyDeleted: false
    },
    errorExample: {
      error: {
        code: "SCAN_FORBIDDEN",
        message: "Forbidden.",
        details: null
      },
      requestId: "a9ff4bde-f0dd-4a9f-98ab-08322f6ed0c7"
    },
    statusCodes: [
      { code: 200, meaning: "Report deleted successfully." },
      { code: 403, meaning: "User is not allowed to delete this report." },
      { code: 404, meaning: "Report not found." }
    ],
    codeSamples: {
      curl: `curl -X DELETE "<API_BASE_URL>/api/scans/reports/scan_ef92183c" \\
  -H "x-api-key: <API_KEY>"`,
      javascript: `await fetch("<API_BASE_URL>/api/scans/reports/scan_ef92183c", {
  method: "DELETE",
  headers: { "x-api-key": process.env.VIROVANTA_API_KEY }
});`,
      python: `requests.delete(
    "<API_BASE_URL>/api/scans/reports/scan_ef92183c",
    headers={"x-api-key": "<API_KEY>"},
    timeout=20
)`
    },
    tryIt: {
      enabled: false,
      body: ""
    }
  },
  {
    id: "analytics",
    name: "Get Analytics Snapshot",
    method: "GET",
    path: "/api/scans/analytics",
    description: "Returns dashboard metrics for reports, verdict posture, queue state, and trend windows.",
    authRequired: true,
    scopes: ["analytics:read"],
    pathParams: [],
    queryParams: [],
    bodySchema: null,
    successExample: {
      analytics: {
        generatedAt: "2026-03-16T18:33:10.331Z",
        comparisonWindowDays: 30,
        summary: {
          totalJobs: 22,
          activeJobs: 2,
          totalReports: 17,
          suspiciousReports: 4,
          maliciousReports: 1,
          cleanReports: 12
        },
        postureBreakdown: [
          { label: "Clean", value: 12 },
          { label: "Suspicious", value: 4 },
          { label: "Malicious", value: 1 }
        ]
      }
    },
    errorExample: {
      error: {
        code: "AUTH_API_KEY_SCOPE_REQUIRED",
        message: "API key does not include required scope permissions.",
        details: {
          requiredScopes: ["analytics:read"],
          grantedScopes: ["jobs:read", "reports:read"]
        }
      },
      requestId: "de89a33d-c7a7-4cc6-b4d1-2f20b8d89f2d"
    },
    statusCodes: [
      { code: 200, meaning: "Analytics returned." },
      { code: 403, meaning: "API key lacks analytics:read scope." }
    ],
    codeSamples: {
      curl: `curl -X GET "<API_BASE_URL>/api/scans/analytics" \\
  -H "x-api-key: <API_KEY>"`,
      javascript: `const res = await fetch("<API_BASE_URL>/api/scans/analytics", {
  headers: { "x-api-key": process.env.VIROVANTA_API_KEY }
});
const data = await res.json();`,
      python: `res = requests.get(
    "<API_BASE_URL>/api/scans/analytics",
    headers={"x-api-key": "<API_KEY>"},
    timeout=20
)
print(res.json())`
    },
    tryIt: {
      enabled: true,
      body: ""
    }
  }
]);

export const DOCS_ERROR_FORMAT = Object.freeze({
  rawApiShape: {
    error: {
      code: "SCAN_QUOTA_EXCEEDED",
      message: "Daily scan quota exceeded for URL scans.",
      details: {
        limit: 40,
        used: 40,
        remaining: 0
      }
    },
    requestId: "8b257a65-f3f7-4d2c-8912-a6d261791f2d"
  },
  normalizedSdkShape: {
    error: {
      code: "SCAN_QUOTA_EXCEEDED",
      message: "Daily scan quota exceeded for URL scans.",
      type: "rate_limit_error"
    }
  }
});

export const DOCS_RATE_LIMITS = Object.freeze([
  {
    name: "Global API limit",
    value: "240 requests / 15 minutes (default)"
  },
  {
    name: "URL scan endpoint",
    value: "30 requests / 15 minutes per account (default)"
  },
  {
    name: "Public quick scan",
    value: "30 requests / 15 minutes per IP (default)"
  }
]);

export const DOCS_RATE_LIMIT_HEADERS = Object.freeze([
  { name: "RateLimit-Limit", description: "Request limit for the active window." },
  { name: "RateLimit-Remaining", description: "Remaining requests in the active window." },
  { name: "RateLimit-Reset", description: "Seconds until window reset." },
  { name: "RateLimit-Policy", description: "Window policy expression (e.g., 30;w=900)." }
]);

export const DOCS_RETRY_GUIDANCE = Object.freeze([
  "Retry only idempotent GET requests automatically.",
  "On 429, use exponential backoff with jitter (for example 1s, 2s, 4s, 8s).",
  "Use the reset header to schedule safe retry windows.",
  "Do not auto-retry 4xx validation/auth errors without request correction."
]);

export const DOCS_JS_SDK_SAMPLE = `export class ViroVantaClient {
  constructor({ baseUrl, apiKey }) {
    this.baseUrl = String(baseUrl || "").replace(/\\/+$/, "");
    this.apiKey = apiKey;
  }

  async request(path, { method = "GET", body } = {}) {
    const response = await fetch(\`\${this.baseUrl}\${path}\`, {
      method,
      headers: {
        "x-api-key": this.apiKey,
        ...(body ? { "Content-Type": "application/json" } : {})
      },
      ...(body ? { body: JSON.stringify(body) } : {})
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const type = response.status === 429 ? "rate_limit_error" : response.status >= 500 ? "server_error" : "request_error";
      throw {
        error: {
          code: payload?.error?.code || "UNKNOWN_ERROR",
          message: payload?.error?.message || "Request failed",
          type
        }
      };
    }

    return payload;
  }

  listJobs(limit = 20) {
    return this.request(\`/api/scans/jobs?limit=\${limit}\`);
  }

  submitUrlScan(url) {
    return this.request("/api/scans/links/jobs", {
      method: "POST",
      body: { url }
    });
  }

  getReport(reportId) {
    return this.request(\`/api/scans/reports/\${reportId}\`);
  }
}`;

export const DOCS_PYTHON_SDK_SAMPLE = `import requests


class ViroVantaClient:
    def __init__(self, base_url: str, api_key: str, timeout: int = 20):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"x-api-key": api_key})

    def request(self, method: str, path: str, json=None, params=None):
        response = self.session.request(
            method=method,
            url=f"{self.base_url}{path}",
            json=json,
            params=params,
            timeout=self.timeout,
        )
        payload = {}
        try:
            payload = response.json()
        except ValueError:
            payload = {}

        if not response.ok:
            if response.status_code == 429:
                error_type = "rate_limit_error"
            elif response.status_code >= 500:
                error_type = "server_error"
            else:
                error_type = "request_error"
            raise Exception(
                {
                    "error": {
                        "code": payload.get("error", {}).get("code", "UNKNOWN_ERROR"),
                        "message": payload.get("error", {}).get("message", "Request failed"),
                        "type": error_type,
                    }
                }
            )
        return payload

    def list_jobs(self, limit: int = 20):
        return self.request("GET", "/api/scans/jobs", params={"limit": limit})

    def submit_url_scan(self, url: str):
        return self.request("POST", "/api/scans/links/jobs", json={"url": url})

    def get_report(self, report_id: str):
        return self.request("GET", f"/api/scans/reports/{report_id}")
`;

export const DOCS_WEBHOOK = Object.freeze({
  availability:
    "Outbound webhooks are optional and can be enabled in integrations where asynchronous report-ready events are required.",
  signatureHeader: "x-virovanta-signature",
  signatureScheme: "HMAC-SHA256 over raw request body using your webhook signing secret.",
  eventExample: {
    id: "evt_019f112a",
    type: "report.ready",
    createdAt: "2026-03-16T18:40:02.318Z",
    data: {
      jobId: "job_2ad6d7b4",
      reportId: "scan_ef92183c",
      verdict: "suspicious",
      riskScore: 58
    }
  },
  verificationCode: `import crypto from "crypto";

function verifySignature(rawBody, signatureHeader, signingSecret) {
  const expected = crypto.createHmac("sha256", signingSecret).update(rawBody).digest("hex");
  const received = String(signatureHeader || "").replace(/^sha256=/i, "");
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(received));
}`
});

export const DOCS_TRY_IT_OPTIONS = Object.freeze(
  API_ENDPOINTS.filter((endpoint) => endpoint.tryIt?.enabled).map((endpoint) => ({
    id: endpoint.id,
    name: endpoint.name,
    method: endpoint.method,
    path: endpoint.path,
    defaultBody: endpoint.tryIt?.body || ""
  }))
);
