export const MARKETING_NAV_ITEMS = Object.freeze([
  { path: "/features", label: "Features" },
  { path: "/how-it-works", label: "How it works" },
  { path: "/use-cases", label: "Use cases" },
  { path: "/security", label: "Security" },
  { path: "/pricing", label: "Pricing" },
  { path: "/about", label: "About" }
]);

export const MARKETING_FOOTER_GROUPS = Object.freeze([
  {
    title: "Explore",
    links: [
      { path: "/features", label: "Features" },
      { path: "/how-it-works", label: "How it works" },
      { path: "/use-cases", label: "Use cases" }
    ]
  },
  {
    title: "Company",
    links: [
      { path: "/security", label: "Security" },
      { path: "/pricing", label: "Pricing" },
      { path: "/about", label: "About" }
    ]
  },
  {
    title: "Access",
    links: [
      { path: "/", label: "Quick guest scan" },
      { path: "/signin", label: "Sign in" },
      { path: "/signup", label: "Create account" }
    ]
  }
]);

export const MARKETING_PAGES = Object.freeze([
  {
    id: "features",
    path: "/features",
    navLabel: "Features",
    eyebrow: "Platform capabilities",
    heroTitle: "Features built for practical file triage",
    heroDescription:
      "ViroVanta gives teams a fast path from suspicious file upload to a plain-language decision. The focus is operational clarity, not noisy dashboards.",
    heroPoints: [
      "Guest quick scan for evaluation and demos",
      "Batch intake and saved history for signed-in users",
      "Shareable reports, API keys, notifications, and analytics"
    ],
    seoTitle: "Features | ViroVanta",
    seoDescription:
      "Explore ViroVanta features for malware and anomaly scanning, including guest scans, batch uploads, saved reports, analytics, notifications, and API access.",
    sections: [
      {
        title: "File intake and analysis",
        tag: "Core workflow",
        layout: "grid",
        items: [
          {
            title: "Quick guest scan",
            description: "Drop a file, run a rapid scan, and review a temporary result without creating an account."
          },
          {
            title: "Batch upload workspace",
            description: "Signed-in users can queue multiple files at once and manage processing from the project workspace."
          },
          {
            title: "Layered findings",
            description: "Reports combine verdicts, risk scores, file traits, and plain-language findings so non-specialists can act faster."
          }
        ]
      },
      {
        title: "Operational controls",
        tag: "Built for repeat use",
        layout: "grid",
        items: [
          {
            title: "Saved report history",
            description: "Keep a searchable record of completed scans instead of treating every upload as a one-off event."
          },
          {
            title: "Shareable report links",
            description: "Generate controlled links when a report needs to move across a review chain."
          },
          {
            title: "API keys and notifications",
            description: "Support automation access while surfacing events like completed scans, key changes, and quota warnings."
          }
        ]
      },
      {
        title: "What the team sees",
        tag: "Decision-ready output",
        layout: "list",
        items: [
          {
            title: "Risk scoring with verdict context",
            description: "Scores are paired with clean, suspicious, or malicious verdict labels so the result is easier to interpret."
          },
          {
            title: "Readable findings",
            description: "Technical signals are translated into everyday language where possible so office teams are not left guessing."
          },
          {
            title: "History and analytics",
            description: "The workspace tracks completed jobs, verdict distribution, queue health, and report activity over time."
          }
        ]
      }
    ],
    cta: {
      title: "Start with a real file workflow",
      description: "Use the guest scanner for a quick evaluation or create an account to save reports and queue multi-file jobs.",
      primary: { path: "/signup", label: "Create free account" },
      secondary: { path: "/", label: "Try guest scan" }
    }
  },
  {
    id: "how-it-works",
    path: "/how-it-works",
    navLabel: "How it works",
    eyebrow: "From upload to report",
    heroTitle: "A simple workflow for suspicious files",
    heroDescription:
      "The product flow is designed so teams can move from intake to decision without losing track of what was uploaded, what was found, and what happened next.",
    heroPoints: [
      "Upload one file or a signed-in batch",
      "Process scans through the queue and worker pipeline",
      "Review reports, history, and share links in one workspace"
    ],
    seoTitle: "How It Works | ViroVanta",
    seoDescription:
      "Learn how ViroVanta handles suspicious file intake, analysis, reporting, and workspace review for malware and anomaly detection.",
    sections: [
      {
        title: "The flow",
        tag: "Three stages",
        layout: "steps",
        items: [
          {
            eyebrow: "01",
            title: "Upload and queue",
            description: "Start with a guest scan for quick testing or sign in to queue one or many files for tracked processing."
          },
          {
            eyebrow: "02",
            title: "Analyze and classify",
            description: "The scan pipeline inspects file structure, type cues, entropy, indicators, and verdict conditions."
          },
          {
            eyebrow: "03",
            title: "Review and respond",
            description: "Use the report, history page, notifications, and analytics to decide what to block, share, or investigate further."
          }
        ]
      },
      {
        title: "Outputs users receive",
        tag: "What is returned",
        layout: "grid",
        items: [
          {
            title: "Verdict and risk score",
            description: "Each report returns a verdict with scoring that helps distinguish low-risk files from urgent items."
          },
          {
            title: "File metadata",
            description: "The report includes hashes, type hints, size, and other context that helps validate what was uploaded."
          },
          {
            title: "Recommended next steps",
            description: "Findings are paired with actionable guidance so the report is useful outside a security specialist workflow."
          }
        ]
      },
      {
        title: "Workspace follow-through",
        tag: "After the scan",
        layout: "list",
        items: [
          {
            title: "Queue visibility",
            description: "Users can track queued, processing, completed, and failed jobs instead of waiting in a blind upload flow."
          },
          {
            title: "History retention",
            description: "Completed reports remain available inside the account history window for later review and sharing."
          },
          {
            title: "Notification trail",
            description: "Report-ready and usage events surface in the dashboard so the workflow stays visible."
          }
        ]
      }
    ],
    cta: {
      title: "See the process on a live upload",
      description: "Run a guest scan or open the workspace to watch queued jobs move through the pipeline.",
      primary: { path: "/", label: "Run guest scan" },
      secondary: { path: "/signup", label: "Create account" }
    }
  },
  {
    id: "use-cases",
    path: "/use-cases",
    navLabel: "Use cases",
    eyebrow: "Who it is for",
    heroTitle: "Use cases that start with unknown files",
    heroDescription:
      "ViroVanta is built for teams that need a safer, faster decision on uploads, attachments, downloads, and handoffs before those files move deeper into the business.",
    heroPoints: [
      "Office and operations teams reviewing unknown attachments",
      "Security teams triaging suspicious files without heavy tooling",
      "Shared-service teams that need reports they can forward"
    ],
    seoTitle: "Use Cases | ViroVanta",
    seoDescription:
      "Review ViroVanta use cases for office operations, SOC triage, help desks, and teams that inspect suspicious files before opening them.",
    sections: [
      {
        title: "Common teams",
        tag: "Daily workflows",
        layout: "grid",
        items: [
          {
            title: "Office operations",
            description: "Check emailed documents, shared downloads, and unexpected attachments before they are opened on employee devices."
          },
          {
            title: "SOC and security review",
            description: "Triage inbound files, collect quick verdicts, and route high-risk items for deeper investigation."
          },
          {
            title: "IT and help desk",
            description: "Validate user-submitted files, installers, or macros before they move into a support workflow."
          }
        ]
      },
      {
        title: "Where the product helps most",
        tag: "Decision moments",
        layout: "list",
        items: [
          {
            title: "Before a user opens a file",
            description: "Use the scanner as an early gate instead of reacting after execution or document preview."
          },
          {
            title: "When a report must be shared",
            description: "Pass a report link to a reviewer, manager, or downstream analyst instead of copying fragments into chat."
          },
          {
            title: "When multiple files arrive together",
            description: "Queue a batch from one workspace instead of repeating a single-file process over and over."
          }
        ]
      },
      {
        title: "Examples of files teams check",
        tag: "Typical intake",
        layout: "grid",
        items: [
          {
            title: "Attachments and documents",
            description: "Invoices, resumes, spreadsheets, PDFs, and archive files sent through email or support channels."
          },
          {
            title: "Scripts and executables",
            description: "Installers, scripts, or binaries that need a first-pass safety review before internal use."
          },
          {
            title: "Downloaded artifacts",
            description: "Files pulled from external portals, vendor links, or cloud shares that need validation before opening."
          }
        ]
      }
    ],
    cta: {
      title: "Match the scanner to your workflow",
      description: "Evaluate the guest flow first, then move repeat file intake into the authenticated workspace.",
      primary: { path: "/", label: "Evaluate with guest scan" },
      secondary: { path: "/features", label: "See platform features" }
    }
  },
  {
    id: "security",
    path: "/security",
    navLabel: "Security",
    eyebrow: "Trust and controls",
    heroTitle: "Security controls built into the product flow",
    heroDescription:
      "ViroVanta is not positioned as a marketing shell over open file upload. The workspace is designed around authenticated access, ownership-scoped data, and controlled processing paths.",
    heroPoints: [
      "Authenticated routes are tied to the signed-in account",
      "Sensitive API responses are marked no-store",
      "Operational actions are separated from guest access"
    ],
    seoTitle: "Security | ViroVanta",
    seoDescription:
      "Review the ViroVanta security model for authenticated access, ownership-scoped data retrieval, protected API routes, and secure processing workflows.",
    sections: [
      {
        title: "Access controls",
        tag: "Identity first",
        layout: "grid",
        items: [
          {
            title: "Authenticated account routes",
            description: "Report history, notifications, API key management, analytics, and workspace actions require authenticated access."
          },
          {
            title: "Ownership-scoped data",
            description: "User-facing report and analytics retrieval is tied to the authenticated account rather than broad shared access."
          },
          {
            title: "Admin route separation",
            description: "Administrative actions are separated from standard user flows and require elevated authorization."
          }
        ]
      },
      {
        title: "API protections",
        tag: "Request handling",
        layout: "list",
        items: [
          {
            title: "Rate-limited auth and lookup routes",
            description: "Authentication and account-adjacent endpoints use dedicated rate limits to reduce abuse pressure."
          },
          {
            title: "Sensitive response caching disabled",
            description: "Authenticated and security-sensitive responses are marked to avoid unintended browser or proxy retention."
          },
          {
            title: "Bearer-only interactive account actions",
            description: "Interactive account operations such as notifications and API key management are restricted to bearer-authenticated sessions."
          }
        ]
      },
      {
        title: "Operational security direction",
        tag: "Scaling posture",
        layout: "grid",
        items: [
          {
            title: "Background queue processing",
            description: "Queued scan execution keeps uploads and processing decoupled so workloads can be handled more safely under load."
          },
          {
            title: "Persistent report records",
            description: "User history and analytics are stored persistently so decision records are tied back to the account that initiated them."
          },
          {
            title: "Storage and worker isolation roadmap",
            description: "The platform is structured to keep improving storage, worker isolation, and scanning boundaries as the service scales."
          }
        ]
      }
    ],
    cta: {
      title: "Review the product in a real secure flow",
      description: "Use the public scan for evaluation or open an account to see how reports, notifications, and ownership controls behave together.",
      primary: { path: "/signup", label: "Create account" },
      secondary: { path: "/", label: "Run guest scan" }
    }
  },
  {
    id: "pricing",
    path: "/pricing",
    navLabel: "Pricing",
    eyebrow: "Current access model",
    heroTitle: "Free access while the platform is still expanding",
    heroDescription:
      "ViroVanta is currently available without billing logic enabled. The public surface is open for evaluation, and workspace accounts are available for saved reports and deeper workflows.",
    heroPoints: [
      "Guest scan for quick evaluation",
      "Free account workflow for saved history and queue access",
      "Commercial packaging can be added later without reworking the product core"
    ],
    seoTitle: "Pricing | ViroVanta",
    seoDescription:
      "See the current ViroVanta pricing model: free guest scans and free accounts while the malware and anomaly scanning platform continues to expand.",
    sections: [
      {
        title: "Current tiers",
        tag: "What is available now",
        layout: "grid",
        items: [
          {
            title: "Guest evaluation",
            description: "Run a limited quick scan without creating an account. Best for testing speed and report clarity."
          },
          {
            title: "Free workspace account",
            description: "Create an account to save report history, access the queue, generate API keys, and view analytics."
          },
          {
            title: "Future commercial rollout",
            description: "The product is structured so billing and paid packaging can be introduced later without rebuilding the platform."
          }
        ]
      },
      {
        title: "What teams are evaluating",
        tag: "Value during free access",
        layout: "list",
        items: [
          {
            title: "Report quality",
            description: "How clearly the product explains verdicts and findings to technical and non-technical users."
          },
          {
            title: "Workflow fit",
            description: "Whether the queue, history, sharing, notifications, and analytics match day-to-day file review work."
          },
          {
            title: "Operational readiness",
            description: "Whether the service shape is strong enough to support future team, automation, and paid-service expansion."
          }
        ]
      }
    ],
    cta: {
      title: "Use the free access window well",
      description: "Test the guest flow, create a workspace account, and validate whether the product fits your review pipeline before pricing expands.",
      primary: { path: "/signup", label: "Create free account" },
      secondary: { path: "/", label: "Try guest scan" }
    }
  },
  {
    id: "about",
    path: "/about",
    navLabel: "About",
    eyebrow: "Product direction",
    heroTitle: "Why ViroVanta exists",
    heroDescription:
      "The goal is straightforward: make suspicious-file review faster, clearer, and more operationally useful for real teams instead of burying users in noise or jargon.",
    heroPoints: [
      "Designed for teams that need decisions, not generic dashboards",
      "Built to serve both security specialists and office operators",
      "Structured to scale into a stronger paid product over time"
    ],
    seoTitle: "About | ViroVanta",
    seoDescription:
      "Learn about ViroVanta, the product mission behind fast malware and anomaly scanning for suspicious files, and the principles guiding the platform.",
    sections: [
      {
        title: "Principles",
        tag: "How the product is shaped",
        layout: "grid",
        items: [
          {
            title: "Clarity over jargon",
            description: "Reports should be usable by people who are not deep malware analysts without hiding the important details."
          },
          {
            title: "Operational usefulness",
            description: "Features should support queueing, review, history, sharing, and automation instead of existing as disconnected demos."
          },
          {
            title: "Scalable foundation",
            description: "The product structure is being hardened so storage, queueing, auth, and reporting can support broader deployment."
          }
        ]
      },
      {
        title: "Who the product serves",
        tag: "Primary audience",
        layout: "list",
        items: [
          {
            title: "Security teams",
            description: "Teams that need a quick first-pass verdict and a report they can escalate or share."
          },
          {
            title: "Office and operations teams",
            description: "Teams that receive unknown files and need help deciding whether to trust, quarantine, or forward them."
          },
          {
            title: "Growing digital businesses",
            description: "Organizations that want a modern file-scanning workflow they can expand into automation and paid tiers later."
          }
        ]
      }
    ],
    cta: {
      title: "Use the product the way it is meant to be judged",
      description: "Run real uploads, review the report quality, and decide whether the workflow is strong enough for your team.",
      primary: { path: "/", label: "Run guest scan" },
      secondary: { path: "/pricing", label: "See current access" }
    }
  }
]);

export function getMarketingPageByPath(pathname = "/") {
  return MARKETING_PAGES.find((page) => page.path === pathname) || null;
}

export function getMarketingPageById(id = "") {
  return MARKETING_PAGES.find((page) => page.id === id) || null;
}
