const DEFAULT_TRIAL_PLAN_ID = "pro";
const DEFAULT_TRIAL_DAYS = 14;

export const WORKSPACE_PLAN_CATALOG = Object.freeze({
  free: Object.freeze({
    id: "free",
    name: "Free",
    headline: "Best for individual evaluation and lightweight triage",
    limits: Object.freeze({
      dailyScans: null,
      monitors: 3,
      webhooks: 1,
      apiKeys: 3,
      shareTtlHours: 72,
      retentionDays: 90
    }),
    features: Object.freeze({
      comments: true,
      workflow: true,
      monitoring: true,
      webhooks: true,
      exports: ["json", "csv", "stix", "pdf"],
      brandedReports: true,
      shareRevocation: true
    })
  }),
  pro: Object.freeze({
    id: "pro",
    name: "Pro",
    headline: "Private phishing and trust triage for solo operators",
    limits: Object.freeze({
      dailyScans: 250,
      monitors: 25,
      webhooks: 3,
      apiKeys: 10,
      shareTtlHours: 168,
      retentionDays: 180
    }),
    features: Object.freeze({
      comments: true,
      workflow: true,
      monitoring: true,
      webhooks: true,
      exports: ["json", "csv", "stix", "pdf"],
      brandedReports: true,
      shareRevocation: true
    })
  }),
  team: Object.freeze({
    id: "team",
    name: "Team",
    headline: "Shared triage for service desks and internal security teams",
    limits: Object.freeze({
      dailyScans: 1000,
      monitors: 150,
      webhooks: 10,
      apiKeys: 25,
      shareTtlHours: 336,
      retentionDays: 365
    }),
    features: Object.freeze({
      comments: true,
      workflow: true,
      monitoring: true,
      webhooks: true,
      exports: ["json", "csv", "stix", "pdf"],
      brandedReports: true,
      shareRevocation: true
    })
  }),
  business: Object.freeze({
    id: "business",
    name: "Business",
    headline: "High-volume review with long retention and integration headroom",
    limits: Object.freeze({
      dailyScans: 5000,
      monitors: 500,
      webhooks: 25,
      apiKeys: 100,
      shareTtlHours: 720,
      retentionDays: 365
    }),
    features: Object.freeze({
      comments: true,
      workflow: true,
      monitoring: true,
      webhooks: true,
      exports: ["json", "csv", "stix", "pdf"],
      brandedReports: true,
      shareRevocation: true
    })
  })
});

function toIsoOrNull(value) {
  if (!value) {
    return null;
  }

  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date.toISOString();
}

function resolveNonNegativeOverride(value, fallback) {
  if (value == null || value === "") {
    return fallback;
  }

  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return fallback;
  }

  return parsed;
}

function resolvePositiveOverride(value, fallback) {
  if (value == null || value === "") {
    return fallback;
  }

  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }

  return parsed;
}

export function resolveTrialState(profile = {}, now = new Date()) {
  const currentTimeMs = now instanceof Date ? now.getTime() : Date.now();
  const trialStatus = String(profile?.trialStatus || "available").trim().toLowerCase() || "available";
  const trialEndsAt = toIsoOrNull(profile?.trialEndsAt);
  const trialEndsAtMs = Date.parse(trialEndsAt || "");

  if (trialStatus === "active") {
    if (Number.isFinite(trialEndsAtMs) && trialEndsAtMs > currentTimeMs) {
      return "active";
    }

    return "expired";
  }

  if (trialStatus === "converted") {
    return "converted";
  }

  if (trialStatus === "expired") {
    return "expired";
  }

  return "available";
}

export function resolveEffectivePlanId(profile = {}, config = {}, now = new Date()) {
  const basePlanId = WORKSPACE_PLAN_CATALOG[profile?.planId] ? profile.planId : "free";
  const trialState = resolveTrialState(profile, now);
  const trialPlanId = WORKSPACE_PLAN_CATALOG[profile?.trialPlanId] ? profile.trialPlanId : DEFAULT_TRIAL_PLAN_ID;

  if (trialState === "active") {
    return trialPlanId;
  }

  if (basePlanId === "free" && Number(config?.freeTierDailyScanLimit) > 0) {
    return basePlanId;
  }

  return basePlanId;
}

export function getPlanDefinition(planId = "free") {
  return WORKSPACE_PLAN_CATALOG[planId] || WORKSPACE_PLAN_CATALOG.free;
}

export function buildWorkspaceEntitlements(profile = {}, config = {}, now = new Date()) {
  const effectivePlanId = resolveEffectivePlanId(profile, config, now);
  const plan = getPlanDefinition(effectivePlanId);
  const freePlan = getPlanDefinition("free");
  const dailyScans =
    effectivePlanId === "free" && Number(config?.freeTierDailyScanLimit) > 0
      ? Number(config.freeTierDailyScanLimit)
      : plan.limits.dailyScans;
  const retentionDays = resolvePositiveOverride(profile?.retentionDaysOverride, plan.limits.retentionDays);

  return {
    planId: plan.id,
    planName: plan.name,
    headline: plan.headline,
    trial: {
      status: resolveTrialState(profile, now),
      trialPlanId: WORKSPACE_PLAN_CATALOG[profile?.trialPlanId] ? profile.trialPlanId : DEFAULT_TRIAL_PLAN_ID,
      trialStartedAt: toIsoOrNull(profile?.trialStartedAt),
      trialEndsAt: toIsoOrNull(profile?.trialEndsAt),
      trialDays:
        Number.isFinite(Number(profile?.trialDays)) && Number(profile.trialDays) > 0
          ? Number(profile.trialDays)
          : DEFAULT_TRIAL_DAYS
    },
    limits: {
      dailyScans,
      monitors: resolveNonNegativeOverride(profile?.monitorLimitOverride, plan.limits.monitors),
      webhooks: resolveNonNegativeOverride(profile?.webhookLimitOverride, plan.limits.webhooks),
      apiKeys: resolveNonNegativeOverride(profile?.apiKeyLimitOverride, plan.limits.apiKeys),
      shareTtlHours: plan.limits.shareTtlHours,
      retentionDays
    },
    features: {
      ...freePlan.features,
      ...plan.features
    },
    billing: {
      provider: profile?.billingProvider || null,
      customerId: profile?.billingCustomerId || null,
      subscriptionId: profile?.billingSubscriptionId || null,
      status:
        resolveTrialState(profile, now) === "active"
          ? "trialing"
          : profile?.billingSubscriptionId
            ? "configured"
            : "not_configured"
    }
  };
}

export function createDefaultWorkspaceProfile(userId, now = new Date().toISOString()) {
  const timestamp = toIsoOrNull(now) || new Date().toISOString();

  return {
    id: `workspace_${userId}`,
    userId,
    planId: "free",
    trialPlanId: DEFAULT_TRIAL_PLAN_ID,
    trialStatus: "available",
    trialStartedAt: null,
    trialEndsAt: null,
    trialDays: DEFAULT_TRIAL_DAYS,
    retentionDaysOverride: null,
    monitorLimitOverride: null,
    webhookLimitOverride: null,
    apiKeyLimitOverride: null,
    billingProvider: null,
    billingCustomerId: null,
    billingSubscriptionId: null,
    createdAt: timestamp,
    updatedAt: timestamp
  };
}

export function buildWorkspaceSnapshot({
  profile,
  config,
  usage,
  counts = {},
  now = new Date()
}) {
  const entitlements = buildWorkspaceEntitlements(profile, config, now);

  return {
    profile: {
      planId: profile?.planId || "free",
      effectivePlanId: entitlements.planId,
      planName: entitlements.planName,
      headline: entitlements.headline
    },
    trial: entitlements.trial,
    billing: entitlements.billing,
    entitlements: {
      limits: entitlements.limits,
      features: entitlements.features
    },
    usage: {
      scans: usage || null,
      monitorsActive: Number(counts.monitorsActive) || 0,
      webhooksActive: Number(counts.webhooksActive) || 0,
      apiKeysActive: Number(counts.apiKeysActive) || 0
    },
    upgradePath: {
      recommendedPlanId: entitlements.planId === "free" ? "pro" : entitlements.planId === "pro" ? "team" : "business",
      trialAvailable: entitlements.trial.status === "available"
    }
  };
}

export function buildStartedTrialProfile(profile = {}, now = new Date()) {
  const startedAt = now instanceof Date ? now : new Date(now);
  const trialDays =
    Number.isFinite(Number(profile?.trialDays)) && Number(profile.trialDays) > 0 ? Number(profile.trialDays) : DEFAULT_TRIAL_DAYS;
  const trialEndsAt = new Date(startedAt.getTime() + trialDays * 24 * 60 * 60 * 1000);

  return {
    ...profile,
    trialPlanId: WORKSPACE_PLAN_CATALOG[profile?.trialPlanId] ? profile.trialPlanId : DEFAULT_TRIAL_PLAN_ID,
    trialStatus: "active",
    trialStartedAt: startedAt.toISOString(),
    trialEndsAt: trialEndsAt.toISOString(),
    updatedAt: startedAt.toISOString()
  };
}
