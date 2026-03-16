const DEFAULT_INTEL_TIMEOUT_MS = 8_000;

function toBase64Url(value) {
  return Buffer.from(String(value || ""), "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function withTimeoutSignal(timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  return {
    signal: controller.signal,
    clear: () => clearTimeout(timeout)
  };
}

async function safeJson(response) {
  const type = response.headers.get("content-type") || "";
  if (!type.includes("application/json")) {
    return null;
  }

  return response.json().catch(() => null);
}

function resolveUrlhausApiUrl(config) {
  const base = String(config?.urlhausApiBaseUrl || "https://urlhaus-api.abuse.ch/v1").replace(/\/+$/, "");
  return `${base}/url/`;
}

async function queryVirusTotalUrl(url, config) {
  if (!config?.virusTotalApiKey) {
    return {
      provider: "virustotal",
      status: "disabled",
      reason: "missing_api_key"
    };
  }

  const timeoutMs = Number(config?.urlIntelTimeoutMs) || DEFAULT_INTEL_TIMEOUT_MS;
  const { signal, clear } = withTimeoutSignal(timeoutMs);

  try {
    const urlId = toBase64Url(url);
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      method: "GET",
      headers: {
        accept: "application/json",
        "x-apikey": config.virusTotalApiKey
      },
      signal
    });

    if (response.status === 404) {
      return {
        provider: "virustotal",
        status: "not_found",
        reason: "url_not_indexed"
      };
    }

    if (!response.ok) {
      return {
        provider: "virustotal",
        status: "error",
        reason: `http_${response.status}`
      };
    }

    const payload = await safeJson(response);
    const stats = payload?.data?.attributes?.last_analysis_stats || {};
    const malicious = Number(stats.malicious) || 0;
    const suspicious = Number(stats.suspicious) || 0;
    const harmless = Number(stats.harmless) || 0;
    const undetected = Number(stats.undetected) || 0;

    return {
      provider: "virustotal",
      status: malicious > 0 || suspicious > 0 ? "flagged" : "clean",
      malicious,
      suspicious,
      harmless,
      undetected,
      confidence: Number(payload?.data?.attributes?.reputation) || 0
    };
  } catch (error) {
    return {
      provider: "virustotal",
      status: error?.name === "AbortError" ? "timeout" : "error",
      reason: error?.name === "AbortError" ? "timeout" : "request_failed"
    };
  } finally {
    clear();
  }
}

async function queryGoogleSafeBrowsing(url, config) {
  if (!config?.googleSafeBrowsingApiKey) {
    return {
      provider: "google_safe_browsing",
      status: "disabled",
      reason: "missing_api_key"
    };
  }

  const timeoutMs = Number(config?.urlIntelTimeoutMs) || DEFAULT_INTEL_TIMEOUT_MS;
  const { signal, clear } = withTimeoutSignal(timeoutMs);

  try {
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(config.googleSafeBrowsingApiKey)}`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json"
        },
        body: JSON.stringify({
          client: {
            clientId: String(config?.serviceName || "virovanta").slice(0, 50),
            clientVersion: String(config?.apiVersion || "1.0.0").slice(0, 20)
          },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }]
          }
        }),
        signal
      }
    );

    if (!response.ok) {
      return {
        provider: "google_safe_browsing",
        status: "error",
        reason: `http_${response.status}`
      };
    }

    const payload = await safeJson(response);
    const matches = Array.isArray(payload?.matches) ? payload.matches : [];
    const threatTypes = [...new Set(matches.map((match) => String(match?.threatType || "").trim()).filter(Boolean))];

    return {
      provider: "google_safe_browsing",
      status: matches.length > 0 ? "flagged" : "clean",
      matches: matches.length,
      threatTypes
    };
  } catch (error) {
    return {
      provider: "google_safe_browsing",
      status: error?.name === "AbortError" ? "timeout" : "error",
      reason: error?.name === "AbortError" ? "timeout" : "request_failed"
    };
  } finally {
    clear();
  }
}

async function queryUrlhaus(url, config) {
  if (!config?.urlhausEnabled) {
    return {
      provider: "urlhaus",
      status: "disabled",
      reason: "provider_disabled"
    };
  }

  const timeoutMs = Number(config?.urlIntelTimeoutMs) || DEFAULT_INTEL_TIMEOUT_MS;
  const { signal, clear } = withTimeoutSignal(timeoutMs);

  try {
    const body = new URLSearchParams();
    body.set("url", String(url || ""));

    const response = await fetch(resolveUrlhausApiUrl(config), {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded"
      },
      body: body.toString(),
      signal
    });

    if (!response.ok) {
      return {
        provider: "urlhaus",
        status: "error",
        reason: `http_${response.status}`
      };
    }

    const payload = await safeJson(response);
    const queryStatus = String(payload?.query_status || "").trim().toLowerCase();

    if (!queryStatus || queryStatus === "no_results") {
      return {
        provider: "urlhaus",
        status: "clean",
        queryStatus: queryStatus || "no_results"
      };
    }

    const urlStatus = String(payload?.url_status || "").trim().toLowerCase();
    const threat = String(payload?.threat || "").trim().toUpperCase();
    const tags = Array.isArray(payload?.tags) ? payload.tags.map((value) => String(value || "").trim()).filter(Boolean) : [];

    return {
      provider: "urlhaus",
      status: queryStatus === "ok" ? (urlStatus === "online" || urlStatus === "offline" ? "flagged" : "clean") : "clean",
      queryStatus,
      urlStatus: urlStatus || "unknown",
      threat: threat || null,
      tags,
      firstSeen: payload?.firstseen || null
    };
  } catch (error) {
    return {
      provider: "urlhaus",
      status: error?.name === "AbortError" ? "timeout" : "error",
      reason: error?.name === "AbortError" ? "timeout" : "request_failed"
    };
  } finally {
    clear();
  }
}

export async function getUrlReputationSnapshot({ url, config }) {
  const [virusTotal, googleSafeBrowsing, urlhaus] = await Promise.all([
    queryVirusTotalUrl(url, config),
    queryGoogleSafeBrowsing(url, config),
    queryUrlhaus(url, config)
  ]);

  const providers = [virusTotal, googleSafeBrowsing, urlhaus];
  const flaggedProviders = providers.filter((provider) => provider.status === "flagged");
  const flaggedThreats = [
    ...new Set(
      flaggedProviders.flatMap((provider) => {
        if (provider.provider === "google_safe_browsing") {
          return provider.threatTypes || [];
        }

        if (provider.provider === "virustotal") {
          return provider.malicious > 0 ? ["MALWARE"] : provider.suspicious > 0 ? ["SUSPICIOUS"] : [];
        }

        if (provider.provider === "urlhaus") {
          return provider.threat ? [provider.threat] : ["MALWARE"];
        }

        return [];
      })
    )
  ];

  return {
    providers,
    flagged: flaggedProviders.length > 0,
    flaggedProviders: flaggedProviders.map((provider) => provider.provider),
    flaggedThreats
  };
}
