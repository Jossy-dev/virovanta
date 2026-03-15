import IORedis from "ioredis";

function shouldEnableTls(config) {
  if (config.redisTls) {
    return true;
  }

  return String(config.redisUrl || "").startsWith("rediss://");
}

export function createRedisClient(config, { purpose = "general", maxRetriesPerRequest = 3 } = {}) {
  if (!config.redisUrl) {
    return null;
  }

  const tlsEnabled = shouldEnableTls(config);

  return new IORedis(config.redisUrl, {
    lazyConnect: false,
    maxRetriesPerRequest,
    enableReadyCheck: true,
    ...(tlsEnabled ? { tls: {} } : {}),
    connectionName: `${config.serviceName}-${purpose}`
  });
}
