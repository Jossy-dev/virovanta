import "dotenv/config";
import { createApp } from "./src/app/createApp.js";

async function startWorker() {
  const { config, logger, services } = await createApp({
    configOverrides: {
      runApiServer: false,
      runScanWorker: true
    }
  });

  logger.info(
    { queueProvider: config.queueProvider, queueName: config.queueName, service: config.serviceName },
    "Scan worker started."
  );

  async function shutdown(signal) {
    logger.info({ signal }, "Shutting down worker.");
    await services.scanQueueService?.stop?.().catch(() => {});
    await services.store?.close?.().catch(() => {});
    process.exit(0);
  }

  process.on("SIGTERM", () => {
    shutdown("SIGTERM");
  });

  process.on("SIGINT", () => {
    shutdown("SIGINT");
  });
}

startWorker().catch((error) => {
  console.error("Failed to start worker", error);
  process.exit(1);
});
