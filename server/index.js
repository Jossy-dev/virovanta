import "dotenv/config";
import path from "path";
import { fileURLToPath } from "url";
import { createApp } from "./src/app/createApp.js";
import { registerProductionClientRoutes } from "./src/app/registerProductionClientRoutes.js";

async function start() {
  const { app, config, logger, services } = await createApp();

  async function shutdown(signal) {
    logger.info({ signal }, "Shutting down service.");
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

  if (process.env.NODE_ENV === "production") {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    const clientDistPath = path.resolve(__dirname, "../client/dist");
    registerProductionClientRoutes(app, clientDistPath);
  }

  if (config.runApiServer) {
    app.listen(config.port, () => {
      logger.info({ port: config.port, service: config.serviceName }, `${config.apiTitle} listening on port ${config.port}`);
    });
  } else {
    logger.info({ service: config.serviceName }, "API server disabled (RUN_API_SERVER=false). Worker mode active.");
  }
}

start().catch((error) => {
  console.error("Failed to start service", error);
  process.exit(1);
});
