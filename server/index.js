import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { createApp } from "./src/app/createApp.js";

async function start() {
  const { app, config, logger } = await createApp();

  if (process.env.NODE_ENV === "production") {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    const clientDistPath = path.resolve(__dirname, "../client/dist");

    app.use(express.static(clientDistPath));

    app.get(/^\/(?!api).*/, (_req, res) => {
      res.sendFile(path.join(clientDistPath, "index.html"));
    });
  }

  app.listen(config.port, () => {
    logger.info({ port: config.port }, `ViroVanta API listening on http://localhost:${config.port}`);
  });
}

start().catch((error) => {
  console.error("Failed to start ViroVanta", error);
  process.exit(1);
});
