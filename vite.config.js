import { defineConfig, loadEnv } from "vite";
import { createApiHandler } from "./server/api.js";

export default defineConfig(({ mode }) => {
  const fileEnv = loadEnv(mode, process.cwd(), "");
  const env = { ...fileEnv, ...process.env };
  const apiHandler = createApiHandler({ env });
  const mountApi = (server) => {
    server.middlewares.use((req, res, next) => {
      if (!req.url?.startsWith("/api/")) {
        next();
        return;
      }
      void apiHandler(req, res);
    });
  };

  return {
    plugins: [
      {
        name: "doriya-api-middleware",
        configureServer: mountApi,
        configurePreviewServer: mountApi,
      },
    ],
  };
});
