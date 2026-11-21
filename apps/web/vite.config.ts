import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

export default defineConfig({
  resolve: {
    alias: { "@sentinel/core": fileURLToPath(new URL("../../packages/core/src/index.ts", import.meta.url)) },
  },
  server: {
    // `npm run dev:worker` serves the API on 8787; proxy it so the app is same-origin in dev too.
    proxy: { "/api": "http://127.0.0.1:8787", "/badge": "http://127.0.0.1:8787" },
  },
  build: { target: "es2022" },
});
