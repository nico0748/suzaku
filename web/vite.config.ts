import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Vite dev server runs on :5173, FastAPI on :8765.
// Same-origin in prod (FastAPI serves web/dist/), but in dev we proxy /api/*
// to localhost:8765 so CSRF + Origin checks in OriginCheckMiddleware see a
// localhost prefix.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8765",
        changeOrigin: false,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
