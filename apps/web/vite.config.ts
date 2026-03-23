import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const rootDir = fileURLToPath(new URL("../..", import.meta.url));

export default defineConfig({
  envDir: resolve(rootDir),
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("@mediapipe/tasks-vision")) {
            return "vision-vendor";
          }

          if (
            id.includes("/react/") ||
            id.includes("\\react\\") ||
            id.includes("/react-dom/") ||
            id.includes("\\react-dom\\") ||
            id.includes("/scheduler/") ||
            id.includes("\\scheduler\\")
          ) {
            return "react-vendor";
          }

          if (id.includes("/jsqr/") || id.includes("\\jsqr\\")) {
            return "qr-vendor";
          }
        }
      }
    }
  },
  server: {
    port: Number(process.env.PORT_WEB) || 5173
  }
});
