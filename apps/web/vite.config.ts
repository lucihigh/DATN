import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const rootDir = fileURLToPath(new URL("../..", import.meta.url));

export default defineConfig({
  envDir: resolve(rootDir),
  plugins: [react()],
  server: {
    port: Number(process.env.PORT_WEB) || 5173
  }
});
