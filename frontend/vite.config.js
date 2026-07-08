import { defineConfig } from "vite";

export default defineConfig({
  root: ".",
  build: {
    outDir: "../runtime/ui",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8780",
    },
  },
});
