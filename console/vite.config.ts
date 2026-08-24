import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Docker is absent on this machine, so the console talks to a uvicorn running on the host.
// Proxying /v1 keeps the frontend origin-relative: no base URL in the code, and the same
// build works unchanged behind a reverse proxy in Compose.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/v1": {
        target: "http://127.0.0.1:8080",
        changeOrigin: true,
      },
      "/health": { target: "http://127.0.0.1:8080", changeOrigin: true },
    },
  },
});
