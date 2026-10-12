import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Lets the app import the sample .hex files from ../samples.
    fs: { allow: [".."] },
    // The browser talks only to Vite; Vite forwards /api to FastAPI.
    // Demo: whatever URL the browser used (LAN IP, other port, tunnel), the backend sees an allowed Origin.
    proxy: { "/api": { target: "http://127.0.0.1:8000", headers: { Origin: "http://localhost:5173" } } },
  },
});
