import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  base: mode === "github-pages" ? "/dnsqueryanalysis/" : "/",
  server: { host: "localhost" },
  preview: { allowedHosts: ["dnsqueryanalysis.onrender.com"] },
}));
