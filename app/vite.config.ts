import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// No external CDN, no remote scripts (ARCHITECTURE.md §9.1).
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 5173, strictPort: true, host: "127.0.0.1" },
  build: {
    target: "es2021",
    sourcemap: false,
    // Keep the module-preload polyfill out: it isn't needed in WebView2 and
    // avoids extra inline script.
    modulePreload: { polyfill: false },
  },
});
