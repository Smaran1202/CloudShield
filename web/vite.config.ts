import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // localhost is always allowed. "cloudshield" is the extra name the dev server answers to. The
  // server is not bound to other interfaces: that is still decided by --host.
  server: { allowedHosts: ["cloudshield"] },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    // The browser tests in e2e/ and e2e-actions/ are run by Playwright, not by vitest.
    exclude: [...configDefaults.exclude, "e2e/**", "e2e-actions/**"],
    // Style files are empty in tests, except when a test reads one as text.
    css: { include: [/\.css\?raw$/] },
  },
});
