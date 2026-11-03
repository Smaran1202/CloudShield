import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    // The browser tests in e2e/ are run by Playwright (npm run e2e), not by vitest.
    exclude: [...configDefaults.exclude, "e2e/**"],
    // Style files are empty in tests, except when a test reads one as text.
    css: { include: [/\.css\?raw$/] },
  },
});
