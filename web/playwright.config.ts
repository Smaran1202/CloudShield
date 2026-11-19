import { defineConfig } from "@playwright/test";
import { installedBrowser } from "./browser";

const WEB = "http://localhost:5173";
const API = "http://127.0.0.1:8000";

const python =
  process.platform === "win32" ? ".venv\\Scripts\\python.exe" : ".venv/bin/python";

export default defineConfig({
  testDir: "e2e",
  outputDir: "test-results",
  workers: 1,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: WEB,
    channel: installedBrowser(),
    screenshot: "off",
    trace: "off",
    video: "off",
  },
  // Servers that are already running are reused. The API starts in the project folder.
  webServer: [
    {
      command: `${python} -m uvicorn cloudshield.api.app:create_app --factory --host 127.0.0.1 --port 8000`,
      cwd: "..",
      url: `${API}/api/health`,
      reuseExistingServer: true,
      timeout: 60_000,
    },
    {
      command: "npm run dev -- --host localhost --port 5173 --strictPort",
      url: WEB,
      reuseExistingServer: true,
      timeout: 60_000,
    },
  ],
});
