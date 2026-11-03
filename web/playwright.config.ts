import { existsSync } from "node:fs";
import { defineConfig } from "@playwright/test";

const WEB = "http://localhost:5173";
const API = "http://127.0.0.1:8000";

// No browser is downloaded. The tests use the Chrome that is installed, or Edge.
function installedBrowser(): "chrome" | "msedge" {
  const local = process.env.LOCALAPPDATA ?? "";
  const chrome = [
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    `${local}\\Google\\Chrome\\Application\\chrome.exe`,
  ];
  const edge = [
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
  ];
  if (chrome.some(existsSync)) return "chrome";
  if (edge.some(existsSync)) return "msedge";
  throw new Error(
    "Neither Google Chrome nor Microsoft Edge was found. Install one of them: the browser tests do not download a browser.",
  );
}

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
