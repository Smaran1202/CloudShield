import { defineConfig } from "@playwright/test";
import { installedBrowser } from "../browser";

function setting(name: string): string {
  const value = process.env[name];
  if (!value || process.env.CLOUDSHIELD_E2E_ACTIONS !== "yes") {
    throw new Error(
      "These tests act on AWS. Run them with: $env:CLOUDSHIELD_E2E_ACTIONS = 'yes'; npm run e2e:actions",
    );
  }
  return value;
}

const db = setting("E2E_ACTIONS_DB");
const apiPort = setting("E2E_ACTIONS_API_PORT");
const webPort = setting("E2E_ACTIONS_WEB_PORT");

const WEB = `http://localhost:${webPort}`;
const API = `http://127.0.0.1:${apiPort}`;
const python =
  process.platform === "win32" ? ".venv\\Scripts\\python.exe" : ".venv/bin/python";

// Own servers on other ports, never reused: if a port is busy the run stops. The API gets a
// throwaway SQLite file (made from the migrations) and the web address as its frontend origin,
// so the origin check passes. The web app learns the API address from VITE_API_URL.
export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  outputDir: "../test-results/actions",
  workers: 1,
  fullyParallel: false,
  retries: 0,
  timeout: 15 * 60_000,
  reporter: [["list"]],
  use: {
    baseURL: WEB,
    channel: installedBrowser(),
    screenshot: "off",
    trace: "off",
    video: "off",
  },
  webServer: [
    {
      command: `${python} -m alembic upgrade head && ${python} -m uvicorn cloudshield.api.app:create_app --factory --host 127.0.0.1 --port ${apiPort}`,
      cwd: "../..",
      url: `${API}/api/health`,
      reuseExistingServer: false,
      timeout: 120_000,
      env: { DATABASE_URL: `sqlite:///${db}`, FRONTEND_ORIGIN: WEB },
    },
    {
      command: `npm run dev -- --host localhost --port ${webPort} --strictPort`,
      cwd: "..",
      url: WEB,
      reuseExistingServer: false,
      timeout: 60_000,
      env: { VITE_API_URL: `http://localhost:${apiPort}` },
    },
  ],
});
