import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { defineConfig } from "@playwright/test";
import { installedBrowser } from "../browser";
import {
  API_PORT,
  DB_NAME,
  OWNER_PASSWORD,
  VIEWER_PASSWORD,
  WEB_PORT,
} from "./credentials";

const WEB = `http://localhost:${WEB_PORT}`;
const API = `http://127.0.0.1:${API_PORT}`;
// run.mjs starts this from the web folder, so the project folder is the one above it.
const root = path.resolve(process.cwd(), "..");
const python =
  process.platform === "win32" ? ".venv\\Scripts\\python.exe" : ".venv/bin/python";

// The hash is made by the project's own code, from the made-up password above. Nothing real is
// used, and no password is typed or printed.
function hashOf(password: string): string {
  const code =
    "import sys; from cloudshield.auth.passwords import hash_password; print(hash_password(sys.argv[1]))";
  const done = spawnSync(path.join(root, python), ["-c", code, password], {
    cwd: root,
    encoding: "utf-8",
  });
  if (done.status !== 0)
    throw new Error(`Could not make a password hash: ${done.stderr}`);
  return done.stdout.trim();
}

// Own servers on other ports, never reused. The API has the login on, a throwaway database made
// from the migrations and one made-up imported finding, and the web address as its frontend
// origin. The web app learns the API address from VITE_API_URL.
export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  outputDir: "../test-results/auth",
  workers: 1,
  fullyParallel: false,
  retries: 0,
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
      command: [
        `${python} -m alembic upgrade head`,
        `${python} -m cloudshield.imports prowler web/e2e-auth/seed.json`,
        `${python} -m uvicorn cloudshield.api.app:create_app --factory --host 127.0.0.1 --port ${API_PORT}`,
      ].join(" && "),
      cwd: root,
      url: `${API}/api/health`,
      reuseExistingServer: false,
      timeout: 120_000,
      env: {
        DATABASE_URL: `sqlite:///${DB_NAME}`,
        FRONTEND_ORIGIN: WEB,
        AUTH_ENABLED: "true",
        OWNER_PASSWORD_HASH: hashOf(OWNER_PASSWORD),
        VIEWER_PASSWORD_HASH: hashOf(VIEWER_PASSWORD),
        SESSION_SECRET: randomBytes(48).toString("base64url"),
      },
    },
    {
      command: `npm run dev -- --host localhost --port ${WEB_PORT} --strictPort`,
      cwd: "..",
      url: WEB,
      reuseExistingServer: false,
      timeout: 60_000,
      env: { VITE_API_URL: `http://localhost:${API_PORT}` },
    },
  ],
});
