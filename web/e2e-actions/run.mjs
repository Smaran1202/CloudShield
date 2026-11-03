import { spawnSync } from "node:child_process";
import { rmSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

// The one place that names the throwaway database and the ports. The Playwright config and the
// tests read them from the environment, so they cannot be run any other way.
const DB_NAME = "e2e-actions.db";
const API_PORT = "8010";
const WEB_PORT = "5183";

const NOTICE = `
These tests ACT. They are not read-only. They will:
  - call AWS, read-only, with the profile in your .env (a real scan of that account)
  - maybe call Gemini (Generate fix does, when a key and model are set in your .env)
  - run Docker (Run full scan does, when PROWLER_MODE=docker in your .env), for up to 30 minutes
  - write only to a throwaway database, ${DB_NAME}, which is deleted before and after
They start their own API on port ${API_PORT} and web server on port ${WEB_PORT}.
Your real cloudshield.db is not touched.
`;

if (process.env.CLOUDSHIELD_E2E_ACTIONS !== "yes") {
  console.error(NOTICE);
  console.error("Not started. To run them, set CLOUDSHIELD_E2E_ACTIONS=yes first:");
  console.error('  $env:CLOUDSHIELD_E2E_ACTIONS = "yes"; npm run e2e:actions');
  process.exit(1);
}
console.log(NOTICE);

const here = path.dirname(fileURLToPath(import.meta.url));
const webDir = path.resolve(here, "..");
const rootDir = path.resolve(webDir, "..");

function removeDatabase() {
  for (const suffix of ["", "-journal", "-wal", "-shm"]) {
    const file = path.join(rootDir, DB_NAME + suffix);
    try {
      rmSync(file, { force: true });
    } catch (error) {
      console.error(`Could not delete ${file}: ${error.message}. Delete it yourself.`);
    }
  }
}

removeDatabase();
const cli = createRequire(import.meta.url).resolve("@playwright/test/cli");
const result = spawnSync(
  process.execPath,
  [cli, "test", "-c", "e2e-actions/playwright.config.ts", ...process.argv.slice(2)],
  {
    cwd: webDir,
    stdio: "inherit",
    env: {
      ...process.env,
      E2E_ACTIONS_DB: DB_NAME,
      E2E_ACTIONS_API_PORT: API_PORT,
      E2E_ACTIONS_WEB_PORT: WEB_PORT,
    },
  },
);
removeDatabase();
process.exit(result.status ?? 1);
