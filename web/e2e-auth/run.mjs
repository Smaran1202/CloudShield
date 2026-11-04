import { spawnSync } from "node:child_process";
import { rmSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

// The one place that names the throwaway database. It holds one made-up finding and is deleted
// before and after. This test calls no AWS, no Gemini and no Docker: the only thing it sends
// besides GET is the login and the logout.
const DB_NAME = "e2e-auth.db";

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
  [cli, "test", "-c", "e2e-auth/playwright.config.ts", ...process.argv.slice(2)],
  { cwd: webDir, stdio: "inherit", env: process.env },
);
removeDatabase();
process.exit(result.status ?? 1);
