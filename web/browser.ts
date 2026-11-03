import { existsSync } from "node:fs";

// No browser is downloaded. The tests use the Chrome that is installed, or Edge.
export function installedBrowser(): "chrome" | "msedge" {
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
