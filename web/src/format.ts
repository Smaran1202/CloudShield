import type { ScanOut } from "./api";

// Dates always spell the month ("5 Oct 2026, 2:42 pm"). A date like 2/10 can mean the second
// of October or the tenth of February, so a numeric day and month is never shown.
const LOCALE = "en-AU";
const DATE_TIME = new Intl.DateTimeFormat(LOCALE, {
  day: "numeric",
  month: "short",
  year: "numeric",
  hour: "numeric",
  minute: "2-digit",
  hour12: true,
});
const RELATIVE = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

function parse(iso: string | null): Date | null {
  if (!iso) return null;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatDate(iso: string | null): string {
  const date = parse(iso);
  if (!date) return "-";
  // Newer engines put a narrow no-break space before "pm".
  return DATE_TIME.format(date).replace(/ /g, " ");
}

const MINUTE = 60;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export function formatRelative(iso: string | null, now: number = Date.now()): string {
  const date = parse(iso);
  if (!date) return "-";
  const seconds = Math.round((date.getTime() - now) / 1000);
  const size = Math.abs(seconds);
  if (size < 45) return "just now";
  if (size < HOUR) return RELATIVE.format(Math.round(seconds / MINUTE), "minute");
  if (size < DAY) return RELATIVE.format(Math.round(seconds / HOUR), "hour");
  if (size < 30 * DAY) return RELATIVE.format(Math.round(seconds / DAY), "day");
  if (size < 365 * DAY) return RELATIVE.format(Math.round(seconds / (30 * DAY)), "month");
  return RELATIVE.format(Math.round(seconds / (365 * DAY)), "year");
}

export function scanDuration(scan: Pick<ScanOut, "started_at" | "finished_at">): string {
  const start = parse(scan.started_at);
  const end = parse(scan.finished_at);
  if (!start || !end) return "-";
  const seconds = Math.round((end.getTime() - start.getTime()) / 1000);
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

// Imported rule ids start with "PRW-". The user sees the check id without it.
export function ruleLabel(ruleId: string): string {
  return ruleId.startsWith("PRW-") ? ruleId.slice("PRW-".length) : ruleId;
}

export function pretty(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2) ?? "null";
}

export function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}

export function scanChipText(scan: ScanOut): string {
  if (scan.status === "completed") {
    return `Scan ${scan.id} completed, ${plural(scan.error_count, "error", "errors")}`;
  }
  return `Scan ${scan.id} ${scan.status}`;
}

export function ruleOptions(rows: { rule_id: string }[]): string[] {
  return [...new Set(rows.map((row) => row.rule_id))].sort();
}

export const ENVIRONMENT_HELP =
  "Combines every open finding that counts toward risk: 100 x (1 - product of (1 - score / 100)). " +
  "It climbs towards 100 with only a few findings, so the lanes decide the order, not this number.";
