import { describe, expect, it } from "vitest";
import { formatDate, formatRelative, scanDuration } from "./format";

describe("formatDate", () => {
  it("writes the month as a short word, never as a number", () => {
    const text = formatDate("2026-10-02T12:00:00Z");

    expect(text).toMatch(/^\d{1,2} Oct 2026, \d{1,2}:\d{2} (am|pm)$/i);
  });

  it("cannot confuse 2 October with 10 February", () => {
    const second = formatDate("2026-10-02T12:00:00Z");
    const tenth = formatDate("2026-02-10T12:00:00Z");

    expect(second).not.toBe(tenth);
    expect(second).toContain("Oct");
    expect(tenth).toContain("Feb");
    expect(second).not.toMatch(/\d{1,2}\/\d{1,2}/);
    expect(tenth).not.toMatch(/\d{1,2}\/\d{1,2}/);
  });

  it("cannot confuse 5 October with 10 May", () => {
    const fifth = formatDate("2026-10-05T12:00:00Z");
    const tenth = formatDate("2026-05-10T12:00:00Z");

    expect(fifth).toMatch(/^5 Oct 2026/);
    expect(tenth).toMatch(/^10 May 2026/);
    expect(fifth).not.toBe(tenth);
  });

  it("includes the year", () => {
    expect(formatDate("2025-01-15T12:00:00Z")).toContain("2025");
  });

  it("uses a plain space, so the text can be searched and copied", () => {
    expect(formatDate("2026-10-02T12:00:00Z")).not.toMatch(/[\u202f\u00a0]/);
  });

  it("shows a dash when there is no date or the date is not valid", () => {
    expect(formatDate(null)).toBe("-");
    expect(formatDate("not a date")).toBe("-");
  });
});

describe("formatRelative", () => {
  const now = new Date("2026-10-06T12:00:00Z").getTime();
  const ago = (seconds: number) => new Date(now - seconds * 1000).toISOString();

  it("says just now for the last few seconds", () => {
    expect(formatRelative(ago(10), now)).toBe("just now");
  });

  it("counts minutes, hours and days", () => {
    expect(formatRelative(ago(5 * 60), now)).toBe("5 minutes ago");
    expect(formatRelative(ago(3 * 3600), now)).toBe("3 hours ago");
    expect(formatRelative(ago(3 * 86400), now)).toBe("3 days ago");
  });

  it("says yesterday for one day ago", () => {
    expect(formatRelative(ago(86400), now)).toBe("yesterday");
  });

  it("counts months and years for old dates", () => {
    expect(formatRelative(ago(90 * 86400), now)).toBe("3 months ago");
    expect(formatRelative(ago(800 * 86400), now)).toBe("2 years ago");
  });

  it("shows a dash when there is no date", () => {
    expect(formatRelative(null, now)).toBe("-");
  });
});

describe("scanDuration", () => {
  it("shows seconds under a minute and minutes with seconds above", () => {
    expect(
      scanDuration({
        started_at: "2026-10-01T10:00:00Z",
        finished_at: "2026-10-01T10:00:42Z",
      }),
    ).toBe("42s");
    expect(
      scanDuration({
        started_at: "2026-10-01T10:00:00Z",
        finished_at: "2026-10-01T10:02:05Z",
      }),
    ).toBe("2m 5s");
  });

  it("shows a dash when the scan has not finished", () => {
    expect(scanDuration({ started_at: "2026-10-01T10:00:00Z", finished_at: null })).toBe(
      "-",
    );
  });
});
