import { describe, expect, it } from "vitest";
import index from "./index.css?raw";
import motion from "./motion.css?raw";
import tokens from "./tokens.css?raw";

const MEDIA = "@media (prefers-reduced-motion: no-preference)";

// The text between the braces of the media query, found by counting braces.
function mediaBlock(css: string): { start: number; end: number } {
  const open = css.indexOf("{", css.indexOf(MEDIA));
  let depth = 0;
  for (let i = open; i < css.length; i += 1) {
    if (css[i] === "{") depth += 1;
    if (css[i] === "}") depth -= 1;
    if (depth === 0) return { start: open, end: i };
  }
  throw new Error("The media query is not closed");
}

function positions(css: string, pattern: RegExp): number[] {
  return [...css.matchAll(pattern)].map((match) => match.index ?? 0);
}

describe("motion rules", () => {
  const block = mediaBlock(motion);

  it("has a prefers-reduced-motion media query", () => {
    expect(motion).toContain(MEDIA);
  });

  it("keeps every keyframes rule inside the media query", () => {
    const found = positions(motion, /@keyframes/g);

    expect(found.length).toBeGreaterThanOrEqual(4);
    for (const at of found) expect(at > block.start && at < block.end).toBe(true);
  });

  it("keeps every animation and transition inside the media query", () => {
    const found = positions(motion, /\b(animation|transition)\s*:/g);

    expect(found.length).toBeGreaterThan(5);
    for (const at of found) expect(at > block.start && at < block.end).toBe(true);
  });

  it("has nothing after the media query that moves", () => {
    expect(motion.slice(block.end + 1)).not.toMatch(/animation|transition|@keyframes/);
  });

  it("has no animation or transition in the other style files", () => {
    for (const css of [index, tokens]) {
      expect(css).not.toMatch(/@keyframes|\banimation\s*:|\btransition\s*:/);
    }
  });

  it("defines the named motions", () => {
    for (const name of ["fade", "spin", "slide", "skeleton"]) {
      expect(motion).toContain(`@keyframes ${name}`);
    }
  });

  it("moves the navigation oval and the buttons only inside the media query", () => {
    const at = (needle: string) => motion.indexOf(needle);

    for (const needle of [".nav-oval {", ".btn {"]) {
      expect(at(needle)).toBeGreaterThan(block.start);
      expect(at(needle)).toBeLessThan(block.end);
    }
    expect(motion).toMatch(/\.nav-oval \{\s*transition:\s*transform 180ms ease-out/);
  });

  it("keeps every duration between 100 and 200 ms, except the endless loops", () => {
    const times = [...motion.matchAll(/(?:transition|animation)[^;]*?(\d+)ms/g)].map(
      (m) => Number(m[1]),
    );

    expect(times.length).toBeGreaterThan(4);
    for (const ms of times) expect(ms >= 100 && ms <= 200).toBe(true);
  });

  it("has no bounce and no overshoot", () => {
    expect(motion).not.toMatch(/cubic-bezier|scale\(|translateY/);
  });

  it("does not hide anything outside the media query, so the still page is complete", () => {
    const outside = motion.slice(0, block.start) + motion.slice(block.end + 1);

    expect(outside).not.toMatch(/opacity\s*:\s*0\b/);
  });
});

describe("tokens", () => {
  it("defines the colours, fonts and radii of the design", () => {
    for (const value of [
      "#0f172a",
      "#f8f9fb",
      "#b42318",
      "#0e5a6b",
      "#166a46",
      "#e2e8f0",
      "#8794a8",
      "#475569",
      "#eaeef3",
      "#64748b",
      "#fde8e6",
      "#8a1c12",
      "#dff1e8",
      "#11543a",
      "#334155",
    ]) {
      expect(tokens.toLowerCase()).toContain(value);
    }
    expect(tokens).toContain("IBM Plex Sans");
    expect(tokens).toContain("IBM Plex Mono");
    expect(tokens).toContain("--radius-chip: 4px");
    expect(tokens).toContain("--radius-lane: 6px");
    expect(tokens).toContain("outline: 2px solid");
    expect(tokens).toContain("outline-offset: 2px");
  });

  it("shows INFO rows in dim text, and lets the hover colours win over it", () => {
    const dim = index.indexOf('.board-row[data-muted="true"]');
    const hover = index.indexOf(".board-row:hover");

    expect(dim).toBeGreaterThan(-1);
    expect(hover).toBeGreaterThan(dim);
  });

  it("defines the type scale, with 12px for tags only and nothing smaller", () => {
    const sizes = [...tokens.matchAll(/--text-[\w-]+: (\d+)px/g)].map((m) =>
      Number(m[1]),
    );

    expect(Math.min(...sizes)).toBe(12);
    expect(tokens).toContain("--text-tag: 12px");
    expect(tokens).toContain("--text-label: 13px");
    expect(tokens).toContain("--text-secondary: 14px");
    expect(tokens).toContain("--text-body: 16px");
    expect(tokens).toContain("--text-title: 20px");
    expect(tokens).toContain("--text-h3: 24px");
    expect(tokens).toContain("--text-h2: 32px");
    expect(tokens).toContain("--text-h1: 48px");
    expect(tokens).toContain("--text-display:");
  });

  it("defines the spacing steps 4, 8, 12, 16, 24, 32, 48 and 64", () => {
    const steps = [...tokens.matchAll(/--space-\d+: (\d+)px/g)].map((m) => Number(m[1]));

    expect(steps).toEqual([4, 8, 12, 16, 24, 32, 48, 64]);
  });

  it("has no shadow, and uses tabular numerals", () => {
    expect(tokens).not.toContain("--shadow");
    expect(index).not.toContain("box-shadow");
    expect(motion).not.toContain("box-shadow");
    expect(index).toContain("tabular-nums");
  });

  it("has no dark theme", () => {
    expect(index).not.toContain("custom-variant dark");
    expect(index).not.toMatch(/\.dark\b/);
  });
});
