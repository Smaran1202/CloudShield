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

    expect(found.length).toBeGreaterThanOrEqual(9);
    for (const at of found) expect(at > block.start && at < block.end).toBe(true);
  });

  it("keeps every animation and transition inside the media query", () => {
    const found = positions(motion, /\b(animation|transition)\s*:/g);

    expect(found.length).toBeGreaterThan(10);
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
    for (const name of [
      "rise",
      "mask",
      "pulse",
      "wipe",
      "draw",
      "fade-up",
      "pop",
      "spin",
      "slide",
    ]) {
      expect(motion).toContain(`@keyframes ${name}`);
    }
  });

  it("does not hide anything outside the media query, so the still page is complete", () => {
    const outside = motion.slice(0, block.start) + motion.slice(block.end + 1);

    expect(outside).not.toMatch(/opacity\s*:\s*0\b/);
  });
});

describe("tokens", () => {
  it("defines the colours, fonts and radii of the design", () => {
    for (const value of [
      "#14110f",
      "#f6f5f1",
      "#c8331c",
      "#2347d8",
      "#1f7a4d",
      "#e3e1da",
      "#8a847a",
      "#4a453f",
      "#efede7",
      "#6b655d",
      "#ffe3dd",
      "#8a1f10",
      "#dcefe4",
      "#14573a",
      "#3a352f",
    ]) {
      expect(tokens.toLowerCase()).toContain(value);
    }
    expect(tokens).toContain("Bricolage Grotesque");
    expect(tokens).toContain("Public Sans");
    expect(tokens).toContain("IBM Plex Mono");
    expect(tokens).toContain("--radius-chip: 6px");
    expect(tokens).toContain("--radius-lane: 10px");
    expect(tokens).toContain("outline: 3px solid");
    expect(tokens).toContain("outline-offset: 3px");
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

  it("has one shadow, for the lifted tile, and uses tabular numerals", () => {
    expect(tokens).toContain("--shadow-lift:");
    expect(index.match(/box-shadow/g)).toHaveLength(1);
    expect(index).toContain("tabular-nums");
  });

  it("has no dark theme", () => {
    expect(index).not.toContain("custom-variant dark");
    expect(index).not.toMatch(/\.dark\b/);
  });
});
