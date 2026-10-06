import { describe, expect, it } from "vitest";
import indexHtml from "../index.html?raw";

// Every file under web/src as text, so these rules cover the whole code base.
const everything = import.meta.glob("./**/*", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

// Page code and styles, without the tests and without the tokens file that defines the scale.
const pageCode = Object.fromEntries(
  Object.entries(everything).filter(
    ([name]) =>
      /\.(tsx?|css)$/.test(name) &&
      !/\.test\.tsx?$/.test(name) &&
      name !== "./tokens.css",
  ),
);

// What UTF-8 text looks like after it has been read as Windows-1252 and saved again, written
// as escapes so that this file does not contain them.
const MOJIBAKE = ["â†", "â€", "âœ", "Ã", "Â", "ï¿½", "�"];

function matches(text: string, pattern: RegExp): string[] {
  return [...text.matchAll(pattern)].map((m) => m[0].trim());
}

describe("file encoding", () => {
  it("reads more than a few files, so the rule is not empty", () => {
    expect(Object.keys(everything).length).toBeGreaterThan(40);
  });

  it("has no mojibake in any file under web/src", () => {
    const found: string[] = [];
    for (const [name, text] of Object.entries(everything)) {
      for (const sequence of MOJIBAKE) {
        if (text.includes(sequence))
          found.push(`${name} has U+${sequence.charCodeAt(0).toString(16)}`);
      }
    }

    expect(found).toEqual([]);
  });

  it("has no byte order mark in any file under web/src", () => {
    const found = Object.entries(everything)
      .filter(([, text]) => text.startsWith("﻿"))
      .map(([name]) => name);

    expect(found).toEqual([]);
  });

  it("has no arrow, check or dash glyph typed into the source: icons are SVG", () => {
    const glyphs = /[←-⇿✓✔✕—–]/;
    const found = Object.entries(everything)
      .filter(([, text]) => glyphs.test(text))
      .map(([name]) => name);

    expect(found).toEqual([]);
  });

  it("declares the page as UTF-8, with no mojibake or byte order mark in it", () => {
    expect(indexHtml).toContain('<meta charset="utf-8" />');
    expect(indexHtml.startsWith("﻿")).toBe(false);
    for (const sequence of MOJIBAKE) expect(indexHtml).not.toContain(sequence);
  });
});

describe("type scale", () => {
  it("uses only the token sizes, never a Tailwind default size or a pixel size", () => {
    const found: string[] = [];
    for (const [name, text] of Object.entries(pageCode)) {
      if (!name.endsWith("x") && !name.endsWith("s")) continue;
      for (const hit of matches(text, /(?<![\w-])text-(?:xs|sm|base|lg|xl|[2-9]xl)\b/g)) {
        found.push(`${name}: ${hit}`);
      }
      for (const hit of matches(text, /(?<![\w-])text-\[[^\]]+\]/g))
        found.push(`${name}: ${hit}`);
    }

    expect(found).toEqual([]);
  });

  it("sets no font size in the style files except through the tokens", () => {
    const found: string[] = [];
    for (const [name, text] of Object.entries(pageCode)) {
      if (!name.endsWith(".css")) continue;
      for (const hit of matches(text, /font-size:\s*[^;]+;/g)) {
        if (!hit.includes("var(--text-")) found.push(`${name}: ${hit}`);
      }
    }

    expect(found).toEqual([]);
  });
});

describe("spacing scale", () => {
  const ALLOWED = new Set(["0", "1", "2", "3", "4", "6", "8", "12", "16"]);
  const SPACING =
    /(?<![\w-])-?(?:px|py|pt|pr|pb|pl|p|mx|my|mt|mr|mb|ml|m|gap-x|gap-y|gap|space-x|space-y)-(\d+(?:\.\d+)?)(?![\w.[-])/g;

  it("uses only the spacing tokens (4, 8, 12, 16, 24, 32, 48, 64) for padding, margin and gap", () => {
    const found: string[] = [];
    for (const [name, text] of Object.entries(pageCode)) {
      if (!/\.tsx?$/.test(name)) continue;
      for (const match of text.matchAll(SPACING)) {
        if (!ALLOWED.has(match[1])) found.push(`${name}: ${match[0]}`);
      }
    }

    expect(found).toEqual([]);
  });
});

describe("finish", () => {
  it("has no gradients and no emoji", () => {
    const emoji = /[\u{1F300}-\u{1FAFF}☀-⛿]/u;
    const found: string[] = [];
    for (const [name, text] of Object.entries(pageCode)) {
      if (/gradient\(/.test(text) || /(?<![\w-])(?:bg|from|to|via)-gradient/.test(text)) {
        found.push(`${name}: gradient`);
      }
      if (emoji.test(text)) found.push(`${name}: emoji`);
    }

    expect(found).toEqual([]);
  });

  it("uses the lift shadow only in the tile hover state", () => {
    const shadows: string[] = [];
    for (const [name, text] of Object.entries(pageCode)) {
      for (const hit of matches(
        text,
        /(?<![\w-])shadow(?:-[\w[\]]+)?\b|box-shadow:[^;]+;/g,
      )) {
        shadows.push(`${name}: ${hit}`);
      }
    }

    // Animated pulse dot (motion.css) and the tile hover are the only box-shadows.
    const outsideMotion = shadows.filter((s) => !s.startsWith("./motion.css"));
    expect(outsideMotion).toEqual(["./index.css: box-shadow: var(--shadow-lift);"]);
  });
});
