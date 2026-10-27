import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RichText } from "./components/RichText";
import { parseInline, parseRich } from "./richText";

const RISK =
  "**Unrestricted `*:*` access** enables any action on any resource, risking:\n" +
  "- Data exfiltration (**confidentiality**)\n" +
  "- Unauthorized changes and policy tampering";

function html(text: string): HTMLElement {
  return render(<RichText text={text} />).container;
}

describe("parseInline", () => {
  it("reads bold and inline code", () => {
    expect(parseInline("a **b** and `c`")).toEqual([
      { kind: "text", text: "a " },
      { kind: "bold", parts: [{ kind: "text", text: "b" }] },
      { kind: "text", text: " and " },
      { kind: "code", text: "c" },
    ]);
  });

  it("reads code inside bold, as in the scanner's own text", () => {
    expect(parseInline("**Unrestricted `*:*` access**")).toEqual([
      {
        kind: "bold",
        parts: [
          { kind: "text", text: "Unrestricted " },
          { kind: "code", text: "*:*" },
          { kind: "text", text: " access" },
        ],
      },
    ]);
  });

  it("leaves a lone *:* alone", () => {
    expect(parseInline("allows '*:*' administrative privileges")).toEqual([
      { kind: "text", text: "allows '*:*' administrative privileges" },
    ]);
  });

  it("reads a link and a bare address, without the full stop that ends a sentence", () => {
    expect(
      parseInline("See [the page](https://example.com/a) or https://example.com/b."),
    ).toEqual([
      { kind: "text", text: "See " },
      { kind: "link", text: "the page", href: "https://example.com/a" },
      { kind: "text", text: " or " },
      { kind: "link", text: "https://example.com/b", href: "https://example.com/b" },
      { kind: "text", text: "." },
    ]);
  });

  it("makes links only for http and https", () => {
    for (const text of [
      "[x](javascript:alert(1))",
      "[x](data:text/html,<script>alert(1)</script>)",
      "[x](ftp://example.com/file)",
      "[x](//example.com)",
      "[x](JAVASCRIPT:alert(1))",
    ]) {
      expect(parseInline(text).some((part) => part.kind === "link")).toBe(false);
    }
  });

  it("leaves an unterminated marker as text", () => {
    for (const text of ["**bold", "`code", "[x](http", "a ** b", "``", "**"]) {
      const parts = parseInline(text);
      expect(parts.every((part) => part.kind === "text")).toBe(true);
      expect(parts.map((part) => (part as { text: string }).text).join("")).toBe(text);
    }
  });

  it("keeps markup in the text as text", () => {
    expect(parseInline("<script>alert(1)</script> <b>x</b>")).toEqual([
      { kind: "text", text: "<script>alert(1)</script> <b>x</b>" },
    ]);
  });

  it("does not nest bold forever", () => {
    const deep = "**a **b **c **d** c** b** a**";

    expect(() => parseInline(deep)).not.toThrow();
  });
});

describe("parseRich", () => {
  it("makes a paragraph and then a list from lines that start with a dash", () => {
    const blocks = parseRich(RISK);

    expect(blocks.map((block) => block.kind)).toEqual(["paragraph", "list"]);
    expect(blocks[1]).toMatchObject({ kind: "list" });
    expect((blocks[1] as { items: unknown[] }).items).toHaveLength(2);
  });

  it("starts a new paragraph at a blank line", () => {
    expect(parseRich("one\n\ntwo").map((b) => b.kind)).toEqual([
      "paragraph",
      "paragraph",
    ]);
  });

  it("joins the lines of one paragraph", () => {
    const [block] = parseRich("one\ntwo");

    expect(block).toEqual({
      kind: "paragraph",
      parts: [{ kind: "text", text: "one two" }],
    });
  });

  it("reads Windows line endings", () => {
    expect(parseRich("a:\r\n- b\r\n- c").map((b) => b.kind)).toEqual([
      "paragraph",
      "list",
    ]);
  });

  it("splits a lead-in that ends in a colon followed by two or more dash items", () => {
    const blocks = parseRich("Risks include: - theft - loss - delay");

    expect(blocks.map((b) => b.kind)).toEqual(["paragraph", "list"]);
    expect((blocks[1] as { items: unknown[] }).items).toHaveLength(3);
  });

  it("splits when the first item has no dash of its own but two more follow", () => {
    const blocks = parseRich("Do this: first - second - third");

    expect((blocks[1] as { items: unknown[] }).items).toHaveLength(3);
  });

  it("does not split a sentence that only has one dash", () => {
    expect(parseRich("Use a key - not a password.").map((b) => b.kind)).toEqual([
      "paragraph",
    ]);
    expect(parseRich("Note: use a key - not a password.").map((b) => b.kind)).toEqual([
      "paragraph",
    ]);
  });

  it("does not split a lead-in with a single dash item", () => {
    expect(parseRich("Risks: - theft").map((b) => b.kind)).toEqual(["paragraph"]);
  });

  it("does not split dashes in words or in text with no colon lead-in", () => {
    expect(parseRich("a well-known - check - here").map((b) => b.kind)).toEqual([
      "paragraph",
    ]);
  });

  it("does not split a line that is already a bullet", () => {
    expect(parseRich("- Note: a - b - c").map((b) => b.kind)).toEqual(["list"]);
  });

  it("returns nothing for empty text", () => {
    expect(parseRich("")).toEqual([]);
    expect(parseRich("\n\n")).toEqual([]);
  });

  it("handles a very long text", () => {
    const long = `${"word ".repeat(20000)}**bold** `.repeat(5);

    expect(() => parseRich(long)).not.toThrow();
  });
});

describe("RichText", () => {
  it("shows the scanner's risk text with bold, code and a list, and no raw marks", () => {
    const view = html(RISK);

    expect(view.querySelectorAll("strong")).toHaveLength(2);
    expect(view.querySelector("code")).toHaveTextContent("*:*");
    expect(view.querySelectorAll("li")).toHaveLength(2);
    expect(view.textContent).not.toContain("**");
    expect(view.textContent).not.toContain("`");
  });

  it("puts a split run into separate list items", () => {
    const view = html("Threats include: - theft - loss");

    expect(Array.from(view.querySelectorAll("li")).map((li) => li.textContent)).toEqual([
      "theft",
      "loss",
    ]);
  });

  it("never makes an element out of markup in the text", () => {
    const view = html(
      '<script>window.hacked = true</script><img src=x onerror="window.hacked=1">',
    );

    expect(view.querySelector("script")).toBeNull();
    expect(view.querySelector("img")).toBeNull();
    expect(view.textContent).toContain("<script>");
    expect((window as unknown as { hacked?: boolean }).hacked).toBeUndefined();
  });

  it("makes a link that opens safely, and no link for a javascript address", () => {
    const view = html("[good](https://example.com) [bad](javascript:alert(1))");

    const links = view.querySelectorAll("a");
    expect(links).toHaveLength(1);
    expect(links[0]).toHaveAttribute("href", "https://example.com");
    expect(links[0]).toHaveAttribute("rel", "noopener noreferrer");
    expect(links[0]).toHaveAttribute("target", "_blank");
    expect(view.textContent).toContain("[bad](javascript:alert(1))");
  });

  it("shows an unterminated marker as it was written", () => {
    const view = html("This is **not closed and `neither is this");

    expect(view.textContent).toBe("This is **not closed and `neither is this");
    expect(view.querySelector("strong")).toBeNull();
  });
});
