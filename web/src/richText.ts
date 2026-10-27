// A small reader for the text an external scanner writes, which uses a few markdown marks:
// **bold**, `code`, [text](https://link), "- " bullet lines, and bare web addresses. It returns
// plain data. Nothing here builds HTML, so text from a file can never become markup.

export type Inline =
  | { kind: "text"; text: string }
  | { kind: "bold"; parts: Inline[] }
  | { kind: "code"; text: string }
  | { kind: "link"; text: string; href: string };

export type Block =
  { kind: "paragraph"; parts: Inline[] } | { kind: "list"; items: Inline[][] };

const MAX_DEPTH = 2;

// code, bold, [text](http link), or a bare http(s) address. Only http and https are links.
const MARK =
  /`([^`\n]+)`|\*\*([^*\n](?:[^\n]*?[^*\n])?)\*\*|\[([^\]\n]+)\]\((https?:\/\/[^\s)]+)\)|(https?:\/\/[^\s<>"'`)\]]+)/g;
const TRAILING = /[.,;:!?]+$/;

function plain(text: string): Inline[] {
  return text ? [{ kind: "text", text }] : [];
}

export function parseInline(text: string, depth = 0): Inline[] {
  const parts: Inline[] = [];
  let last = 0;
  for (const match of text.matchAll(MARK)) {
    const start = match.index ?? 0;
    parts.push(...plain(text.slice(last, start)));
    const [whole, code, bold, label, href, bare] = match;
    if (code !== undefined) {
      parts.push({ kind: "code", text: code });
      last = start + whole.length;
    } else if (bold !== undefined) {
      const inner = depth < MAX_DEPTH ? parseInline(bold, depth + 1) : plain(bold);
      parts.push({ kind: "bold", parts: inner });
      last = start + whole.length;
    } else if (label !== undefined) {
      parts.push({ kind: "link", text: label, href });
      last = start + whole.length;
    } else {
      // A bare address does not own the full stop or comma that ends the sentence.
      const trimmed = bare.replace(TRAILING, "");
      parts.push({ kind: "link", text: trimmed, href: trimmed });
      last = start + trimmed.length;
    }
  }
  parts.push(...plain(text.slice(last)));
  return parts;
}

// "Lead-in: - a - b - c" is one line that really is a list. It is split only when a lead-in
// that ends in a colon is followed by two or more " - " items, so a dash in a sentence stays.
const RUN = /^(.*?:)\s+((?:-\s+)?\S.*)$/;

const BULLET = /^\s*[-*•]\s+(.*)$/;

function splitRun(line: string): string[] | null {
  // A line that is already a bullet is never split again.
  if (BULLET.test(line)) return null;
  const match = RUN.exec(line);
  if (!match) return null;
  const items = match[2].replace(/^-\s+/, "").split(/\s+-\s+/);
  const dashes = items.length - 1 + (match[2].startsWith("- ") ? 1 : 0);
  if (dashes < 2 || items.some((item) => !item.trim())) return null;
  return [match[1], ...items.map((item) => `- ${item.trim()}`)];
}

export function parseRich(text: string): Block[] {
  const lines = text
    .replace(/\r\n?/g, "\n")
    .split("\n")
    .flatMap((line) => splitRun(line) ?? [line]);
  const blocks: Block[] = [];
  let paragraph: string[] = [];
  let items: Inline[][] = [];

  const endParagraph = () => {
    if (paragraph.length > 0) {
      blocks.push({ kind: "paragraph", parts: parseInline(paragraph.join(" ")) });
    }
    paragraph = [];
  };
  const endList = () => {
    if (items.length > 0) blocks.push({ kind: "list", items });
    items = [];
  };

  for (const line of lines) {
    const bullet = BULLET.exec(line);
    if (bullet) {
      endParagraph();
      items.push(parseInline(bullet[1].trim()));
    } else if (line.trim() === "") {
      endParagraph();
      endList();
    } else {
      endList();
      paragraph.push(line.trim());
    }
  }
  endParagraph();
  endList();
  return blocks;
}
