import { parseRich, type Inline } from "../richText";

function Parts({ parts }: { parts: Inline[] }) {
  return (
    <>
      {parts.map((part, index) => {
        if (part.kind === "text") return part.text;
        if (part.kind === "bold") {
          return (
            <strong key={index} className="font-semibold">
              <Parts parts={part.parts} />
            </strong>
          );
        }
        if (part.kind === "code") {
          return (
            <code
              key={index}
              className="rounded-[4px] bg-lane-grey px-1 font-mono text-label"
            >
              {part.text}
            </code>
          );
        }
        return (
          <a
            key={index}
            href={part.href}
            target="_blank"
            rel="noopener noreferrer"
            className="font-semibold break-all underline"
          >
            {part.text}
          </a>
        );
      })}
    </>
  );
}

// Text from an external scanner, shown with its bold, code, bullets and links. This is the one
// place every imported text field goes through, and it only ever makes text, never markup.
export function RichText({ text }: { text: string }) {
  return (
    <div className="space-y-2 text-secondary break-words">
      {parseRich(text).map((block, index) =>
        block.kind === "paragraph" ? (
          <p key={index}>
            <Parts parts={block.parts} />
          </p>
        ) : (
          <ul key={index} className="list-disc space-y-1 pl-6">
            {block.items.map((item, position) => (
              <li key={position}>
                <Parts parts={item} />
              </li>
            ))}
          </ul>
        ),
      )}
    </div>
  );
}
