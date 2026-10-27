import { termsIn } from "../glossary";

// A fold-out list of the hard words in this finding's own text. It is a real details element, so
// it opens with a tap or the keyboard, and nothing depends on hovering.
export function PlainWords({ text }: { text: string }) {
  const terms = termsIn(text);
  if (terms.length === 0) return null;
  return (
    <details className="rounded-lane border-2 border-ink bg-white p-4">
      <summary className="flex min-h-11 cursor-pointer items-center font-display text-title font-bold">
        Plain words ({terms.length})
      </summary>
      <dl className="mt-3 space-y-3 text-secondary">
        {terms.map((entry) => (
          <div key={entry.term}>
            <dt className="font-semibold">{entry.term}</dt>
            <dd className="text-dim">{entry.meaning}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}
