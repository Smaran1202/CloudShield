import { useEffect, useState } from "react";
import { Icon } from "./Icon";

const COPIED_MS = 1400;

// Copies `text` with the real clipboard. If the browser refuses, it says so in plain words.
export function CopyButton({ text, label }: { text: string; label: string }) {
  const [state, setState] = useState<"idle" | "done" | "failed">("idle");

  useEffect(() => {
    if (state !== "done") return;
    const timer = setTimeout(() => setState("idle"), COPIED_MS);
    return () => clearTimeout(timer);
  }, [state]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setState("done");
    } catch {
      setState("failed");
    }
  }

  return (
    <span className="inline-flex flex-col items-start">
      <button
        type="button"
        onClick={copy}
        aria-label={label}
        className="copy-reveal relative z-10 inline-flex h-11 w-11 items-center justify-center rounded-chip text-ink hover:bg-lane-grey"
      >
        <Icon name={state === "done" ? "check" : "copy"} size={18} />
      </button>
      <span role="status" className="sr-only">
        {state === "done" ? "Copied" : ""}
      </span>
      {state === "failed" && (
        <span role="alert" className="text-label text-red">
          Copy failed: this browser blocked clipboard access.
        </span>
      )}
    </span>
  );
}
