import { useId, type ReactNode } from "react";

// Shown on hover and on keyboard focus, and read out through aria-describedby.
export function Tooltip({ text, children }: { text: string; children: ReactNode }) {
  const id = useId();
  return (
    <span className="group relative inline-flex">
      <span
        tabIndex={0}
        aria-describedby={id}
        className="cursor-help underline decoration-dotted underline-offset-4"
      >
        {children}
      </span>
      <span
        role="tooltip"
        id={id}
        className="pointer-events-none absolute bottom-full left-0 z-10 mb-2 hidden w-72 rounded-chip bg-ink p-3 font-body text-secondary font-normal text-white group-focus-within:block group-hover:block"
      >
        {text}
      </span>
    </span>
  );
}
