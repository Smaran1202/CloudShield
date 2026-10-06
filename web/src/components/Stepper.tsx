export type StepState = "done" | "current" | "todo";

const STEPS = [
  "Review the evidence",
  "Check the blast radius",
  "Apply the fix yourself",
  "Rescan to verify",
];

// The state of each step comes from what has really happened, not from a timer.
export function stepStates(events: {
  fixShown: boolean;
  rescanning: boolean;
  resolved: boolean;
}): StepState[] {
  if (events.resolved) return ["done", "done", "done", "done"];
  if (events.rescanning) return ["done", "done", "done", "current"];
  if (events.fixShown) return ["done", "done", "current", "todo"];
  return ["current", "todo", "todo", "todo"];
}

const BORDER: Record<StepState, string> = {
  done: "border-ink",
  current: "border-red",
  todo: "border-lane-grey",
};

const LABEL: Record<StepState, string> = {
  done: "done",
  current: "current step",
  todo: "to do",
};

export function Stepper({ states }: { states: StepState[] }) {
  return (
    <ol aria-label="Progress" className="mb-8 grid grid-cols-2 gap-4 md:grid-cols-4">
      {STEPS.map((step, index) => (
        <li
          key={step}
          data-state={states[index]}
          aria-current={states[index] === "current" ? "step" : undefined}
          className={`border-t-[6px] pt-3 ${BORDER[states[index]]}`}
        >
          <span className="block font-mono text-label text-dim">Step {index + 1}</span>
          <span
            className={`block font-display text-title font-bold ${
              states[index] === "todo" ? "text-dim" : "text-ink"
            }`}
          >
            {step}
          </span>
          <span className="sr-only">{LABEL[states[index]]}</span>
        </li>
      ))}
    </ol>
  );
}
