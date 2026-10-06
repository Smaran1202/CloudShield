import type { KeyboardEvent, ReactNode } from "react";

export interface TabSpec {
  id: string;
  label: string;
}

export function Tabs({
  tabs,
  active,
  onChange,
  children,
}: {
  tabs: TabSpec[];
  active: string;
  onChange: (id: string) => void;
  children: ReactNode;
}) {
  function onKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const step = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
    if (step === 0) return;
    event.preventDefault();
    const next = tabs[(index + step + tabs.length) % tabs.length];
    onChange(next.id);
    document.getElementById(`tab-${next.id}`)?.focus();
  }

  return (
    <div>
      <div
        role="tablist"
        aria-label="Finding sections"
        className="mb-6 flex flex-wrap gap-2 border-b-2 border-divider"
      >
        {tabs.map((tab, index) => (
          <button
            key={tab.id}
            id={`tab-${tab.id}`}
            type="button"
            role="tab"
            aria-selected={tab.id === active}
            aria-controls={`panel-${tab.id}`}
            tabIndex={tab.id === active ? 0 : -1}
            onClick={() => onChange(tab.id)}
            onKeyDown={(event) => onKeyDown(event, index)}
            className={`-mb-[2px] min-h-12 border-b-4 px-6 font-display text-title font-bold ${
              tab.id === active
                ? "border-red text-ink"
                : "border-transparent text-dim hover:text-ink"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`panel-${active}`} aria-labelledby={`tab-${active}`}>
        {children}
      </div>
    </div>
  );
}
