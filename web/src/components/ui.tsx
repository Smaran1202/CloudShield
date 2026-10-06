import { useState, type ReactNode } from "react";
import type { BlastLevel, Certainty, FindingStatus, ScanStatus, Severity } from "../api";
import type { AsyncState } from "../useAsync";
import { Icon } from "./Icon";

const CHIP =
  "inline-flex items-center rounded-chip px-3 py-1 text-secondary font-semibold";

// Every page, and the header, use this one container.
export const CONTAINER = "mx-auto w-full max-w-[1440px] px-[clamp(20px,4vw,64px)]";

export function Container({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return <div className={`${CONTAINER} ${className}`}>{children}</div>;
}

export function Card({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-lane border-2 border-ink bg-white p-6 ${className}`}>
      {children}
    </section>
  );
}

export function PageTitle({ children, sub }: { children: ReactNode; sub?: ReactNode }) {
  return (
    <header className="rise mb-12">
      <h1 className="font-display text-page leading-[0.95] font-extrabold tracking-[-0.045em]">
        {children}
      </h1>
      {sub && <p className="mt-3 text-body text-dim">{sub}</p>}
    </header>
  );
}

export function SectionTitle({ children }: { children: ReactNode }) {
  return (
    <h2 className="font-display text-h3 font-extrabold tracking-[-0.02em]">{children}</h2>
  );
}

const SEVERITY_CHIP: Record<Severity, string> = {
  CRITICAL: "bg-red text-white",
  HIGH: "bg-chip-high-bg text-chip-high-text",
  MEDIUM: "bg-chip-warn-bg text-chip-warn-text",
  LOW: "bg-chip-info-bg text-chip-info-text",
  INFO: "bg-chip-unknown-bg text-chip-unknown-text",
};

export function SeverityChip({ severity }: { severity: Severity }) {
  return <span className={`${CHIP} ${SEVERITY_CHIP[severity]}`}>{severity}</span>;
}

const STATUS_CHIP: Record<FindingStatus | ScanStatus, string> = {
  OPEN: "bg-chip-high-bg text-chip-high-text",
  RESOLVED: "bg-chip-ok-bg text-chip-ok-text",
  queued: "bg-chip-unknown-bg text-chip-unknown-text",
  running: "bg-chip-info-bg text-chip-info-text",
  completed: "bg-chip-ok-bg text-chip-ok-text",
  failed: "bg-chip-high-bg text-chip-high-text",
};

const STATUS_TEXT: Record<FindingStatus | ScanStatus, string> = {
  OPEN: "Open",
  RESOLVED: "Resolved",
  queued: "queued",
  running: "running",
  completed: "completed",
  failed: "failed",
};

export function statusText(status: FindingStatus | ScanStatus): string {
  return STATUS_TEXT[status];
}

export function StatusChip({ status }: { status: FindingStatus | ScanStatus }) {
  return <span className={`${CHIP} ${STATUS_CHIP[status]}`}>{STATUS_TEXT[status]}</span>;
}

const CERTAINTY_CHIP: Record<Certainty, string> = {
  verified: "bg-chip-ok-bg text-chip-ok-text",
  heuristic: "bg-chip-warn-bg text-chip-warn-text",
  unknown: "bg-chip-unknown-bg text-chip-unknown-text",
};

const CERTAINTY_HELP: Record<Certainty, string> = {
  verified: "Read directly from AWS in a scan",
  heuristic: "A conclusion the scan cannot fully prove",
  unknown: "The data needed was not available",
};

export function CertaintyChip({ certainty }: { certainty: Certainty }) {
  return (
    <span
      className={`${CHIP} ${CERTAINTY_CHIP[certainty]}`}
      title={CERTAINTY_HELP[certainty]}
      data-certainty={certainty}
    >
      {certainty}
    </span>
  );
}

const LEVEL_CHIP: Record<BlastLevel, string> = {
  low: "bg-chip-ok-bg text-chip-ok-text",
  medium: "bg-chip-warn-bg text-chip-warn-text",
  high: "bg-chip-high-bg text-chip-high-text",
  unknown: "border-2 border-dashed border-dash bg-transparent text-dim",
};

export function LevelChip({ level }: { level: BlastLevel }) {
  return (
    <span className={`${CHIP} uppercase ${LEVEL_CHIP[level]}`} data-level={level}>
      {level}
    </span>
  );
}

// Rule ids and similar short labels. This is the only place the 12px size is used.
export function Tag({ children }: { children: ReactNode }) {
  return (
    <span className="inline-block rounded-[4px] border-[1.5px] border-current px-2 py-1 font-mono text-tag">
      {children}
    </span>
  );
}

// A check that draws itself when it appears. Other icons are in Icon.tsx.
export function Check({ size = 28 }: { size?: number }) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      className="check"
      aria-hidden="true"
      focusable="false"
    >
      <path d="M4 12.5 L10 18.5 L20 6" pathLength={30} />
    </svg>
  );
}

export function Spinner() {
  return <span className="spinner" aria-hidden="true" />;
}

export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`skeleton rounded-chip ${className}`} />;
}

export type SkeletonShape = "table" | "board" | "card";

// Loading placeholders are shaped like what they stand in for, so the page does not jump.
export function Loading({
  label = "Loading",
  shape = "card",
}: {
  label?: string;
  shape?: SkeletonShape;
}) {
  return (
    <div role="status">
      <span className="sr-only">{label}...</span>
      <div aria-hidden="true">
        {shape === "table" && (
          <div className="space-y-3">
            <Skeleton className="h-16 w-1/2" />
            <Skeleton className="h-11 w-full" />
            {Array.from({ length: 8 }, (_, i) => (
              <Skeleton key={i} className="h-16 w-full" />
            ))}
          </div>
        )}
        {shape === "board" && (
          <div className="space-y-12">
            <div className="grid gap-12 min-[1100px]:grid-cols-[1.4fr_1fr]">
              <Skeleton className="h-64 w-full" />
              <Skeleton className="h-64 w-full" />
            </div>
            <div className="flex flex-wrap gap-6">
              {[0, 1, 2].map((i) => (
                <Skeleton key={i} className="h-80 flex-[1_1_300px]" />
              ))}
            </div>
          </div>
        )}
        {shape === "card" && (
          <div className="space-y-6">
            <Skeleton className="h-16 w-1/2" />
            <Skeleton className="h-48 w-full" />
          </div>
        )}
      </div>
    </div>
  );
}

export const PRIMARY_BUTTON =
  "inline-flex min-h-12 items-center justify-center gap-2 rounded-chip bg-ink px-6 text-secondary font-semibold text-white disabled:cursor-not-allowed disabled:opacity-70";

export const SECONDARY_BUTTON =
  "inline-flex min-h-11 items-center justify-center gap-2 rounded-chip border-2 border-ink bg-white px-4 text-secondary font-semibold text-ink hover:bg-lane-grey disabled:cursor-not-allowed disabled:opacity-60";

export const FIELD =
  "h-11 rounded-chip border-[1.5px] border-ink bg-white px-3 font-body text-secondary text-ink placeholder:text-dim";

// A native <select> with its own look and a chevron icon over it.
export function SelectField({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: [string, string][];
}) {
  return (
    <label className="flex flex-col gap-1 text-label font-semibold">
      {label}
      <span className="relative inline-block">
        <select
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="styled-select h-11 w-full min-w-[160px] rounded-chip border-[1.5px] border-ink bg-white pr-12 pl-3 font-body text-secondary font-normal text-ink"
        >
          {options.map(([optionValue, text]) => (
            <option key={optionValue} value={optionValue}>
              {text}
            </option>
          ))}
        </select>
        <Icon
          name="chevron"
          size={18}
          className="pointer-events-none absolute top-1/2 right-4 -translate-y-1/2"
        />
      </span>
    </label>
  );
}

export function ErrorBox({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div
      role="alert"
      className="rounded-lane border-2 border-red bg-chip-high-bg p-6 text-secondary text-chip-high-text"
    >
      <p className="font-semibold">Something went wrong</p>
      <p className="mt-1 break-words">{message}</p>
      {onRetry && (
        <button type="button" onClick={onRetry} className={`mt-4 ${SECONDARY_BUTTON}`}>
          Try again
        </button>
      )}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="rounded-lane border-2 border-dashed border-dash p-8 text-center">
      <p className="font-display text-title font-bold">{title}</p>
      {children && <div className="mt-2 text-secondary text-dim">{children}</div>}
    </div>
  );
}

// Shows the loading and error states, and hands the data to `children` on success. A failed
// refresh keeps the old data on screen and says what went wrong above it.
export function AsyncView<T>({
  state,
  onRetry,
  label,
  shape,
  children,
}: {
  state: AsyncState<T>;
  onRetry: () => void;
  label?: string;
  shape?: SkeletonShape;
  children: (data: T) => ReactNode;
}) {
  if (state.status === "loading") return <Loading label={label} shape={shape} />;
  if (state.status === "error")
    return <ErrorBox message={state.message} onRetry={onRetry} />;
  return (
    <>
      {state.refreshError && (
        <div className="mb-4">
          <ErrorBox message={state.refreshError} onRetry={onRetry} />
        </div>
      )}
      {children(state.data)}
    </>
  );
}

// Delays are read once, when the element first appears, so a refetch never replays them.
export function useMountValue<T>(value: T): T {
  const [first] = useState(value);
  return first;
}
