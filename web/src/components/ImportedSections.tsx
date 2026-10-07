import type { ReactNode } from "react";
import { api } from "../api";
import { formatDate, formatRelative } from "../format";
import { shortResource } from "../lanes";
import { useAsync } from "../useAsync";
import { Icon, iconForResource } from "./Icon";
import { AsyncView, EmptyState, SectionTitle } from "./ui";

export const IMPORTED_RESOURCES_GRID =
  "grid grid-cols-[minmax(0,1fr)_168px_144px_120px_120px] items-center gap-4";

export const IMPORTS_GRID =
  "grid grid-cols-[minmax(0,1.4fr)_96px_minmax(0,1.2fr)_72px_72px_96px_96px_96px] items-center gap-4";

const heading = "text-label font-semibold";

function Box({
  label,
  minWidth,
  children,
}: {
  label: string;
  minWidth: string;
  children: ReactNode;
}) {
  return (
    <div className="max-h-[75vh] overflow-auto rounded-lane border-2 border-ink bg-white">
      <div role="table" aria-label={label} className={minWidth}>
        {children}
      </div>
    </div>
  );
}

// Resources that only an imported scan told us about. CloudShield did not scan them.
export function ImportedResources() {
  const [state, reload] = useAsync(() => api.importedResources());
  return (
    <section aria-label="Seen only in imports" className="mt-16">
      <SectionTitle>Seen only in imports</SectionTitle>
      <p className="mt-1 mb-6 text-secondary text-dim">Not scanned by CloudShield.</p>
      <AsyncView
        state={state}
        onRetry={reload}
        label="Loading imported resources"
        shape="table"
      >
        {(resources) =>
          resources.length === 0 ? (
            <EmptyState title="Nothing here">
              Every resource in an imported file is also one CloudShield scanned.
            </EmptyState>
          ) : (
            <Box label="Seen only in imports" minWidth="min-w-[760px]">
              <div
                role="row"
                data-testid="imported-resources-header"
                className={`${IMPORTED_RESOURCES_GRID} sticky top-0 z-10 border-b border-ink bg-white px-4 py-3`}
              >
                {["Resource", "Type", "Region", "Open findings", "Highest risk"].map(
                  (name) => (
                    <span key={name} role="columnheader" className={heading}>
                      {name}
                    </span>
                  ),
                )}
              </div>
              {resources.map((r) => (
                <div
                  key={r.resource_id}
                  role="row"
                  className={`${IMPORTED_RESOURCES_GRID} border-t border-divider px-4 py-3 text-secondary first:border-t-0`}
                >
                  <span
                    role="cell"
                    className="min-w-0 truncate font-mono text-label"
                    title={r.resource_id}
                  >
                    {shortResource(r.resource_id)}
                  </span>
                  <span role="cell" className="flex items-center gap-2">
                    <Icon name={iconForResource(r.resource_type)} size={18} />
                    {r.resource_type}
                  </span>
                  <span role="cell">{r.region ?? "global"}</span>
                  <span role="cell" className="font-semibold tabular-nums">
                    {r.open_count === 0 ? "-" : r.open_count}
                  </span>
                  <span role="cell" className="font-semibold tabular-nums">
                    {r.highest_risk ?? "-"}
                  </span>
                </div>
              ))}
            </Box>
          )
        }
      </AsyncView>
    </section>
  );
}

const count = (value: number | null) => (value === null ? "-" : value);

// Every file that was imported, newest first.
export function ImportHistory() {
  const [state, reload] = useAsync(() => api.imports());
  return (
    <section aria-label="Imports" className="mt-16">
      <SectionTitle>Imports</SectionTitle>
      <p className="mt-1 mb-6 text-secondary text-dim">
        Results files you imported from another scanner.
      </p>
      <AsyncView state={state} onRetry={reload} label="Loading imports" shape="table">
        {(imports) =>
          imports.length === 0 ? (
            <EmptyState title="No file has been imported yet" />
          ) : (
            <Box label="Imports" minWidth="min-w-[960px]">
              <div
                role="row"
                data-testid="imports-header"
                className={`${IMPORTS_GRID} sticky top-0 z-10 border-b border-ink bg-white px-4 py-3`}
              >
                {[
                  "File",
                  "Version",
                  "Imported",
                  "Pass",
                  "Fail",
                  "Added",
                  "Resolved",
                  "Rejected",
                ].map((name) => (
                  <span key={name} role="columnheader" className={heading}>
                    {name}
                  </span>
                ))}
              </div>
              {imports.map((item) => (
                <div
                  key={item.id}
                  role="row"
                  className={`${IMPORTS_GRID} border-t border-divider px-4 py-3 text-secondary first:border-t-0`}
                >
                  <span
                    role="cell"
                    className="min-w-0 truncate font-mono text-label"
                    title={item.file_name ?? undefined}
                  >
                    {item.file_name ?? "-"}
                  </span>
                  <span role="cell">{item.tool_version ?? "-"}</span>
                  <span role="cell" title={formatDate(item.imported_at)}>
                    <span className="block font-semibold">
                      {formatDate(item.imported_at)}
                    </span>
                    <span className="block text-label text-dim">
                      {formatRelative(item.imported_at)}
                    </span>
                  </span>
                  <span role="cell" className="tabular-nums">
                    {count(item.pass_count)}
                  </span>
                  <span role="cell" className="tabular-nums">
                    {count(item.fail_count)}
                  </span>
                  <span role="cell" className="tabular-nums">
                    {item.findings_added}
                  </span>
                  <span role="cell" className="tabular-nums">
                    {item.resolved}
                  </span>
                  <span role="cell" className="tabular-nums">
                    {item.rejected}
                  </span>
                </div>
              ))}
            </Box>
          )
        }
      </AsyncView>
    </section>
  );
}
