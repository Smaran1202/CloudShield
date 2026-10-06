import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import {
  AsyncView,
  Card,
  EmptyState,
  SectionTitle,
  SeverityChip,
  StatusChip,
} from "../components/ui";
import { pretty } from "../format";
import { shortResource } from "../lanes";
import { useAsync } from "../useAsync";

// There is no endpoint for one resource, so the list is loaded and the right one picked.
export function ResourceDetail() {
  const { resourceId = "" } = useParams();
  const [state, reload] = useAsync(async () => {
    const [resources, findings] = await Promise.all([api.resources(), api.findings()]);
    return {
      resource: resources.find((r) => r.resource_id === resourceId) ?? null,
      findings: findings.filter((f) => f.resource_id === resourceId),
    };
  }, [resourceId]);

  return (
    <AsyncView state={state} onRetry={reload} label="Loading resource">
      {({ resource, findings }) =>
        resource === null ? (
          <>
            <Crumb />
            <EmptyState title="This resource is not in the stored data">
              <span className="break-all">{resourceId}</span>
            </EmptyState>
          </>
        ) : (
          <>
            <Crumb />
            <header className="rise mb-8">
              <h1 className="font-display text-detail leading-none font-extrabold tracking-[-0.03em]">
                {resource.name}
              </h1>
              <p
                className="mt-3 font-mono text-secondary text-dim"
                title={resource.resource_id}
              >
                {resource.resource_type}, {resource.region ?? "global"},{" "}
                {shortResource(resource.resource_id)}
              </p>
            </header>
            <div className="space-y-6">
              <Card>
                <SectionTitle>Stored attributes</SectionTitle>
                <p className="mt-2 mb-4 text-secondary break-all text-dim">
                  {resource.resource_id}, last seen in scan {resource.last_seen_scan_id}.
                  A missing attribute means a call failed, so it is unknown, not off.
                </p>
                {Object.keys(resource.attributes).length === 0 ? (
                  <p className="text-secondary">No attributes were stored.</p>
                ) : (
                  <dl className="space-y-4">
                    {Object.entries(resource.attributes).map(([key, value]) => (
                      <div key={key}>
                        <dt className="font-mono text-secondary font-medium">{key}</dt>
                        <dd>
                          <pre className="mt-1 overflow-x-auto rounded-chip bg-paper p-3 font-mono text-label">
                            {pretty(value)}
                          </pre>
                        </dd>
                      </div>
                    ))}
                  </dl>
                )}
              </Card>
              <Card>
                <SectionTitle>Findings on this resource</SectionTitle>
                {findings.length === 0 ? (
                  <p className="mt-3 text-secondary">No findings.</p>
                ) : (
                  <ul className="mt-3 divide-y-2 divide-divider">
                    {findings.map((f) => (
                      <li
                        key={f.finding_id}
                        className="flex flex-wrap items-center gap-3 py-3"
                      >
                        <SeverityChip severity={f.severity} />
                        <StatusChip status={f.status} />
                        <Link
                          to={`/findings/${encodeURIComponent(f.finding_id)}`}
                          className="font-display text-title font-bold underline"
                        >
                          {f.title}
                        </Link>
                      </li>
                    ))}
                  </ul>
                )}
              </Card>
            </div>
          </>
        )
      }
    </AsyncView>
  );
}

function Crumb() {
  return (
    <nav aria-label="Breadcrumb" className="mb-4 font-mono text-secondary text-dim">
      <Link to="/resources" className="font-semibold text-ink underline">
        Resources
      </Link>{" "}
      / detail
    </nav>
  );
}
