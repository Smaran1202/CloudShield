import { useEffect, useState } from "react";
import { Link, NavLink, Outlet } from "react-router-dom";
import { api } from "../api";
import { config } from "../config";
import { scanChipText } from "../format";
import { ScanProvider, useScans } from "../ScanContext";
import { RunScanButton, ScanBar, ScanStatusLine } from "./ScanControl";
import { Container } from "./ui";

type Health =
  { state: "checking" } | { state: "online"; version: string } | { state: "offline" };

const NAV = [
  { to: "/", label: "Overview", end: true },
  { to: "/findings", label: "Findings", end: false },
  { to: "/resources", label: "Resources", end: false },
  { to: "/scans", label: "Scans", end: false },
];

function ApiStatus() {
  const [health, setHealth] = useState<Health>({ state: "checking" });

  useEffect(() => {
    let current = true;
    const check = () =>
      api.health().then(
        (result) => current && setHealth({ state: "online", version: result.version }),
        () => current && setHealth({ state: "offline" }),
      );
    check();
    const timer = setInterval(check, config.healthPollMs);
    return () => {
      current = false;
      clearInterval(timer);
    };
  }, []);

  const text =
    health.state === "online"
      ? `API online v${health.version}`
      : health.state === "offline"
        ? "API offline"
        : "Checking API...";
  const dot =
    health.state === "online"
      ? "bg-green"
      : health.state === "offline"
        ? "bg-red"
        : "bg-later-dot";

  return (
    <p role="status" className="flex items-center gap-2 font-mono text-label">
      <span aria-hidden="true" className={`h-2.5 w-2.5 rounded-full ${dot}`} />
      {text}
    </p>
  );
}

function LastScanChip() {
  const { scans, flash } = useScans();
  const latest = scans.status === "success" ? scans.data[0] : undefined;
  if (!latest) return null;
  return (
    <Link
      to="/scans"
      data-flash={flash}
      className={`inline-flex min-h-11 items-center rounded-chip border-2 border-ink px-3 font-mono text-label ${
        flash ? "chip-flash" : "bg-white"
      }`}
    >
      {scanChipText(latest)}
    </Link>
  );
}

function Header() {
  const { runner } = useScans();
  return (
    <header className="sticky top-0 z-20 border-b border-ink bg-paper">
      <Container className="flex flex-wrap items-center justify-between gap-x-8 gap-y-3 py-3">
        <div className="flex flex-wrap items-center gap-x-12 gap-y-2">
          <Link
            to="/"
            className="font-display text-wordmark leading-none font-extrabold tracking-[-0.03em]"
          >
            cloudshield
          </Link>
          <nav aria-label="Main" className="flex flex-wrap gap-x-6">
            {NAV.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  `inline-flex min-h-11 items-center border-b-[3px] text-body font-semibold ${
                    isActive ? "border-ink" : "border-transparent text-dim hover:text-ink"
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
        </div>
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
          <ApiStatus />
          <LastScanChip />
          <RunScanButton runner={runner} />
        </div>
      </Container>
      {runner.phase === "running" && <ScanBar />}
    </header>
  );
}

function Shell() {
  const { runner } = useScans();
  return (
    <div className="min-h-screen bg-paper">
      <Header />
      <Container className="py-8">
        <div aria-live="polite" className="text-secondary text-dim [&>p]:mb-4">
          <ScanStatusLine runner={runner} />
        </div>
        <main>
          <Outlet />
        </main>
      </Container>
    </div>
  );
}

export function Layout() {
  return (
    <ScanProvider>
      <Shell />
    </ScanProvider>
  );
}
