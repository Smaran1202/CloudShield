import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
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
    let failures = 0;
    let timer: ReturnType<typeof setTimeout>;
    // One failed check is not enough to say the API is offline: it must fail twice in a row.
    // A single success brings it back at once.
    const check = () =>
      api
        .health()
        .then(
          (result) => {
            failures = 0;
            if (current) setHealth({ state: "online", version: result.version });
          },
          () => {
            failures += 1;
            if (current && failures >= 2) setHealth({ state: "offline" });
          },
        )
        .finally(() => {
          if (current) {
            timer = setTimeout(
              check,
              failures > 0 ? config.healthRetryMs : config.healthPollMs,
            );
          }
        });
    check();
    return () => {
      current = false;
      clearTimeout(timer);
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
    // Online and checking are read out to screen readers but not drawn: only a problem shows.
    <p
      role="status"
      className={`flex items-center gap-2 font-mono text-label ${
        health.state === "offline" ? "" : "sr-only"
      }`}
    >
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
      className={`inline-flex min-h-10 items-center rounded-chip border border-ink px-3 font-mono text-label ${
        flash ? "chip-flash" : "bg-white"
      }`}
    >
      {scanChipText(latest)}
    </Link>
  );
}

const PILL =
  "relative z-10 inline-flex h-10 items-center rounded-full px-4 text-body font-semibold";
const PILL_IDLE = "text-dim hover:bg-pill-hover hover:text-ink active:bg-pill-press";

// One oval sits behind the active item and slides to the new one. The links stay plain links:
// the page is told apart by aria-current, never by the oval alone.
function MainNav() {
  const { pathname } = useLocation();
  const nav = useRef<HTMLElement>(null);
  const [oval, setOval] = useState<{ x: number; y: number; width: number } | null>(null);

  useLayoutEffect(() => {
    const place = () => {
      const active = nav.current?.querySelector<HTMLElement>('[aria-current="page"]');
      setOval(
        active
          ? { x: active.offsetLeft, y: active.offsetTop, width: active.offsetWidth }
          : null,
      );
    };
    place();
    window.addEventListener("resize", place);
    void document.fonts?.ready.then(place);
    return () => window.removeEventListener("resize", place);
  }, [pathname]);

  return (
    <nav ref={nav} aria-label="Main" className="relative flex flex-wrap gap-x-1 gap-y-1">
      <span
        aria-hidden="true"
        hidden={!oval}
        data-testid="nav-oval"
        className="nav-oval absolute top-0 left-0 h-10 rounded-full bg-ink"
        style={{
          width: oval?.width,
          transform: `translate(${oval?.x ?? 0}px, ${oval?.y ?? 0}px)`,
        }}
      />
      {NAV.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.end}
          className={({ isActive }) => `${PILL} ${isActive ? "text-white" : PILL_IDLE}`}
        >
          {item.label}
        </NavLink>
      ))}
    </nav>
  );
}

function Header() {
  const { runner } = useScans();
  return (
    <header className="sticky top-0 z-20 border-b border-ink bg-paper">
      <Container className="flex flex-wrap items-center justify-between gap-x-4 gap-y-3 py-3">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
          <Link
            to="/"
            className="font-display text-wordmark leading-none font-extrabold tracking-[-0.03em]"
          >
            cloudshield
          </Link>
          <MainNav />
        </div>
        <div className="flex w-full flex-wrap items-center justify-between gap-x-4 gap-y-2 min-[1100px]:ml-auto min-[1100px]:w-auto min-[1100px]:justify-end">
          <ApiStatus />
          <LastScanChip />
          <RunScanButton runner={runner} />
        </div>
      </Container>
      {runner.phase === "running" && <ScanBar />}
    </header>
  );
}

// Demo data says what it is on every page, for as long as the newest scan is demo data.
function DataLabel() {
  const { scans } = useScans();
  const label = scans.status === "success" ? scans.data[0]?.data_label : null;
  if (!label) return null;
  return (
    <p
      role="note"
      className="border-b border-ink bg-lane-grey px-4 py-2 text-center text-secondary font-semibold text-ink"
    >
      {label}
    </p>
  );
}

function Shell() {
  const { runner } = useScans();
  return (
    <div className="min-h-screen bg-paper">
      <Header />
      <DataLabel />
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
