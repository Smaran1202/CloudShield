import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { api, type ScanOut } from "./api";
import { useAsync, type AsyncState } from "./useAsync";
import { useScanRunner, type Runner } from "./useScanRunner";

interface ScanContextValue {
  scans: AsyncState<ScanOut[]>;
  reloadScans: () => void;
  runner: Runner;
  // Counts up each time a scan ends, so pages know to fetch their data again.
  finished: number;
  lastFinished: ScanOut | null;
  // True for a moment after a scan completes.
  flash: boolean;
}

const ScanContext = createContext<ScanContextValue | null>(null);

export const FLASH_MS = 1400;

// One scan runner for the whole app: the header button, the progress bar and the
// "Rescan to verify" panel all follow the same scan.
export function ScanProvider({ children }: { children: ReactNode }) {
  const [scans, reloadScans] = useAsync(() => api.scans());
  const [finished, setFinished] = useState(0);
  const [lastFinished, setLastFinished] = useState<ScanOut | null>(null);
  const [flash, setFlash] = useState(false);
  const flashTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const runner = useScanRunner((scan) => {
    setLastFinished(scan);
    setFinished((n) => n + 1);
    reloadScans();
    if (scan.status === "completed") {
      setFlash(true);
      if (flashTimer.current) clearTimeout(flashTimer.current);
      flashTimer.current = setTimeout(() => setFlash(false), FLASH_MS);
    }
  });

  useEffect(
    () => () => {
      if (flashTimer.current) clearTimeout(flashTimer.current);
    },
    [],
  );

  // A scan that is already running when the app opens is followed, not started again.
  const running =
    scans.status === "success"
      ? scans.data.find((s) => s.status === "queued" || s.status === "running")
      : undefined;
  useEffect(() => {
    if (running && runner.phase === "idle") runner.attach(running);
  }, [running?.id]);

  return (
    <ScanContext.Provider
      value={{ scans, reloadScans, runner, finished, lastFinished, flash }}
    >
      {children}
    </ScanContext.Provider>
  );
}

export function useScans(): ScanContextValue {
  const value = useContext(ScanContext);
  if (!value) throw new Error("useScans must be used inside ScanProvider");
  return value;
}

// Fetch again, without blanking the page, each time a scan ends.
export function useRefreshWhenScanEnds(reload: () => void): void {
  const { finished } = useScans();
  const seen = useRef(finished);
  useEffect(() => {
    if (finished !== seen.current) {
      seen.current = finished;
      reload();
    }
  }, [finished]);
}
