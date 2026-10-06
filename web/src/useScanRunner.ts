import { useCallback, useEffect, useRef, useState } from "react";
import { api, type ScanOut } from "./api";
import { config } from "./config";
import { messageOf } from "./useAsync";

export type RunnerPhase = "idle" | "running" | "completed" | "failed" | "error";

export interface Runner {
  phase: RunnerPhase;
  scan: ScanOut | null;
  message: string | null;
  start: () => void;
  attach: (scan: ScanOut) => void;
}

// Starts a scan, or follows one that is already running, and checks it until it ends.
// The message of a failed scan is the backend's own.
export function useScanRunner(onFinished?: (scan: ScanOut) => void): Runner {
  const [phase, setPhase] = useState<RunnerPhase>("idle");
  const [scan, setScan] = useState<ScanOut | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const alive = useRef(true);
  const finished = useRef(onFinished);
  finished.current = onFinished;

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  const follow = useCallback((first: ScanOut) => {
    if (timer.current) clearTimeout(timer.current);
    const handle = (current: ScanOut) => {
      if (!alive.current) return;
      setScan(current);
      if (current.status === "completed" || current.status === "failed") {
        setPhase(current.status);
        setMessage(current.status === "failed" ? current.failure_message : null);
        finished.current?.(current);
        return;
      }
      setPhase("running");
      timer.current = setTimeout(check, config.scanPollMs);
    };
    const check = () => {
      api.scan(first.id).then(handle, (error) => {
        if (!alive.current) return;
        setPhase("error");
        setMessage(messageOf(error));
      });
    };
    handle(first);
  }, []);

  const start = useCallback(() => {
    setPhase("running");
    setScan(null);
    setMessage(null);
    api.startScan().then(follow, (error) => {
      if (!alive.current) return;
      setPhase("error");
      setMessage(messageOf(error));
    });
  }, [follow]);

  return { phase, scan, message, start, attach: follow };
}
