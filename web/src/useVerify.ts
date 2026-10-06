import { useEffect, useRef, useState } from "react";
import { api } from "./api";
import { useScans } from "./ScanContext";
import { messageOf } from "./useAsync";

export type VerifyState =
  | { phase: "idle" }
  | { phase: "scanning" }
  | { phase: "resolved"; fixed: number; toGo: number }
  | { phase: "open" }
  | { phase: "failed"; message: string };

// "Rescan to verify": start a scan, wait for it to end, fetch the finding again, and only then
// decide. Nothing is celebrated unless the fetched finding is RESOLVED.
export function useVerify(findingId: string, onChecked: () => void) {
  const { runner, finished, lastFinished } = useScans();
  const [state, setState] = useState<VerifyState>({ phase: "idle" });
  const waiting = useRef(false);
  const seen = useRef(finished);
  const checked = useRef(onChecked);
  checked.current = onChecked;

  useEffect(() => {
    waiting.current = false;
    setState({ phase: "idle" });
  }, [findingId]);

  function start() {
    waiting.current = true;
    setState({ phase: "scanning" });
    runner.start();
  }

  // The scan could not start, or contact with the API was lost while it ran.
  useEffect(() => {
    if (waiting.current && runner.phase === "error") {
      waiting.current = false;
      setState({ phase: "failed", message: runner.message ?? "The scan could not run." });
    }
  }, [runner.phase, runner.message]);

  useEffect(() => {
    if (finished === seen.current) return;
    seen.current = finished;
    if (!waiting.current || !lastFinished) return;
    waiting.current = false;
    if (lastFinished.status === "failed") {
      setState({
        phase: "failed",
        message: lastFinished.failure_message ?? "The scan failed.",
      });
      return;
    }
    Promise.all([api.finding(findingId), api.findings()]).then(
      ([fresh, all]) => {
        checked.current();
        if (fresh.status === "RESOLVED") {
          const fixed = all.filter((f) => f.status === "RESOLVED").length;
          setState({ phase: "resolved", fixed, toGo: all.length - fixed });
        } else {
          setState({ phase: "open" });
        }
      },
      (error) => setState({ phase: "failed", message: messageOf(error) }),
    );
  }, [finished]);

  return { state, start };
}

export type Verify = ReturnType<typeof useVerify>;
