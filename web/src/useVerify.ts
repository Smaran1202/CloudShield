import { useEffect, useRef, useState } from "react";
import { api } from "./api";
import { useScans } from "./ScanContext";
import { messageOf } from "./useAsync";

export type VerifyState =
  | { phase: "idle" }
  | { phase: "scanning" }
  | { phase: "resolved"; fixed: number; toGo: number }
  | { phase: "open" }
  // The check did not run in that scan, so nothing can be said about the finding.
  | { phase: "not_rechecked"; message: string }
  | { phase: "failed"; message: string };

// "Rescan to verify": start a scan, wait for it to end, fetch the finding again, and only then
// decide. Nothing is celebrated unless the fetched finding is RESOLVED.
export function useVerify(findingId: string, onChecked: () => void) {
  const { runner, finished, lastFinished } = useScans();
  const [state, setState] = useState<VerifyState>({ phase: "idle" });
  const waiting = useRef(false);
  const extended = useRef(false);
  const seen = useRef(finished);
  const checked = useRef(onChecked);
  checked.current = onChecked;

  useEffect(() => {
    waiting.current = false;
    setState({ phase: "idle" });
  }, [findingId]);

  // `withExtended` runs the extended checks too, which is the only way an imported finding can
  // be checked again.
  function start(withExtended = false) {
    waiting.current = true;
    extended.current = withExtended;
    setState({ phase: "scanning" });
    runner.start(withExtended);
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
    const ran = lastFinished;
    Promise.all([api.finding(findingId), api.findings()]).then(
      ([fresh, all]) => {
        checked.current();
        if (fresh.status === "RESOLVED") {
          const fixed = all.filter((f) => f.status === "RESOLVED").length;
          setState({ phase: "resolved", fixed, toGo: all.length - fixed });
        } else if (extended.current && ran.extended_status !== "ok") {
          const why = ran.extended_message ?? "The extended checks did not run.";
          setState({ phase: "not_rechecked", message: why });
        } else if (extended.current && fresh.not_rechecked) {
          setState({
            phase: "not_rechecked",
            message: "This check did not run in that scan, so the result is not known.",
          });
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
