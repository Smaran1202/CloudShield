import { useCallback, useEffect, useRef, useState } from "react";
import { api, type FixOut } from "./api";
import { messageOf } from "./useAsync";

export type FixState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "success"; fix: FixOut };

// The fix is only requested when generate() is called, never on its own.
export function useFixRequest(findingId: string) {
  const [state, setState] = useState<FixState>({ status: "idle" });
  const latest = useRef(findingId);

  useEffect(() => {
    latest.current = findingId;
    setState({ status: "idle" });
  }, [findingId]);

  const generate = useCallback(
    (refresh = false) => {
      setState({ status: "loading" });
      api.generateFix(findingId, refresh).then(
        (fix) => latest.current === findingId && setState({ status: "success", fix }),
        (error) =>
          latest.current === findingId &&
          setState({ status: "error", message: messageOf(error) }),
      );
    },
    [findingId],
  );

  return { state, generate };
}
