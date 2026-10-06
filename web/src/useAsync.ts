import { useCallback, useEffect, useRef, useState } from "react";

export type AsyncState<T> =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "success"; data: T; refreshing: boolean; refreshError: string | null };

export function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : "Something went wrong.";
}

// Runs `load` on mount and whenever `deps` change. `reload` runs it again but keeps the data
// that is already on screen, so lists are not rebuilt (and their animations do not replay).
export function useAsync<T>(
  load: () => Promise<T>,
  deps: unknown[] = [],
): [AsyncState<T>, () => void] {
  const [state, setState] = useState<AsyncState<T>>({ status: "loading" });
  const [round, setRound] = useState(0);
  const lastInputs = useRef(JSON.stringify(deps));
  const inputs = JSON.stringify(deps);

  useEffect(() => {
    let current = true;
    const sameInputs = lastInputs.current === inputs;
    lastInputs.current = inputs;
    setState((previous) =>
      sameInputs && previous.status === "success"
        ? { ...previous, refreshing: true, refreshError: null }
        : { status: "loading" },
    );
    load().then(
      (data) =>
        current &&
        setState({ status: "success", data, refreshing: false, refreshError: null }),
      (error) =>
        current &&
        setState((previous) =>
          previous.status === "success"
            ? { ...previous, refreshing: false, refreshError: messageOf(error) }
            : { status: "error", message: messageOf(error) },
        ),
    );
    return () => {
      current = false;
    };
    // `load` is a new function on every render, so only the inputs decide when to run again.
  }, [round, inputs]);

  const reload = useCallback(() => setRound((n) => n + 1), []);
  return [state, reload];
}
