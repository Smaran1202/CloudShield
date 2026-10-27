import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import { api, MAX_IMPORT_BYTES, type ImportResultOut } from "../api";
import { useAsync, messageOf } from "../useAsync";
import { CopyButton } from "./CopyButton";
import { SECONDARY_BUTTON, Spinner } from "./ui";

const FOCUSABLE =
  'button:not([disabled]), input:not([disabled]), [href], [tabindex]:not([tabindex="-1"])';
const LIMIT_TEXT = "50 MB";

type Upload =
  | { phase: "idle" }
  | { phase: "uploading"; name: string }
  | { phase: "done"; result: ImportResultOut }
  | { phase: "error"; message: string };

// What the user can check before anything is sent. The API checks again.
function problemWith(file: File): string | null {
  if (!file.name.toLowerCase().endsWith(".json"))
    return "This is not a .json file. Choose the results file that ends in .ocsf.json.";
  if (file.size > MAX_IMPORT_BYTES)
    return `This file is over ${LIMIT_TEXT}, which is too large to import.`;
  return null;
}

function CommandRow({ text, label }: { text: string; label: string }) {
  return (
    <div className="flex items-start gap-2 rounded-chip border-[1.5px] border-ink bg-white pl-3">
      <code className="min-w-0 flex-1 py-3 font-mono text-label break-all">{text}</code>
      <CopyButton text={text} label={label} />
    </div>
  );
}

// Keeps Tab inside the dialog, and closes it on Escape.
function trapFocus(event: KeyboardEvent<HTMLElement>, onEscape: () => void) {
  if (event.key === "Escape") {
    onEscape();
    return;
  }
  if (event.key !== "Tab") return;
  const items = Array.from(event.currentTarget.querySelectorAll<HTMLElement>(FOCUSABLE));
  if (items.length === 0) return;
  const first = items[0];
  const last = items[items.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

// Guides the user to run the second scanner somewhere it works, and imports its results file.
// Nothing is sent until a file is chosen, and there is no percentage: the API gives none.
export function ImportDialog({
  onClose,
  onImported,
}: {
  onClose: () => void;
  onImported: () => void;
}) {
  const titleId = useId();
  const dialog = useRef<HTMLDivElement>(null);
  const picker = useRef<HTMLInputElement>(null);
  const [status] = useAsync(() => api.extendedStatus());
  const [upload, setUpload] = useState<Upload>({ phase: "idle" });
  const [dragging, setDragging] = useState(false);
  const uploading = upload.phase === "uploading";

  // Focus moves into the dialog, and goes back to what opened it when it closes.
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    dialog.current?.focus();
    return () => opener?.focus?.();
  }, []);

  async function send(file: File) {
    const problem = problemWith(file);
    if (problem) {
      setUpload({ phase: "error", message: problem });
      return;
    }
    setUpload({ phase: "uploading", name: file.name });
    try {
      const result = await api.uploadImport(file);
      setUpload({ phase: "done", result });
      onImported();
    } catch (error) {
      setUpload({ phase: "error", message: messageOf(error) });
    }
  }

  function chosen(files: FileList | null) {
    const file = files?.[0];
    if (file && !uploading) void send(file);
  }

  const commands = status.status === "success" ? status.data : null;

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-ink/60 p-4">
      <div
        ref={dialog}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        onKeyDown={(event) => trapFocus(event, () => !uploading && onClose())}
        className="max-h-full w-full max-w-2xl overflow-auto rounded-lane border-2 border-ink bg-paper p-6 outline-none"
      >
        <h2 id={titleId} className="font-display text-h3 leading-tight font-extrabold">
          Import a results file
        </h2>
        <p className="mt-2 text-secondary text-dim">
          Nothing in this file leaves your computer. CloudShield never changes your AWS
          account.
        </p>

        <section aria-labelledby={`${titleId}-1`} className="mt-6">
          <h3 id={`${titleId}-1`} className="text-label font-semibold">
            Step 1. Run Prowler where it works, for example AWS CloudShell
          </h3>
          <div className="mt-2 space-y-2">
            <CommandRow
              text={commands?.install_command ?? "pip install prowler"}
              label="Copy the install command"
            />
            {commands?.run_command ? (
              <CommandRow text={commands.run_command} label="Copy the run command" />
            ) : (
              <p className="text-secondary text-dim">
                {status.status === "loading"
                  ? "Loading the run command..."
                  : "The run command is built from the region set on the server. Set AWS_REGION there and open this window again."}
              </p>
            )}
          </div>
          <p className="mt-2 text-secondary text-dim">
            When it ends, download the file that ends in .ocsf.json from the prowler-out
            folder.
          </p>
        </section>

        <section aria-labelledby={`${titleId}-2`} className="mt-6">
          <h3 id={`${titleId}-2`} className="text-label font-semibold">
            Step 2. Choose the results file
          </h3>
          <div
            data-testid="drop-zone"
            onDragOver={(event) => {
              event.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(event) => {
              event.preventDefault();
              setDragging(false);
              chosen(event.dataTransfer.files);
            }}
            className={`mt-2 flex flex-col items-start gap-3 rounded-lane border-2 border-dashed border-ink p-4 ${
              dragging ? "bg-lane-grey" : "bg-white"
            }`}
          >
            <p className="text-secondary">Drop the file here, or choose it.</p>
            <input
              ref={picker}
              type="file"
              accept=".json,application/json"
              aria-label="Results file"
              className="sr-only"
              tabIndex={-1}
              onChange={(event) => {
                chosen(event.target.files);
                event.target.value = "";
              }}
            />
            <button
              type="button"
              className={SECONDARY_BUTTON}
              disabled={uploading}
              onClick={() => picker.current?.click()}
            >
              Choose a file
            </button>
            <p className="text-secondary text-dim">
              Only .json files, up to {LIMIT_TEXT}.
            </p>
          </div>
        </section>

        <section aria-labelledby={`${titleId}-3`} className="mt-6">
          <h3 id={`${titleId}-3`} className="text-label font-semibold">
            Step 3. Result
          </h3>
          <div className="mt-2 min-h-8 text-secondary" aria-live="polite">
            {upload.phase === "idle" && (
              <p className="text-dim">Nothing has been imported yet.</p>
            )}
            {upload.phase === "uploading" && (
              <p className="flex items-center gap-2">
                <Spinner />
                Importing {upload.name}...
              </p>
            )}
            {upload.phase === "done" && (
              <p role="status" className="font-semibold">
                Imported {upload.result.counts.imported}, {upload.result.counts.passed}{" "}
                passed, {upload.result.counts.resolved} resolved
              </p>
            )}
            {upload.phase === "error" && (
              <p role="alert" className="font-semibold text-red">
                {upload.message}
              </p>
            )}
          </div>
        </section>

        <div className="mt-6 flex flex-wrap gap-3">
          <button
            type="button"
            className={SECONDARY_BUTTON}
            disabled={uploading}
            onClick={onClose}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
