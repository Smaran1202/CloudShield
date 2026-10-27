import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { callsTo, fail } from "../test/mockApi";
import { never, renderApp } from "../test/render";

const INSTALL = "pip install prowler";
const RUN =
  "prowler aws -f ap-southeast-2 --services s3 ec2 iam -M json-ocsf -o prowler-out -b -z";
const READY = {
  available: true,
  version: "Prowler 5.44.0",
  reason: null,
  hint: null,
  blocked: false,
  install_command: INSTALL,
  run_command: RUN,
};
const BLOCKED = {
  available: false,
  version: null,
  reason: "This computer's security policy blocked Prowler from starting.",
  hint: "This computer blocks Prowler. Run it elsewhere, for example in AWS CloudShell, then import the file here.",
  blocked: true,
  install_command: INSTALL,
  run_command: RUN,
};
const RESULT = {
  import_id: 1,
  counts: {
    imported: 2,
    passed: 1,
    ignored: 0,
    already_seen: 0,
    resolved: 3,
    rejected: 0,
  },
};

function resultsFile(name = "results.ocsf.json") {
  return new File(["[]"], name, { type: "application/json" });
}

async function openFromMenu(routes: Record<string, unknown> = {}) {
  const user = renderApp("/scans", { "GET /api/extended/status": READY, ...routes });
  await user.click(await screen.findByRole("button", { name: "More ways to scan" }));
  await user.click(screen.getByRole("menuitem", { name: /Import a results file/ }));
  const dialog = await screen.findByRole("dialog", { name: "Import a results file" });
  return { user, dialog };
}

function fileInput() {
  return screen.getByLabelText("Results file") as HTMLInputElement;
}

describe("Import a results file: opening it", () => {
  it("opens from the Run scan menu and closes the menu", async () => {
    await openFromMenu();

    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("opens from the button above the Imports table", async () => {
    const user = renderApp("/scans", { "GET /api/extended/status": READY });

    const section = await screen.findByRole("region", { name: "Imports" });
    await user.click(
      within(section).getByRole("button", { name: "Import a results file" }),
    );

    expect(
      await screen.findByRole("dialog", { name: "Import a results file" }),
    ).toBeInTheDocument();
  });

  it("says that nothing leaves the computer and that the account is never changed", async () => {
    const { dialog } = await openFromMenu();

    expect(dialog).toHaveTextContent(
      "Nothing in this file leaves your computer. CloudShield never changes your AWS account.",
    );
  });
});

describe("Import a results file: when the full scan is blocked", () => {
  it("keeps the full scan disabled, shows the hint and a button that opens the dialog", async () => {
    const user = renderApp("/scans", { "GET /api/extended/status": BLOCKED });
    await user.click(await screen.findByRole("button", { name: "More ways to scan" }));

    const full = await screen.findByRole("menuitem", { name: /Run full scan/ });
    const note = await screen.findByRole("note");

    expect(full).toBeDisabled();
    expect(note).toHaveTextContent(
      "This computer blocks Prowler. Run it elsewhere, for example in AWS CloudShell, then import the file here.",
    );
    await user.click(within(note).getByRole("button", { name: "Import a results file" }));
    expect(
      await screen.findByRole("dialog", { name: "Import a results file" }),
    ).toBeInTheDocument();
  });

  it("shows no import button in the note when the reason is something else", async () => {
    const user = renderApp("/scans", {
      "GET /api/extended/status": {
        ...BLOCKED,
        blocked: false,
        hint: "Set PROWLER_PYTHON.",
      },
    });
    await user.click(await screen.findByRole("button", { name: "More ways to scan" }));

    const note = await screen.findByRole("note");

    expect(within(note).queryByRole("button")).not.toBeInTheDocument();
  });
});

describe("Import a results file: step 1, the commands", () => {
  it("shows the install and run commands exactly as the API built them", async () => {
    const { dialog } = await openFromMenu();

    expect(await within(dialog).findByText(RUN)).toBeInTheDocument();
    expect(within(dialog).getByText(INSTALL)).toBeInTheDocument();
    expect(dialog).toHaveTextContent("AWS CloudShell");
  });

  it("has copy buttons that copy each command", async () => {
    const { user, dialog } = await openFromMenu();
    await within(dialog).findByText(RUN);
    const writeText = vi.spyOn(navigator.clipboard, "writeText");

    await user.click(
      within(dialog).getByRole("button", { name: "Copy the install command" }),
    );
    await user.click(
      within(dialog).getByRole("button", { name: "Copy the run command" }),
    );

    expect(writeText).toHaveBeenNthCalledWith(1, INSTALL);
    expect(writeText).toHaveBeenNthCalledWith(2, RUN);
  });

  it("says how to get the run command when the server has no region", async () => {
    const { dialog } = await openFromMenu({
      "GET /api/extended/status": { ...READY, run_command: null },
    });

    expect(await within(dialog).findByText(/Set AWS_REGION there/)).toBeInTheDocument();
    expect(
      within(dialog).queryByRole("button", { name: "Copy the run command" }),
    ).not.toBeInTheDocument();
  });
});

describe("Import a results file: steps 2 and 3, the file and the result", () => {
  it("shows the size limit and accepts only .json", async () => {
    const { dialog } = await openFromMenu();

    expect(dialog).toHaveTextContent("up to 50 MB");
    expect(fileInput()).toHaveAttribute("accept", ".json,application/json");
  });

  it("sends the chosen file as it is, with its encoded name, and shows the counts", async () => {
    const { user, dialog } = await openFromMenu({ "POST /api/imports/prowler": RESULT });

    await user.upload(fileInput(), resultsFile("my results.ocsf.json"));

    expect(
      await within(dialog).findByText("Imported 2, 1 passed, 3 resolved"),
    ).toBeInTheDocument();
    const [call] = callsTo("POST", "/api/imports/prowler");
    expect(call.bodyIsFile).toBe(true);
    expect(call.headers["content-type"]).toBe("application/json");
    expect(call.headers["x-filename"]).toBe("my%20results.ocsf.json");
  });

  it("accepts a file dropped on the drop zone", async () => {
    const { dialog } = await openFromMenu({ "POST /api/imports/prowler": RESULT });

    fireEvent.drop(screen.getByTestId("drop-zone"), {
      dataTransfer: { files: [resultsFile()] },
    });

    expect(await within(dialog).findByText(/^Imported 2, /)).toBeInTheDocument();
    expect(callsTo("POST", "/api/imports/prowler")).toHaveLength(1);
  });

  it("shows a spinner and no percentage while the file is being sent", async () => {
    const { user, dialog } = await openFromMenu({ "POST /api/imports/prowler": never });

    await user.upload(fileInput(), resultsFile());

    expect(
      await within(dialog).findByText(/Importing results.ocsf.json/),
    ).toBeInTheDocument();
    expect(dialog).not.toHaveTextContent("%");
    expect(within(dialog).getByRole("button", { name: "Close" })).toBeDisabled();
    expect(within(dialog).getByRole("button", { name: "Choose a file" })).toBeDisabled();
  });

  it.each([
    [409, "This file was already imported (import 3, 2026-10-01 10:00 UTC)."],
    [413, "The file is over 50 MB, which is too large."],
    [422, "The file is not valid JSON (Expecting value at line 1)."],
  ])("shows the API's message when it answers %i", async (status, message) => {
    const { user, dialog } = await openFromMenu({
      "POST /api/imports/prowler": fail(status, message),
    });

    await user.upload(fileInput(), resultsFile());

    expect(await within(dialog).findByRole("alert")).toHaveTextContent(message);
    expect(within(dialog).getByRole("button", { name: "Close" })).toBeEnabled();
  });

  it("says so when the API cannot be reached", async () => {
    const { user, dialog } = await openFromMenu({
      "POST /api/imports/prowler": () => {
        throw new TypeError("Failed to fetch");
      },
    });

    await user.upload(fileInput(), resultsFile());

    expect(await within(dialog).findByRole("alert")).toBeInTheDocument();
  });

  it("refuses a file that is not .json without sending it", async () => {
    const { dialog } = await openFromMenu();

    fireEvent.change(fileInput(), {
      target: { files: [new File(["x"], "notes.txt", { type: "text/plain" })] },
    });

    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "not a .json file",
    );
    expect(callsTo("POST", "/api/imports/prowler")).toHaveLength(0);
  });

  it("refuses a file over the limit without sending it", async () => {
    const { dialog } = await openFromMenu();
    const big = resultsFile();
    Object.defineProperty(big, "size", { value: 50 * 1024 * 1024 + 1 });

    fireEvent.change(fileInput(), { target: { files: [big] } });

    expect(await within(dialog).findByRole("alert")).toHaveTextContent("over 50 MB");
    expect(callsTo("POST", "/api/imports/prowler")).toHaveLength(0);
  });

  it("loads the Imports table again after a file is imported", async () => {
    const { user, dialog } = await openFromMenu({ "POST /api/imports/prowler": RESULT });
    const before = callsTo("GET", "/api/imports").length;

    await user.upload(fileInput(), resultsFile());
    await within(dialog).findByText(/^Imported 2, /);

    await waitFor(() =>
      expect(callsTo("GET", "/api/imports").length).toBeGreaterThan(before),
    );
  });
});

describe("Import a results file: keyboard and focus", () => {
  it("closes on Escape", async () => {
    const { user } = await openFromMenu();

    await user.keyboard("{Escape}");

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("closes with the Close button", async () => {
    const { user, dialog } = await openFromMenu();

    await user.click(within(dialog).getByRole("button", { name: "Close" }));

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("does not close on Escape while a file is being sent", async () => {
    const { user, dialog } = await openFromMenu({ "POST /api/imports/prowler": never });
    await user.upload(fileInput(), resultsFile());
    await within(dialog).findByText(/Importing/);

    await user.keyboard("{Escape}");

    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("keeps Tab and Shift+Tab inside the dialog", async () => {
    const { user, dialog } = await openFromMenu();
    await within(dialog).findByText(RUN);
    const close = within(dialog).getByRole("button", { name: "Close" });
    const firstCopy = within(dialog).getByRole("button", {
      name: "Copy the install command",
    });

    close.focus();
    await user.tab();
    expect(firstCopy).toHaveFocus();

    await user.tab({ shift: true });
    expect(close).toHaveFocus();
  });

  it("has the focus inside the dialog when it opens", async () => {
    const { dialog } = await openFromMenu();

    expect(dialog.contains(document.activeElement)).toBe(true);
  });
});
