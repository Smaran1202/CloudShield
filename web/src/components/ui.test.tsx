import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { PRIMARY_BUTTON, SECONDARY_BUTTON, Spinner } from "./ui";

describe("Button styles", () => {
  it("gives the primary button a hover, a press and a flat disabled look", () => {
    render(<button className={PRIMARY_BUTTON}>Go</button>);

    const button = screen.getByRole("button", { name: "Go" });

    expect(button).toHaveClass(
      "min-h-10",
      "bg-ink",
      "hover:bg-ink-hover",
      "active:bg-black",
    );
    expect(button).toHaveClass("disabled:bg-lane-grey", "disabled:text-dim");
  });

  it("gives the secondary button a hover, a press and a flat disabled look", () => {
    render(<button className={SECONDARY_BUTTON}>Go</button>);

    const button = screen.getByRole("button", { name: "Go" });

    expect(button).toHaveClass("hover:bg-pill-hover", "active:bg-pill-press");
    expect(button).toHaveClass("disabled:bg-lane-grey", "disabled:text-dim");
  });

  it("never scales a button when it is pressed, and never fades it to show it is disabled", () => {
    for (const style of [PRIMARY_BUTTON, SECONDARY_BUTTON]) {
      expect(style).not.toMatch(/scale|opacity/);
    }
  });

  it("draws the spinner as a decoration inside the button", () => {
    render(
      <button aria-busy="true">
        <Spinner />
        Scanning...
      </button>,
    );

    expect(screen.getByRole("button", { name: "Scanning..." })).toHaveAttribute(
      "aria-busy",
      "true",
    );
    expect(document.querySelector(".spinner")).toHaveAttribute("aria-hidden", "true");
  });
});
