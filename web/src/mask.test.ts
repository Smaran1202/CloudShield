import { describe, expect, it } from "vitest";
import { maskAccountIds } from "./mask";

const MASK = "•".repeat(8);

describe("maskAccountIds", () => {
  it("shows only the last four digits of a 12-digit account id", () => {
    expect(maskAccountIds("123456789089")).toBe(`${MASK}9089`);
    expect(maskAccountIds("123456789089")).not.toContain("12345678");
  });

  it("masks an id inside an ARN and inside a sentence", () => {
    expect(maskAccountIds("arn:aws:iam::123456789012:role/deploy")).toBe(
      `arn:aws:iam::${MASK}9012:role/deploy`,
    );
    expect(maskAccountIds("Account 210987654321 has no trail.")).toBe(
      `Account ${MASK}4321 has no trail.`,
    );
  });

  it("masks every id in the text", () => {
    expect(maskAccountIds("111111111111 and 222222222222")).toBe(
      `${MASK}1111 and ${MASK}2222`,
    );
  });

  it("leaves a shorter run of digits alone", () => {
    expect(maskAccountIds("12345678901")).toBe("12345678901");
    expect(maskAccountIds("port 8080, 2026-11-03")).toBe("port 8080, 2026-11-03");
  });

  it("leaves a longer run of digits alone", () => {
    expect(maskAccountIds("1234567890123")).toBe("1234567890123");
    expect(maskAccountIds("1234567890123456")).toBe("1234567890123456");
  });

  it("leaves text with no digits, and an empty string, alone", () => {
    expect(maskAccountIds("no numbers here")).toBe("no numbers here");
    expect(maskAccountIds("")).toBe("");
  });

  it("does not use the REPLACE_WITH placeholder used in patches", () => {
    expect(maskAccountIds("REPLACE_WITH_YOUR_ACCOUNT_ID")).toBe(
      "REPLACE_WITH_YOUR_ACCOUNT_ID",
    );
  });
});
