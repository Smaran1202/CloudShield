import { describe, expect, it } from "vitest";
import {
  byScoreDescending,
  countLanes,
  highestRiskOpen,
  LANE_HINT,
  LANE_THRESHOLDS,
  laneOf,
  shortResource,
} from "./lanes";
import { finding } from "./test/factories";

describe("laneOf", () => {
  it("puts an open finding at the Fix now threshold in Fix now, and one point below in Next", () => {
    expect(laneOf({ status: "OPEN", risk_score: 80 })).toBe("now");
    expect(laneOf({ status: "OPEN", risk_score: 79 })).toBe("next");
  });

  it("puts an open finding at the Next threshold in Next, and one point below in Later", () => {
    expect(laneOf({ status: "OPEN", risk_score: 60 })).toBe("next");
    expect(laneOf({ status: "OPEN", risk_score: 59 })).toBe("later");
  });

  it("puts the highest and the lowest scores in the right lanes", () => {
    expect(laneOf({ status: "OPEN", risk_score: 100 })).toBe("now");
    expect(laneOf({ status: "OPEN", risk_score: 0 })).toBe("later");
  });

  it("puts an open finding with no score in Later", () => {
    expect(laneOf({ status: "OPEN", risk_score: null })).toBe("later");
  });

  it("puts every resolved finding in Done, whatever its last score was", () => {
    expect(laneOf({ status: "RESOLVED", risk_score: 95 })).toBe("done");
    expect(laneOf({ status: "RESOLVED", risk_score: 20 })).toBe("done");
    expect(laneOf({ status: "RESOLVED", risk_score: null })).toBe("done");
  });

  it("reads its thresholds from one constant", () => {
    expect(LANE_THRESHOLDS).toEqual({ fixNow: 80, next: 60 });
    expect(LANE_HINT.now).toBe("Risk score 80 or more");
    expect(LANE_HINT.next).toBe("Risk score 60 to 79");
    expect(LANE_HINT.later).toBe("Risk score below 60, or no score");
  });
});

describe("countLanes", () => {
  it("counts findings per lane", () => {
    const counts = countLanes([
      { status: "OPEN", risk_score: 90 },
      { status: "OPEN", risk_score: 80 },
      { status: "OPEN", risk_score: 61 },
      { status: "OPEN", risk_score: null },
      { status: "RESOLVED", risk_score: 99 },
    ]);

    expect(counts).toEqual({ now: 2, next: 1, later: 1, done: 1 });
  });
});

describe("highestRiskOpen", () => {
  it("is the open finding with the highest score, ignoring resolved and unscored ones", () => {
    const rows = [
      finding({ finding_id: "F-1", risk_score: 70 }),
      finding({ finding_id: "F-2", risk_score: 99, status: "RESOLVED" }),
      finding({ finding_id: "F-3", risk_score: 85 }),
      finding({ finding_id: "F-4", risk_score: null, severity: "INFO" }),
    ];

    expect(highestRiskOpen(rows)?.finding_id).toBe("F-3");
  });

  it("is null when nothing scored is open", () => {
    expect(highestRiskOpen([finding({ risk_score: null })])).toBeNull();
    expect(highestRiskOpen([])).toBeNull();
  });
});

describe("byScoreDescending", () => {
  it("sorts by score, high to low, with findings without a score last", () => {
    const rows = [
      finding({ finding_id: "A", risk_score: null }),
      finding({ finding_id: "B", risk_score: 40 }),
      finding({ finding_id: "C", risk_score: 95 }),
    ];

    expect(rows.sort(byScoreDescending).map((r) => r.finding_id)).toEqual([
      "C",
      "B",
      "A",
    ]);
  });
});

describe("shortResource", () => {
  it("shortens an ARN to its last part", () => {
    expect(shortResource("arn:aws:iam::123456789012:policy/deploy")).toBe(
      "...:policy/deploy",
    );
    expect(shortResource("arn:aws:iam::123456789012:role/app/web")).toBe(
      "...:role/app/web",
    );
  });

  it("leaves other ids as they are", () => {
    expect(shortResource("sg-0abc123")).toBe("sg-0abc123");
    expect(shortResource("my-bucket")).toBe("my-bucket");
  });
});
