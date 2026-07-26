import { describe, expect, it } from "vitest";
import { pickupFallbackFlag } from "./recipients";

describe("pickupFallbackFlag", () => {
  it("is false when not encrypting, whatever the checkbox says", () => {
    expect(pickupFallbackFlag(false, true)).toBe(false);
  });

  it("is false when encrypting without the opt-in", () => {
    expect(pickupFallbackFlag(true, false)).toBe(false);
  });

  it("is true only when encrypting and opted in", () => {
    expect(pickupFallbackFlag(true, true)).toBe(true);
  });
});
