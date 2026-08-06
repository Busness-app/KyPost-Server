import { afterEach, describe, expect, it, vi } from "vitest";
import { holdForSecret, releaseSecretHold, secretHoldReason, subscribeSecretHold } from "./secretHold";

afterEach(releaseSecretHold);

describe("secretHold", () => {
  it("reports the reason so the blocker can explain itself", () => {
    expect(secretHoldReason()).toBe("");
    holdForSecret("password on screen");
    expect(secretHoldReason()).toBe("password on screen");
    releaseSecretHold();
    expect(secretHoldReason()).toBe("");
  });

  it("pushes the current value to a new subscriber immediately", () => {
    holdForSecret("already held");
    const seen = vi.fn();
    subscribeSecretHold(seen);
    // Without this, a component that mounts while a hold is active would think
    // navigation was free until the next change.
    expect(seen).toHaveBeenCalledWith("already held");
  });

  it("does not re-notify when the same reason is held twice", () => {
    const seen = vi.fn();
    const unsubscribe = subscribeSecretHold(seen);
    seen.mockClear();

    holdForSecret("same");
    holdForSecret("same");

    expect(seen).toHaveBeenCalledTimes(1);
    unsubscribe();
  });

  it("stops notifying after unsubscribe, so an unmounted holder cannot leak", () => {
    const seen = vi.fn();
    const unsubscribe = subscribeSecretHold(seen);
    unsubscribe();
    seen.mockClear();

    holdForSecret("ignored");

    expect(seen).not.toHaveBeenCalled();
  });
});
