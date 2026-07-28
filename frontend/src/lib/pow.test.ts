import { describe, expect, it, vi } from "vitest";
import { solvePowChallenge, type PowChallenge } from "./pow";

const encoder = new TextEncoder();

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(input));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Build a challenge whose answer we know, the way the Go server does:
// challenge = sha256(salt + decimal number).
async function makeChallenge(number: number, maxnumber = 100): Promise<PowChallenge> {
  const salt = "0123456789abcdef0123456789abcdef";
  return {
    algorithm: "SHA-256",
    salt,
    challenge: await sha256Hex(salt + number),
    maxnumber,
    expires: Math.floor(Date.now() / 1000) + 300,
    signature: "server-signature-the-client-never-inspects"
  };
}

describe("solvePowChallenge", () => {
  it("finds the number and echoes the whole challenge back", async () => {
    const challenge = await makeChallenge(42);
    const token = await solvePowChallenge(challenge);

    const solution = JSON.parse(atob(token));
    expect(solution.number).toBe(42);
    // The server re-verifies its own HMAC over these, so every field has to
    // survive the round trip untouched.
    expect(solution.salt).toBe(challenge.salt);
    expect(solution.challenge).toBe(challenge.challenge);
    expect(solution.maxnumber).toBe(challenge.maxnumber);
    expect(solution.expires).toBe(challenge.expires);
    expect(solution.signature).toBe(challenge.signature);
    expect(solution.algorithm).toBe("SHA-256");
  });

  it("finds zero", async () => {
    const token = await solvePowChallenge(await makeChallenge(0));
    expect(JSON.parse(atob(token)).number).toBe(0);
  });

  it("finds the top of the range", async () => {
    const token = await solvePowChallenge(await makeChallenge(100, 100));
    expect(JSON.parse(atob(token)).number).toBe(100);
  });

  it("reports progress as it searches", async () => {
    // maxnumber has to clear PROGRESS_EVERY (500) several times over. At
    // maxnumber=100 this fired exactly once, at number 0 with fraction 0, so
    // "was called at least once" passed even if reporting were broken for
    // every iteration after the first.
    const onProgress = vi.fn();
    await solvePowChallenge(await makeChallenge(1500, 1500), onProgress);

    const fractions = onProgress.mock.calls.map(([fraction]) => fraction as number);
    expect(fractions.length).toBeGreaterThan(1);
    for (const fraction of fractions) {
      expect(fraction).toBeGreaterThanOrEqual(0);
      expect(fraction).toBeLessThanOrEqual(1);
    }
    // It must advance, not just fire.
    for (let i = 1; i < fractions.length; i++) {
      expect(fractions[i]).toBeGreaterThan(fractions[i - 1]);
    }
  });

  it("rejects an algorithm it cannot compute", async () => {
    const challenge = { ...(await makeChallenge(1)), algorithm: "MD5" };
    await expect(solvePowChallenge(challenge)).rejects.toThrow(/algorithm/i);
  });

  it("rejects a challenge with no answer in range", async () => {
    // Answer 500, but the client is told to search only 0..100.
    const challenge = { ...(await makeChallenge(500, 500)), maxnumber: 100 };
    await expect(solvePowChallenge(challenge)).rejects.toThrow(/no solution/i);
  });
});
