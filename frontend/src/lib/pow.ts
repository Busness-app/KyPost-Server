// Browser side of the self-hosted proof-of-work login CAPTCHA
// (CAPTCHA_PROVIDER=pow). The server publishes SHA-256(salt + number) and
// keeps the number secret; this finds it by counting up from zero.
//
// No Web Worker on purpose: crypto.subtle.digest is already async, so every
// iteration yields to the event loop and the login form stays responsive
// without one — and without a bundled worker chunk to keep inside
// `worker-src 'self'`. See backend/internal/captcha/pow.go for the server
// half and the wire format.

export type PowChallenge = {
  algorithm: string;
  salt: string;
  challenge: string;
  maxnumber: number;
  expires: number;
  // The address the server issued this challenge to. Echoed back untouched
  // like every other field: the server compares it to the address the login
  // request arrives from, and it is covered by the signature, so editing it
  // invalidates the solution rather than moving it to another address.
  clientip: string;
  signature: string;
};

const encoder = new TextEncoder();

// How often to report progress. Every iteration would spend more time in the
// React render it triggers than in the hashing it reports on.
const PROGRESS_EVERY = 500;

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(input));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// solvePowChallenge returns the base64 token to submit as the login body's
// `captchaToken`. It is the whole challenge echoed back verbatim plus the
// number found: the server re-checks its own HMAC over those fields, so
// altering any of them (notably maxnumber, the difficulty) invalidates the
// solution rather than weakening it.
export async function solvePowChallenge(
  challenge: PowChallenge,
  onProgress?: (fraction: number) => void
): Promise<string> {
  if (challenge.algorithm !== "SHA-256") {
    throw new Error(`Unsupported security-check algorithm: ${challenge.algorithm}`);
  }
  for (let number = 0; number <= challenge.maxnumber; number++) {
    if ((await sha256Hex(challenge.salt + number)) === challenge.challenge) {
      return btoa(JSON.stringify({ ...challenge, number }));
    }
    if (onProgress && number % PROGRESS_EVERY === 0) {
      onProgress(number / challenge.maxnumber);
    }
  }
  // Only reachable if the server and this client disagree about the wire
  // format — a real challenge always has its answer inside maxnumber.
  throw new Error("Security check has no solution in the range the server gave.");
}
