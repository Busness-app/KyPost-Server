// @vitest-environment node
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

// run-8 finding F8: SecurityPage's recovery-code regeneration was the ONE place
// in the frontend that posted a bare account `password` field. It was also
// broken — verifyAccountCredential picks its verifier from what the ACCOUNT
// stores with no fallback, and accounts convert to derived auth on first SPA
// sign-in, so the correct plaintext got a 401 on essentially every deployment.
// The guaranteed failure induced retries that re-sent the plaintext and burned
// lockout strikes, and on a client-protected account that plaintext also
// derives the PGP key-wrapping key.
//
// This is a source scan rather than a behavioural test because the property is
// about the whole tree, not one call site — the audit found this call site by
// grep, and the next one would arrive the same way. credentialFields (api/auth.ts)
// is the single sanctioned producer of a `password` field: it emits one only for
// an account whose stored hash still covers the plaintext.
function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      out.push(...sourceFiles(path));
    } else if (/\.tsx?$/.test(entry) && !/\.test\.tsx?$/.test(entry)) {
      out.push(path);
    }
  }
  return out;
}

describe("the account password is never posted directly (run-8 F8)", () => {
  it("routes every credential through credentialFields", () => {
    const root = join(__dirname, "..");
    const offenders: string[] = [];

    for (const file of sourceFiles(root)) {
      // auth.ts IS credentialFields; pgp.ts wraps it in stepUp().
      if (file.endsWith(join("api", "auth.ts"))) continue;
      const lines = readFileSync(file, "utf8").split("\n");
      lines.forEach((line, i) => {
        // A `password:` / `oldPassword:` object property whose value is a
        // variable — i.e. a credential being placed into a request body by
        // hand rather than by credentialFields. TS parameter and field
        // declarations share this shape, so primitive type annotations are
        // excluded by name.
        const property = /^\s*(old)?[Pp]assword:\s*([A-Za-z_$][\w.$]*)\s*,?\s*$/.exec(line);
        if (property && !["string", "number", "boolean", "unknown", "any"].includes(property[2])) {
          offenders.push(`${file.slice(root.length + 1)}:${i + 1}: ${line.trim()}`);
        }
      });
    }

    expect(offenders).toEqual([]);
  });
});
