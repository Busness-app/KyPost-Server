import { useEffect, useRef, useState } from "react";
import { getJSON, toErrorMessage } from "../api/client";
import { solvePowChallenge, type PowChallenge } from "../lib/pow";

// PowWidget is the self-hosted alternative to CaptchaWidget's two
// third-party providers: it fetches a challenge from this same server and
// solves it in the page. No third-party script, no iframe, nothing to load
// from a CDN — so unlike the other two it renders something useful on the
// very first paint instead of after a remote script arrives.
type PowWidgetProps = {
  onToken: (token: string) => void;
};

type Phase = "working" | "done" | "failed";

// SubtleCrypto is [SecureContext]: over plain http:// to anything but
// localhost — which is exactly what the shipped docker-compose.yml serves, see
// the TLS note in README.md — window.crypto.subtle is undefined and the solver
// throws a TypeError on its first hash. The result is a login page nobody can
// get past, so say what it is and who can fix it rather than surfacing a raw
// TypeError through the generic failure branch. Checked before fetching: a
// challenge this browser cannot solve is not worth minting.
const SECURE_CONTEXT_REQUIRED =
  "This security check needs a secure (HTTPS) connection, and this page was not loaded over one. " +
  "The administrator has to put TLS in front of the server, or choose a different CAPTCHA provider.";

function canRunSecurityCheck(): boolean {
  return window.isSecureContext && Boolean(globalThis.crypto?.subtle);
}

export function PowWidget({ onToken }: PowWidgetProps) {
  const [phase, setPhase] = useState<Phase>("working");
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState("");
  const onTokenRef = useRef(onToken);
  onTokenRef.current = onToken;

  useEffect(() => {
    if (!canRunSecurityCheck()) {
      setPhase("failed");
      setError(SECURE_CONTEXT_REQUIRED);
      return;
    }

    // The solver loop is long-lived by design, and LoginPage remounts this
    // component (via its captchaNonce key) after every attempt. Without this
    // flag an in-flight solve from the previous mount would still call
    // setState and hand up a token that belongs to a form that is gone.
    let cancelled = false;

    (async () => {
      try {
        const challenge = await getJSON<PowChallenge>("/api/auth/pow-challenge");
        if (cancelled) return;
        const token = await solvePowChallenge(challenge, (fraction) => {
          if (!cancelled) setProgress(fraction);
        });
        if (cancelled) return;
        setPhase("done");
        onTokenRef.current(token);
      } catch (err) {
        if (cancelled) return;
        setPhase("failed");
        setError(`${toErrorMessage(err, "Could not complete the security check.")} Reload the page to try again.`);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  // The "reload and retry" advice now lives in the message rather than here,
  // because it is not true of every failure: reloading a page served over
  // plain HTTP produces the same missing crypto.subtle every time.
  if (phase === "failed") {
    return (
      <div className="auth-pow auth-pow-failed" role="alert">
        {error}
      </div>
    );
  }
  if (phase === "done") {
    return (
      <div className="auth-pow auth-pow-done" role="status">
        Security check verified.
      </div>
    );
  }
  return (
    <div className="auth-pow" role="status" aria-live="polite">
      <span className="auth-pow-label">Running security check…</span>
      <progress className="auth-pow-bar" value={progress} max={1} />
    </div>
  );
}
