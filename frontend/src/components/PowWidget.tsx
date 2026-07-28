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

export function PowWidget({ onToken }: PowWidgetProps) {
  const [phase, setPhase] = useState<Phase>("working");
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState("");
  const onTokenRef = useRef(onToken);
  onTokenRef.current = onToken;

  useEffect(() => {
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
        setError(toErrorMessage(err, "Could not complete the security check."));
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  if (phase === "failed") {
    return (
      <div className="auth-pow auth-pow-failed" role="alert">
        {error} Reload the page to try again.
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
