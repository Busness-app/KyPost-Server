import { FormEvent, useEffect, useState } from "react";
import { credentialFields, deriveCredential } from "../api/auth";
import { toErrorMessage } from "../api/client";
import { useNavigate } from "react-router";
import { getJSON, HttpError, postJSON } from "../api/client";
import type { AuthState } from "../auth";
import { CaptchaWidget, type CaptchaProvider } from "../components/CaptchaWidget";
import { ChangePasswordForm } from "../components/ChangePasswordForm";

// /api/auth/login's 401 body is always one of: "invalid credentials",
// "captcha verification failed", "security check expired, please try
// again", or the pow wrong-address message — never anything that reveals
// whether a username exists, so surfacing it is safe. It matters for the
// last two: without this, a stale challenge or a phone's wifi->cellular
// handoff both rendered as "Check username and password", which is the
// opposite of the right advice and, worse, told the user their password
// was wrong on the one path where the lockout strike was refunded because
// it *wasn't* a credential problem.
//
// HttpError's .message is built as `request failed: ${status} - ${detail}`
// (see requestJSON in api/client.ts); stripping that fixed prefix is how
// the server's own text comes back out. Returns undefined rather than the
// generic fallback so a caller can tell "no server message" apart from
// "server message happened to be empty".
function loginServerMessage(err: unknown): string | undefined {
  if (!(err instanceof HttpError) || err.status !== 401) {
    return undefined;
  }
  const prefix = `request failed: ${err.status} - `;
  return err.message.startsWith(prefix) ? err.message.slice(prefix.length) : undefined;
}

type LoginPageProps = {
  auth: AuthState;
  onAuthChanged: () => Promise<void> | void;
  mode?: "login" | "password";
};

type CaptchaConfig = {
  provider: CaptchaProvider | "";
  siteKey: string;
};

export function LoginPage({ auth, onAuthChanged, mode = "login" }: LoginPageProps) {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [needsPasswordChange, setNeedsPasswordChange] = useState(false);
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [mfaChallengeId, setMfaChallengeId] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [useRecoveryCode, setUseRecoveryCode] = useState(false);
  const [mfaMethods, setMfaMethods] = useState<string[]>([]);
  const [mfaMode, setMfaMode] = useState<"totp" | "push">("totp");
  // The number the approving device must send back. Displaying it is what makes
  // push approval more than a blind "yes": the phone shows several numbers and
  // only this screen — the one that actually started the sign-in — says which is
  // right. Without it the person tapping Approve cannot distinguish their own
  // login from an attacker's, which is the whole MFA-fatigue attack.
  const [mfaMatchDigits, setMfaMatchDigits] = useState("");
  const [captchaConfig, setCaptchaConfig] = useState<CaptchaConfig | null>(null);
  const [captchaToken, setCaptchaToken] = useState("");
  const [captchaNonce, setCaptchaNonce] = useState(0);
  const passwordMode = mode === "password";

  useEffect(() => {
    if (passwordMode) {
      return;
    }
    let cancelled = false;
    getJSON<CaptchaConfig>("/api/auth/captcha-config")
      .then((cfg) => {
        if (!cancelled) setCaptchaConfig(cfg);
      })
      .catch(() => {
        // CAPTCHA is an operator opt-in; if the config fetch fails, log in
        // proceeds without it rather than blocking the whole form.
      });
    return () => {
      cancelled = true;
    };
  }, [passwordMode]);

  useEffect(() => {
    if (passwordMode) {
      setNeedsPasswordChange(true);
      setUsername(auth.username ?? username);
      return;
    }
    if (auth.authenticated && !auth.mustChangePassword) {
      navigate("/read", { replace: true });
    }
    if (auth.mustChangePassword) {
      setNeedsPasswordChange(true);
      setUsername(auth.username ?? username);
    }
  }, [auth.authenticated, auth.mustChangePassword, auth.username, navigate, passwordMode, username]);

  function finishSignIn(mustChangePassword: boolean) {
    if (mustChangePassword) {
      // ChangePasswordForm's lede already says why the user landed here (see
      // the `lede` prop below); a second, separately-lived status region
      // saying much the same thing is what let LoginPage's own status
      // outlive its usefulness once the form owned its own status state,
      // producing two live role="status" regions at once. See notice below.
      setNeedsPasswordChange(true);
    } else {
      navigate("/read", { replace: true });
    }
  }

  async function submitLogin(e: FormEvent) {
    e.preventDefault();
    if (captchaConfig?.provider && !captchaToken) {
      setStatus("Complete the security check to continue.");
      return;
    }
    setBusy(true);
    setStatus("");
    try {
      const credential = await deriveCredential(username, password);
      const res = await postJSON<{
        ok?: boolean;
        mustChangePassword?: boolean;
        mfaRequired?: boolean;
        challengeId?: string;
        methods?: string[];
        matchDigits?: string;
        pushRetryAfterSeconds?: number;
      }>("/api/auth/login", {
        username,
        ...credentialFields(credential),
        loginSalt: credential.loginSalt,
        loginIterations: credential.loginIterations,
        captchaToken: captchaToken || undefined
      });
      if (res.mfaRequired && res.challengeId) {
        const methods = res.methods ?? [];
        setMfaChallengeId(res.challengeId);
        setMfaMatchDigits(res.matchDigits ?? "");
        setMfaMethods(methods);
        setMfaMode(methods.includes("push") ? "push" : "totp");
        setMfaCode("");
        setUseRecoveryCode(false);
        // The server only offers "push" when it actually sent one. When it has
        // throttled the notification it says how long for, and saying so is the
        // point: a silent drop to the code field looks like the approval feature
        // breaking, which is exactly how this presented before the server stopped
        // advertising a push it had suppressed.
        setStatus(
          res.pushRetryAfterSeconds
            ? `Approval requests are rate-limited — check your device for a request already waiting, or try again in ${res.pushRetryAfterSeconds}s. Enter a code to sign in now.`
            : ""
        );
        return;
      }
      await onAuthChanged();
      finishSignIn(Boolean(res.mustChangePassword));
    } catch (err) {
      const message = err instanceof Error ? err.message : "";
      setStatus(
        message.includes("429")
          ? "Too many failed attempts. Please wait a few minutes before trying again."
          : loginServerMessage(err) ?? "Login failed. Check username and password."
      );
    } finally {
      // CAPTCHA tokens are single-use: always get a fresh challenge for the
      // next attempt, success or failure.
      setCaptchaToken("");
      setCaptchaNonce((n) => n + 1);
      setBusy(false);
    }
  }

  async function submitMfa(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setStatus("");
    const endpoint = useRecoveryCode ? "/api/auth/mfa/recovery-code" : "/api/auth/mfa/totp";
    try {
      const res = await postJSON<{ ok: boolean; mustChangePassword?: boolean }>(endpoint, {
        challengeId: mfaChallengeId,
        code: mfaCode.trim()
      });
      await onAuthChanged();
      setMfaChallengeId("");
      setMfaMatchDigits("");
      setMfaCode("");
      finishSignIn(Boolean(res.mustChangePassword));
    } catch {
      setStatus(useRecoveryCode ? "Invalid recovery code." : "Invalid authentication code.");
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    if (!mfaChallengeId || mfaMode !== "push") {
      return;
    }
    let cancelled = false;
    const interval = setInterval(async () => {
      try {
        const res = await postJSON<{ status: string }>("/api/auth/mfa/push/poll", {
          challengeId: mfaChallengeId
        });
        if (cancelled) {
          return;
        }
        if (res.status === "approved") {
          clearInterval(interval);
          const fin = await postJSON<{ ok: boolean; mustChangePassword?: boolean }>(
            "/api/auth/mfa/push/finish",
            { challengeId: mfaChallengeId }
          );
          if (cancelled) {
            return;
          }
          await onAuthChanged();
          if (cancelled) {
            return;
          }
          setMfaChallengeId("");
          setMfaMatchDigits("");
          finishSignIn(Boolean(fin.mustChangePassword));
        } else if (res.status === "denied" || res.status === "expired" || res.status === "locked") {
          clearInterval(interval);
          if (cancelled) {
            return;
          }
          // "locked" is a wrong number tapped on the device: push is finished
          // for this sign-in but the challenge is still good for TOTP, which is
          // why it shares this branch rather than restarting the flow. See
          // mfa.maxMatchAttempts.
          setStatus(
            res.status === "denied"
              ? "Sign-in was denied on your device."
              : res.status === "locked"
                ? "That was not the number shown here. Approval on your device is locked for this sign-in — enter a code from your authenticator app instead."
                : "The approval request expired."
          );
          if (mfaMethods.includes("totp")) {
            setMfaMode("totp");
          }
        }
      } catch {
        // Transient error; keep polling until the challenge resolves or expires.
      }
    }, 1500);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
    // finishSignIn/onAuthChanged are stable enough for this flow; re-running on
    // challenge/mode/method changes is what matters.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mfaChallengeId, mfaMode, mfaMethods]);

  // One of four states, each with its own heading and lede, so the card always
  // says which gate you are at instead of carrying one generic title.
  const body = mfaChallengeId ? (
    mfaMode === "push" ? (
      <div className="auth-form">
        <header className="auth-head">
          <h1 className="auth-title">Approve on your device</h1>
          <p className="auth-lede">
            {mfaMatchDigits
              ? "Tap this number on your paired device."
              : "Open KyPost on your paired device to approve."}
          </p>
        </header>

        {mfaMatchDigits ? (
          <div
            className="auth-match"
            role="img"
            aria-label={`Approval number ${mfaMatchDigits.split("").join(" ")}`}
          >
            <span className="auth-match-digits">{mfaMatchDigits}</span>
          </div>
        ) : null}

        {/* Shown in both cases: this screen polls, and without a live indicator
            a pending challenge is indistinguishable from a stalled page. */}
        <p className="auth-waiting-row">
          <span className="auth-waiting" aria-hidden="true">
            <span />
            <span />
            <span />
          </span>
          Waiting for approval…
        </p>

        {mfaMatchDigits ? (
          <p className="auth-caution">
            Did not start this sign-in? Choose <strong>Deny</strong> on your device.
          </p>
        ) : null}

        {mfaMethods.includes("totp") ? (
          <button
            type="button"
            className="auth-alt"
            onClick={() => {
              setMfaMode("totp");
              setStatus("");
              setMfaCode("");
            }}
          >
            Use an authenticator code instead
          </button>
        ) : null}
      </div>
    ) : (
      <form onSubmit={submitMfa} className="auth-form">
        <header className="auth-head">
          <h1 className="auth-title">{useRecoveryCode ? "Use a recovery code" : "Enter your code"}</h1>
          <p className="auth-lede">
            {useRecoveryCode
              ? "Any one of the codes you saved when you set up two-factor sign-in."
              : "The 6-digit code from your authenticator app."}
          </p>
        </header>

        <label className="auth-field">
          <span className="auth-label">{useRecoveryCode ? "Recovery code" : "Authentication code"}</span>
          {useRecoveryCode ? (
            <input
              className="auth-input auth-input-code"
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value)}
              autoComplete="one-time-code"
              placeholder="xxxx-xxxx-xxxx"
              autoFocus
            />
          ) : (
            <input
              className="auth-input auth-input-code auth-input-otp"
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="123456"
              autoFocus
            />
          )}
        </label>

        <button type="submit" className="auth-submit" disabled={busy || mfaCode.trim() === ""}>
          {busy ? "Verifying…" : "Verify"}
        </button>

        <div className="auth-alts">
          <button
            type="button"
            className="auth-alt"
            onClick={() => {
              setUseRecoveryCode((v) => !v);
              setMfaCode("");
              setStatus("");
            }}
          >
            {useRecoveryCode ? "Use an authenticator code instead" : "Use a recovery code instead"}
          </button>
          {mfaMethods.includes("push") ? (
            <button
              type="button"
              className="auth-alt"
              onClick={() => {
                setMfaMode("push");
                setStatus("");
                setMfaCode("");
              }}
            >
              Approve on a device instead
            </button>
          ) : null}
        </div>
      </form>
    )
  ) : !needsPasswordChange ? (
    <form onSubmit={submitLogin} className="auth-form">
      <header className="auth-head">
        <h1 className="auth-title">Sign in</h1>
        <p className="auth-lede">Your mail, on your own server.</p>
      </header>

      <label className="auth-field">
        <span className="auth-label">Username</span>
        <input
          className="auth-input auth-input-code"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoComplete="username"
        />
      </label>
      <label className="auth-field">
        <span className="auth-label">Password</span>
        <input
          className="auth-input"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
        />
      </label>

      {captchaConfig?.provider ? (
        <div className="auth-field">
          <span className="auth-label">Security check</span>
          {/* Fixed slot: the widget arrives from a third-party script well after
              first paint, and an unreserved box made the Sign in button jump
              out from under the pointer as it loaded. */}
          <div className="auth-captcha">
            <CaptchaWidget
              key={captchaNonce}
              provider={captchaConfig.provider}
              siteKey={captchaConfig.siteKey}
              onToken={setCaptchaToken}
            />
          </div>
        </div>
      ) : null}

      <button type="submit" className="auth-submit" disabled={busy}>
        {busy ? "Signing in…" : "Sign in"}
      </button>
    </form>
  ) : (
    <ChangePasswordForm
      username={username}
      initialCurrentPassword={password}
      lede={
        passwordMode
          ? "Your PGP key is re-encrypted under the new password automatically."
          : "This account needs a new password before you can go any further."
      }
      onSuccess={async () => {
        await onAuthChanged();
        setNeedsPasswordChange(false);
        setPassword("");
        navigate("/read", { replace: true });
      }}
    />
  );

  // ChangePasswordForm owns its own status region once it is on screen — see
  // finishSignIn above. Rendering LoginPage's own notice alongside it, from
  // whatever `status` last held (a login error, an MFA rate-limit notice,
  // …), would put two role="status" regions live at the same time.
  const notice = status && !needsPasswordChange ? (
    <p className="auth-status" role="status">
      {status}
    </p>
  ) : null;

  // /password is reached from inside the app, so it stays an ordinary panel in
  // the app shell. Only the signed-out front door gets the standalone layout.
  if (passwordMode) {
    return (
      <section className="panel">
        {body}
        {notice}
      </section>
    );
  }

  return (
    <div className="auth-shell">
      <div className="auth-seal">
        <img className="auth-seal-mark" src="/ky.png" alt="KyPost" />
      </div>
      <section className="auth-card">
        {body}
        {notice}
      </section>
      <p className="auth-footnote">Self-hosted KyPost</p>
    </div>
  );
}
