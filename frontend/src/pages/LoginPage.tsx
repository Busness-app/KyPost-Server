import { FormEvent, useEffect, useState } from "react";
import { prepareRewrappedPGPKey } from "../lib/pgpSession";
import { toErrorMessage } from "../api/client";
import { useNavigate } from "react-router";
import { getJSON, HttpError, postJSON } from "../api/client";
import type { AuthState } from "../auth";
import { CaptchaWidget, type CaptchaProvider } from "../components/CaptchaWidget";

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
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
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
      setNeedsPasswordChange(true);
      setOldPassword(password);
      setStatus("Password change required before using the app.");
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
      const res = await postJSON<{
        ok?: boolean;
        mustChangePassword?: boolean;
        mfaRequired?: boolean;
        challengeId?: string;
        methods?: string[];
        matchDigits?: string;
      }>("/api/auth/login", { username, password, captchaToken: captchaToken || undefined });
      if (res.mfaRequired && res.challengeId) {
        const methods = res.methods ?? [];
        setMfaChallengeId(res.challengeId);
        setMfaMatchDigits(res.matchDigits ?? "");
        setMfaMethods(methods);
        setMfaMode(methods.includes("push") ? "push" : "totp");
        setMfaCode("");
        setUseRecoveryCode(false);
        setStatus("");
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
        } else if (res.status === "denied" || res.status === "expired") {
          clearInterval(interval);
          if (cancelled) {
            return;
          }
          setStatus(
            res.status === "denied"
              ? "Sign-in was denied on your device."
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

  async function submitPasswordChange(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setStatus("");
    const currentPassword = oldPassword || password;
    if (!currentPassword) {
      setStatus("Enter your current password from initial sign-in.");
      setBusy(false);
      return;
    }
    try {
      // The PGP key is wrapped under the account password, so it must be
      // rewrapped as part of this change. Do it BEFORE the password write:
      // if the rewrap fails, the password is untouched and the user retries,
      // which is recoverable. The other order leaves the password changed and
      // the key still wrapped under the old one — recoverable only by knowing
      // to enter a password that is no longer their password.
      const rewrap = await prepareRewrappedPGPKey(currentPassword, newPassword);

      await postJSON<{ ok: boolean }>("/api/auth/password", {
        username,
        oldPassword: currentPassword,
        newPassword
      });

      if (rewrap) {
        try {
          await rewrap();
        } catch (rewrapErr) {
          // The password did change, so say exactly that and name the remedy
          // rather than reporting a generic failure for a half-applied change.
          setStatus(
            "Password updated, but re-encrypting your PGP key failed. Go to Security and unlock your key with your PREVIOUS password, then change your password again. " +
              toErrorMessage(rewrapErr, "")
          );
          setBusy(false);
          return;
        }
      }
      await onAuthChanged();
      setNeedsPasswordChange(false);
      setPassword("");
      setOldPassword("");
      setNewPassword("");
      setStatus("Password updated. You can now continue.");
      navigate("/read", { replace: true });
    } catch (err) {
      const message = err instanceof Error ? err.message : "";
      if (message.includes("401")) {
        setStatus("Password change failed. Sign in first, then try again.");
      } else {
        setStatus("Password change failed. Verify current password.");
      }
    } finally {
      setBusy(false);
    }
  }

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
    <form onSubmit={submitPasswordChange} className="auth-form">
      <header className="auth-head">
        <h1 className="auth-title">Choose a new password</h1>
        <p className="auth-lede">
          {passwordMode
            ? "Your PGP key is re-encrypted under the new password automatically."
            : "This account needs a new password before you can go any further."}
        </p>
      </header>

      <label className="auth-field">
        <span className="auth-label">Username</span>
        <input className="auth-input auth-input-code" value={username} autoComplete="username" readOnly />
      </label>
      <label className="auth-field">
        <span className="auth-label">Current password</span>
        <input
          className="auth-input"
          type="password"
          value={oldPassword}
          onChange={(e) => setOldPassword(e.target.value)}
          autoComplete="current-password"
        />
      </label>
      <label className="auth-field">
        <span className="auth-label">New password</span>
        <input
          className="auth-input"
          type="password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          autoComplete="new-password"
        />
      </label>

      <button type="submit" className="auth-submit" disabled={busy}>
        {busy ? "Updating…" : "Update password"}
      </button>
    </form>
  );

  const notice = status ? (
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
