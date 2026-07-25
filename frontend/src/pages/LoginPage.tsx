import { FormEvent, useEffect, useState } from "react";
import { prepareRewrappedPGPKey } from "../lib/pgpSession";
import { toErrorMessage } from "../api/client";
import { useNavigate } from "react-router-dom";
import { getJSON, postJSON } from "../api/client";
import type { AuthState } from "../auth";
import { CaptchaWidget, type CaptchaProvider } from "../components/CaptchaWidget";

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
      setStatus("Please complete the CAPTCHA challenge.");
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
      }>("/api/auth/login", { username, password, captchaToken: captchaToken || undefined });
      if (res.mfaRequired && res.challengeId) {
        const methods = res.methods ?? [];
        setMfaChallengeId(res.challengeId);
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
          : "Login failed. Check username and password."
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

  return (
    <section className="panel">
      <h2>{passwordMode ? "Change Password" : "Login and Setup"}</h2>
      <p>{passwordMode ? "Update your current password." : "Use your local admin credentials to access configuration and daemon controls."}</p>

      {mfaChallengeId ? (
        mfaMode === "push" ? (
          <div className="auth-form">
            <h3>Two-Factor Authentication</h3>
            <p>Approve this sign-in from a paired device. Waiting for approval…</p>
            {mfaMethods.includes("totp") ? (
              <button
                type="button"
                className="nav-link-button"
                onClick={() => {
                  setMfaMode("totp");
                  setStatus("");
                  setMfaCode("");
                }}
              >
                Use authenticator code instead
              </button>
            ) : null}
          </div>
        ) : (
          <form onSubmit={submitMfa} className="auth-form">
            <h3>Two-Factor Authentication</h3>
            {useRecoveryCode ? (
              <>
                <p>Enter one of your saved recovery codes.</p>
                <label>
                  <div>Recovery Code</div>
                  <input
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value)}
                    autoComplete="one-time-code"
                    placeholder="xxxx-xxxx-xxxx"
                    autoFocus
                  />
                </label>
              </>
            ) : (
              <>
                <p>Enter the 6-digit code from your authenticator app.</p>
                <label>
                  <div>Authentication Code</div>
                  <input
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    placeholder="123456"
                    autoFocus
                  />
                </label>
              </>
            )}
            <button type="submit" disabled={busy || mfaCode.trim() === ""}>
              {busy ? "Verifying..." : "Verify"}
            </button>
            <button
              type="button"
              className="nav-link-button"
              onClick={() => {
                setUseRecoveryCode((v) => !v);
                setMfaCode("");
                setStatus("");
              }}
            >
              {useRecoveryCode ? "Use authenticator code instead" : "Use a recovery code instead"}
            </button>
            {mfaMethods.includes("push") ? (
              <button
                type="button"
                className="nav-link-button"
                onClick={() => {
                  setMfaMode("push");
                  setStatus("");
                  setMfaCode("");
                }}
              >
                Approve on a device instead
              </button>
            ) : null}
          </form>
        )
      ) : !needsPasswordChange ? (
        <form onSubmit={submitLogin} className="auth-form">
          <label>
            <div>Username</div>
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
          </label>
          <label>
            <div>Password</div>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </label>
          {captchaConfig?.provider ? (
            <CaptchaWidget
              key={captchaNonce}
              provider={captchaConfig.provider}
              siteKey={captchaConfig.siteKey}
              onToken={setCaptchaToken}
            />
          ) : null}
          <button type="submit" disabled={busy}>
            {busy ? "Signing in..." : "Sign In"}
          </button>
        </form>
      ) : (
        <form onSubmit={submitPasswordChange} className="auth-form">
          <h3>Change Password</h3>
          <p>Enter your current password and choose a new one.</p>
          <label>
            <div>Username</div>
            <input value={username} autoComplete="username" readOnly />
          </label>
          <label>
            <div>Current Password</div>
            <input
              type="password"
              value={oldPassword}
              onChange={(e) => setOldPassword(e.target.value)}
              autoComplete="current-password"
            />
          </label>
          <label>
            <div>New Password</div>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              autoComplete="new-password"
            />
          </label>
          <button type="submit" disabled={busy}>
            {busy ? "Updating..." : "Update Password"}
          </button>
        </form>
      )}

      {status ? <p>{status}</p> : null}
    </section>
  );
}
