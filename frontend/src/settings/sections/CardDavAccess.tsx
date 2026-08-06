import { useEffect, useState } from "react";
import { toErrorMessage } from "../../api/client";
import { generateDAVPassword, getDAVPasswordStatus, revokeDAVPassword, type DAVPasswordStatus } from "../../api/contacts";
import { useAuth } from "../../auth";
import { holdForSecret, releaseSecretHold } from "../../lib/secretHold";

type CardDavAccessProps = {
  // Optional: when a caller (ConfigPage) has a page-level status banner,
  // errors are also mirrored there, matching the pre-extraction behaviour.
  // Every caller still gets feedback from the message rendered in this
  // card's own body below, regardless of whether this is supplied.
  setConfigStatus?: (status: string) => void;
  // Optional: lets a caller (ConfigPage) know a just-generated password is
  // on screen and unrecoverable if lost, so it can block navigation that
  // would unmount this component and destroy the only copy of it.
  onRevealedPasswordChange?: (revealed: boolean) => void;
};

export function CardDavAccess({ setConfigStatus, onRevealedPasswordChange }: CardDavAccessProps = {}) {
  const auth = useAuth();
  const [davStatus, setDavStatus] = useState<DAVPasswordStatus | null>(null);
  const [davBusy, setDavBusy] = useState(false);
  const [revealedPassword, setRevealedPassword] = useState("");
  // Set once the user has copied the password successfully or clicked "Done"
  // — either counts as "saved it" per the product ruling, and un-arms the
  // caller's navigation guard even while the password stays on screen (Copy)
  // or clears it outright (Done). Reset to false on every newly-generated
  // password so a fresh secret needs its own acknowledgement.
  const [passwordAcknowledged, setPasswordAcknowledged] = useState(false);
  const [copyStatus, setCopyStatus] = useState("");
  const [davMessage, setDavMessage] = useState("");
  const davURL = auth.username ? `${window.location.origin}/dav/${encodeURIComponent(auth.username)}/contacts/` : "";

  useEffect(() => {
    const blocking = revealedPassword !== "" && !passwordAcknowledged;
    onRevealedPasswordChange?.(blocking);
    // The caller's guard only covers its own tab strip. A sidebar link is a
    // route change, which unmounts this component and destroys the password
    // without ever going through that guard — so hold navigation here too,
    // at the source, where it applies wherever this section is rendered.
    if (blocking) {
      holdForSecret(
        "Copy or dismiss the generated CardDAV password before leaving — it will not be shown again."
      );
    } else {
      releaseSecretHold();
    }
    // If this component unmounts (e.g. the settings sidebar's "Configuration"
    // link re-navigates to the same route while ConfigPage stays mounted)
    // while a password is still on screen and un-acknowledged, the caller
    // would otherwise be left with a guard that can never clear — there is
    // no one left to call onRevealedPasswordChange(false). Un-arm it here.
    return () => {
      onRevealedPasswordChange?.(false);
      releaseSecretHold();
    };
  }, [revealedPassword, passwordAcknowledged, onRevealedPasswordChange]);

  async function refreshDavStatus() {
    setDavStatus(await getDAVPasswordStatus());
  }

  useEffect(() => {
    void refreshDavStatus().catch(() => undefined);
  }, []);

  async function generateDavPassword() {
    setDavBusy(true);
    setCopyStatus("");
    setDavMessage("");
    try {
      const generated = await generateDAVPassword();
      setRevealedPassword(generated.password);
      setPasswordAcknowledged(false);
      await refreshDavStatus();
    } catch (error: unknown) {
      const message = `Failed to generate CardDAV password: ${toErrorMessage(error, "unknown error")}`;
      setDavMessage(message);
      setConfigStatus?.(message);
    } finally {
      setDavBusy(false);
    }
  }

  async function revokeDavPassword() {
    if (
      !window.confirm(
        "Revoke the CardDAV app password? Any connected CardDAV client will stop syncing until you generate a new one."
      )
    ) {
      return;
    }
    setDavBusy(true);
    setCopyStatus("");
    setDavMessage("");
    try {
      await revokeDAVPassword();
      setRevealedPassword("");
      await refreshDavStatus();
    } catch (error: unknown) {
      const message = `Failed to revoke CardDAV password: ${toErrorMessage(error, "unknown error")}`;
      setDavMessage(message);
      setConfigStatus?.(message);
    } finally {
      setDavBusy(false);
    }
  }

  function copyDavPassword() {
    if (!revealedPassword || !navigator.clipboard?.writeText) {
      return;
    }
    void navigator.clipboard.writeText(revealedPassword).then(
      () => {
        setCopyStatus("Copied to clipboard.");
        // A successful copy is one of the two ways the ruling allows a
        // caller's navigation guard to clear — the password is safely saved
        // elsewhere even though it stays visible here. A FAILED copy does
        // NOT acknowledge it: the guard must stay armed until the user
        // either retries successfully or clicks "Done" instead.
        setPasswordAcknowledged(true);
      },
      () => setCopyStatus("Could not copy automatically — copy it manually.")
    );
  }

  // The other way out of a caller's navigation guard: explicit
  // acknowledgement that the password has been saved, which also hides it
  // from this screen permanently (see the button's own label/copy below).
  function dismissRevealedPassword() {
    setRevealedPassword("");
    setPasswordAcknowledged(false);
    setCopyStatus("");
  }

  return (
    <div className="config-card">
      <h3>CardDAV Access</h3>
      <p className="config-muted">
        Point a CardDAV-capable app (iOS/macOS Contacts, Nextcloud, Thunderbird, or the KyPost mobile app) at
        the address below using an app-specific password — never your account login password.
      </p>
      {davURL ? (
        <div className="contacts-dav-url">
          <code>{davURL}</code>
        </div>
      ) : null}
      <div className="contacts-dav-status">
        {davStatus?.configured ? (
          <span className="contacts-badge contacts-status-active">
            <span className="contacts-dot" aria-hidden="true" />
            app password configured
          </span>
        ) : (
          <span className="contacts-badge contacts-status-inactive">
            <span className="contacts-dot" aria-hidden="true" />
            no app password yet
          </span>
        )}
      </div>
      {revealedPassword ? (
        <div className="contacts-dav-reveal">
          <p className="config-muted">
            Copy this now — it will not be shown again. Use it as the password for the CardDAV account above.
          </p>
          <div className="contacts-dav-secret">
            <code>{revealedPassword}</code>
            <button type="button" onClick={copyDavPassword}>
              Copy
            </button>
            <button type="button" onClick={dismissRevealedPassword}>
              Done — I saved it
            </button>
          </div>
          <p className="config-muted">
            Clicking &ldquo;Done — I saved it&rdquo; hides this password from the screen permanently — it cannot be
            shown again.
          </p>
          {copyStatus ? <p className="config-muted">{copyStatus}</p> : null}
        </div>
      ) : null}
      <div className="config-actions">
        <button type="button" onClick={() => void generateDavPassword()} disabled={davBusy}>
          {davBusy ? "Working..." : davStatus?.configured ? "Regenerate Password" : "Generate Password"}
        </button>
        {davStatus?.configured ? (
          <button type="button" onClick={() => void revokeDavPassword()} disabled={davBusy}>
            Revoke
          </button>
        ) : null}
      </div>
      {davMessage ? <p className="config-muted">{davMessage}</p> : null}
    </div>
  );
}
