import { useState } from "react";
import { useAuth } from "../../../auth";
import { ChangePasswordForm } from "../../../components/ChangePasswordForm";

/**
 * The voluntary password change, behind Security's reauth gate.
 *
 * The FORCED change stays on /password, outside that gate — a user being made
 * to fix their credential cannot be asked to re-authenticate with the very
 * credential they are being made to change. Both entry points render the same
 * form; only the lede and what happens on success differ.
 */
export function Password() {
  const auth = useAuth();
  const [done, setDone] = useState("");

  return (
    <div className="sec-card" id="password">
      <div className="sec-card-head">
        <p className="sec-eyebrow">Sign-in</p>
        <h3>Password</h3>
      </div>
      <div className="sec-section">
        <ChangePasswordForm
          username={auth.username ?? ""}
          lede="Your PGP key is re-encrypted under the new password automatically."
          onSuccess={() => setDone("Password updated.")}
        />
        {done ? (
          <p className="sec-muted" role="status">
            {done}
          </p>
        ) : null}
      </div>
    </div>
  );
}
