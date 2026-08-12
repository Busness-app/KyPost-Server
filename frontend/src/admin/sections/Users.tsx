import { FormEvent, useEffect, useState } from "react";
import { toErrorMessage } from "../../api/client";
import {
  clearUserMFA,
  createUser,
  deactivateUser,
  listUsers,
  reactivateUser,
  resetUserPassword,
  setUserRole,
  type ManagedUser
} from "../../api/users";
import { useAuth, type Role } from "../../auth";

function formatJoined(value: string): string {
  const when = new Date(value);
  if (Number.isNaN(when.getTime())) {
    return "";
  }
  return when.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export function Users() {
  const auth = useAuth();
  const [users, setUsers] = useState<ManagedUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState("");
  const [busyId, setBusyId] = useState("");

  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState<Role>("user");
  const [createBusy, setCreateBusy] = useState(false);

  const statusTone = status.toLowerCase().includes("failed") ? "notice notice-error" : "notice notice-success";

  const activeCount = users.filter((user) => user.active).length;
  const adminCount = users.filter((user) => user.role === "admin").length;

  async function refresh() {
    try {
      const next = await listUsers();
      setUsers(next);
    } catch (error: unknown) {
      setStatus(`Failed to load users: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function submitCreate(e: FormEvent) {
    e.preventDefault();
    if (createBusy) return;
    if (!newUsername.trim() || !newPassword.trim()) {
      setStatus("Failed: username and a temporary password are required.");
      return;
    }
    setCreateBusy(true);
    setStatus("");
    try {
      const created = await createUser(newUsername.trim(), newPassword, newRole);
      setNewUsername("");
      setNewPassword("");
      setNewRole("user");
      setStatus(`User ${created.username} created. They must change the temporary password on first login.`);
      await refresh();
    } catch (error: unknown) {
      setStatus(`Failed to create user: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setCreateBusy(false);
    }
  }

  async function withRowBusy(user: ManagedUser, action: () => Promise<void>) {
    setBusyId(user.id);
    setStatus("");
    try {
      await action();
      await refresh();
    } catch (error: unknown) {
      setStatus(`Failed: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setBusyId("");
    }
  }

  function toggleRole(user: ManagedUser) {
    const nextRole: Role = user.role === "admin" ? "user" : "admin";
    void withRowBusy(user, async () => {
      await setUserRole(user.id, nextRole);
      setStatus(`${user.username} is now ${nextRole === "admin" ? "an admin" : "a standard user"}.`);
    });
  }

  function toggleActive(user: ManagedUser) {
    void withRowBusy(user, async () => {
      if (user.active) {
        await deactivateUser(user.id);
        setStatus(`${user.username} deactivated. Their data is retained and they can no longer sign in.`);
      } else {
        await reactivateUser(user.id);
        setStatus(`${user.username} reactivated.`);
      }
    });
  }

  function resetPassword(user: ManagedUser) {
    // The admin has to be told what this does, and — just as important — what it
    // does NOT do. A client-protected PGP key is wrapped under the account
    // password and the server cannot rewrap it, so a reset leaves the key
    // INACCESSIBLE UNDER THE NEW PASSWORD. It is not destroyed: SetPassword
    // touches no envelope field, the wrapping salt lives inside the envelope
    // rather than in LoginSalt, and the old password still opens it through
    // "Key won't unlock?" on the user's security page.
    //
    // Saying "permanently unrecoverable" here was worse than imprecise: it sent
    // users to generate a new identity, which overwrites the envelope and nulls
    // the recovery slots, turning a recoverable state into real data loss.
    if (
      !window.confirm(
        `Reset ${user.username}'s password?\n\n` +
          "If their PGP key is end-to-end protected, it is wrapped under the password they " +
          "chose and this server cannot rewrap it. After the reset they will not be able to " +
          "read encrypted mail until they restore the key with their PREVIOUS password, from " +
          "Security → Mail Keys → \"Key won't unlock?\".\n\n" +
          "If they no longer know that password and hold no recovery backup, the key is lost.\n\n" +
          "Prefer having them change it themselves if they still can."
      )
    ) {
      return;
    }
    const password = window.prompt(`New temporary password for ${user.username}:`);
    if (!password || !password.trim()) {
      return;
    }
    void withRowBusy(user, async () => {
      const result = await resetUserPassword(user.id, password);
      setStatus(
        result.pgpKeyInaccessible
          ? `Password reset for ${user.username}. Their end-to-end PGP key is now inaccessible ` +
            "under the new password. Tell them to restore it with their PREVIOUS password from " +
            "Security → Mail Keys → \"Key won't unlock?\", or from a recovery backup. " +
            "Generating a new identity is the last resort — it permanently discards the old key."
          : `Password reset for ${user.username}. They must change it on next login.`
      );
    });
  }

  function clearMFA(user: ManagedUser) {
    const confirmed = window.confirm(
      `Clear two-factor authentication for ${user.username}? They will need to re-enroll.`
    );
    if (!confirmed) {
      return;
    }
    void withRowBusy(user, async () => {
      await clearUserMFA(user.id);
      setStatus(`Two-factor authentication cleared for ${user.username}.`);
    });
  }

  return (
    <>
      <header className="users-header">
        <div>
          <p>
            Create accounts, adjust roles, reset passwords, and deactivate users. Each user connects their own
            mailbox and manages their own devices and tuning.
          </p>
        </div>
        {!loading && users.length > 0 ? (
          <div className="users-stats">
            <span className="users-stat">
              <strong>{users.length}</strong> total
            </span>
            <span className="users-stat">
              <strong>{activeCount}</strong> active
            </span>
            <span className="users-stat">
              <strong>{adminCount}</strong> admin
            </span>
          </div>
        ) : null}
      </header>

      <div className="users-layout">
        <form onSubmit={submitCreate} className="users-card users-create-card">
          <h3>Create User</h3>
          <p className="users-muted">New members must change their temporary password on first sign-in.</p>
          <label>
            <div>Username</div>
            <input value={newUsername} onChange={(e) => setNewUsername(e.target.value)} autoComplete="off" />
          </label>
          <label>
            <div>Temporary Password</div>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              autoComplete="new-password"
              placeholder="User must change this on first login"
            />
          </label>
          <label>
            <div>Role</div>
            <select value={newRole} onChange={(e) => setNewRole(e.target.value as Role)}>
              <option value="user">user</option>
              <option value="admin">admin</option>
            </select>
          </label>
          <button type="submit" className="users-create-submit" disabled={createBusy}>
            {createBusy ? "Creating..." : "Create User"}
          </button>
        </form>

        <div className="users-card users-list-card">
          <div className="users-list-head">
            <h3>Users</h3>
            {!loading && users.length > 0 ? (
              <span className="users-count">{users.length}</span>
            ) : null}
          </div>

          {loading ? <p className="users-muted">Loading users...</p> : null}
          {!loading && users.length === 0 ? (
            <div className="users-empty">No users found.</div>
          ) : null}

          {!loading && users.length > 0 ? (
            <div className="users-table-wrap">
              <table className="users-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th className="users-col-actions">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => {
                    const isSelf = user.id === auth.userId;
                    const busy = busyId === user.id;
                    const joined = formatJoined(user.createdAt);
                    return (
                      <tr key={user.id} className={busy ? "users-row users-row-busy" : "users-row"}>
                        <td>
                          <div className="users-identity">
                            <span className="users-avatar" aria-hidden="true">
                              {user.username.slice(0, 1).toUpperCase()}
                            </span>
                            <div className="users-identity-text">
                              <span className="users-name">
                                {user.username}
                                {isSelf ? <span className="users-you">you</span> : null}
                              </span>
                              <span className="users-sub">
                                {joined ? `Joined ${joined}` : " "}
                                {user.mustChangePassword ? (
                                  <span className="users-pw-flag" title="Must change password on next login">
                                    password change required
                                  </span>
                                ) : null}
                              </span>
                            </div>
                          </div>
                        </td>
                        <td>
                          <span className={`users-badge users-badge-${user.role}`}>{user.role}</span>
                        </td>
                        <td>
                          <span className={`users-badge users-status-${user.active ? "active" : "inactive"}`}>
                            <span className="users-dot" aria-hidden="true" />
                            {user.active ? "active" : "deactivated"}
                          </span>
                        </td>
                        <td className="users-col-actions">
                          <div className="users-actions">
                            <button
                              type="button"
                              className="users-action"
                              onClick={() => toggleRole(user)}
                              disabled={busy}
                            >
                              {user.role === "admin" ? "Make User" : "Make Admin"}
                            </button>
                            <button
                              type="button"
                              className="users-action"
                              onClick={() => resetPassword(user)}
                              disabled={busy}
                            >
                              Reset Password
                            </button>
                            {user.totpEnabled ? (
                              <button
                                type="button"
                                className="users-action users-action-danger"
                                onClick={() => clearMFA(user)}
                                disabled={busy}
                              >
                                Clear MFA
                              </button>
                            ) : null}
                            <button
                              type="button"
                              className={user.active ? "users-action users-action-danger" : "users-action"}
                              onClick={() => toggleActive(user)}
                              disabled={busy}
                            >
                              {user.active ? "Deactivate" : "Reactivate"}
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : null}
        </div>
      </div>

      {status ? <p className={statusTone}>{status}</p> : null}
    </>
  );
}
