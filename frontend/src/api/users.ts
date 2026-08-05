import { getJSON, postJSON, putJSON } from "./client";
import type { Role } from "../auth";

export type ManagedUser = {
  id: string;
  username: string;
  role: Role;
  active: boolean;
  mustChangePassword: boolean;
  createdAt: string;
  updatedAt: string;
  deactivatedAt?: string;
  totpEnabled?: boolean;
};

type UsersListResponse = {
  users: ManagedUser[];
};

export async function listUsers(): Promise<ManagedUser[]> {
  const res = await getJSON<UsersListResponse>("/api/users");
  return res.users ?? [];
}

export function createUser(username: string, password: string, role: Role): Promise<ManagedUser> {
  return postJSON<ManagedUser>("/api/users", { username, password, role });
}

export function setUserRole(id: string, role: Role): Promise<ManagedUser> {
  return putJSON<ManagedUser>(`/api/users/${encodeURIComponent(id)}`, { role });
}

/**
 * Resets an account's password to a temporary one.
 *
 * `pgpKeyDestroyed` reports whether this reset made a client-protected PGP key
 * permanently unrecoverable. The key is wrapped under the account password and
 * the server cannot open it, so an admin cannot rewrap what they cannot read —
 * documented behaviour the USER is warned about, and which the admin doing it
 * previously had no way to know about, before or after.
 */
export function resetUserPassword(
  id: string,
  password: string
): Promise<{ user: ManagedUser; pgpKeyDestroyed: boolean }> {
  return postJSON<{ user: ManagedUser; pgpKeyDestroyed: boolean }>(
    `/api/users/${encodeURIComponent(id)}/reset-password`,
    { password }
  );
}

export function deactivateUser(id: string): Promise<ManagedUser> {
  return postJSON<ManagedUser>(`/api/users/${encodeURIComponent(id)}/deactivate`, {});
}

export function reactivateUser(id: string): Promise<ManagedUser> {
  return postJSON<ManagedUser>(`/api/users/${encodeURIComponent(id)}/reactivate`, {});
}

export function clearUserMFA(id: string): Promise<ManagedUser> {
  return postJSON<ManagedUser>(`/api/users/${encodeURIComponent(id)}/clear-mfa`, {});
}
