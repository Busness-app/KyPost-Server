import { getJSON, postJSON, putJSON, deleteJSON } from "./client";

export type PGPIdentity = {
  fingerprint: string;
  keyId: string;
  publicKey: string;
  source: "generated" | "imported";
  createdAt: string;
};

// PGPRecipientTier mirrors the backend's resolveTier ladder. The
// recipients-check endpoint currently only ever emits "verified" (a usable
// key already pinned to a contact) or "none" — the remaining values are
// produced by the send-time resolver (WKD/keyserver lookups, TOFU
// fingerprint changes) and are included here so the UI can render them
// wherever they do show up without another type change.
export type PGPRecipientTier = "verified" | "wkd" | "keyserver_confirm" | "key_changed" | "none";

export type PGPRecipientStatus = {
  address: string;
  hasKey: boolean;
  tier?: PGPRecipientTier;
};

export type DiscoverySettings = {
  autoEncryptWhenKeyKnown: boolean;
  storeDiscoveredKeys: boolean;
};

export function getPGPIdentity(): Promise<PGPIdentity> {
  return getJSON<PGPIdentity>("/api/pgp/identity");
}

export function generatePGPIdentity(): Promise<PGPIdentity> {
  return postJSON<PGPIdentity>("/api/pgp/identity/generate", {});
}

export function importPGPIdentity(armoredPrivateKey: string, passphrase: string): Promise<PGPIdentity> {
  return postJSON<PGPIdentity>("/api/pgp/identity/import", { armoredPrivateKey, passphrase });
}

export function deletePGPIdentity(): Promise<{ ok: boolean }> {
  return deleteJSON<{ ok: boolean }>("/api/pgp/identity");
}

export function checkPGPRecipients(addresses: string[]): Promise<{ results: PGPRecipientStatus[] }> {
  return postJSON<{ results: PGPRecipientStatus[] }>("/api/pgp/recipients/check", { addresses });
}

export function getPGPDiscoverySettings(): Promise<DiscoverySettings> {
  return getJSON<DiscoverySettings>("/api/pgp/discovery/settings");
}

export function updatePGPDiscoverySettings(settings: DiscoverySettings): Promise<DiscoverySettings> {
  return putJSON<DiscoverySettings>("/api/pgp/discovery/settings", settings);
}

export function lookupPGPKeyserver(
  email: string
): Promise<{ email: string; fingerprint: string; keyId: string; publicKey: string; revoked: boolean; expired: boolean }> {
  return getJSON(`/api/pgp/keyserver/lookup?email=${encodeURIComponent(email)}`);
}
