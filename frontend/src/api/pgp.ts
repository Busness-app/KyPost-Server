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
  advertiseAutocrypt: boolean;
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

export type DiscoverySuppression = {
  email: string;
  suppressedAt: string;
  reason: "deleted" | "explicit";
};

export function listDiscoverySuppressions(): Promise<{ suppressions: DiscoverySuppression[] }> {
  return getJSON<{ suppressions: DiscoverySuppression[] }>("/api/pgp/discovery/suppressions");
}

export function removeDiscoverySuppression(email: string): Promise<{ ok: boolean }> {
  return deleteJSON<{ ok: boolean }>(`/api/pgp/discovery/suppressions/${encodeURIComponent(email)}`);
}

export function suppressContactDiscovery(contactUID: string): Promise<{ uid: string }> {
  return postJSON<{ uid: string }>("/api/pgp/discovery/suppress-contact", { contactUID });
}

// WKDDomainClaim mirrors backend/internal/wkdpublish.Claim's JSON shape
// (see wkdpublish/store.go), as returned by both the GET list and embedded
// (via Go struct embedding) in the POST claim response.
export type WKDDomainClaim = {
  domain: string;
  token: string;
  verified: boolean;
  createdAt: string;
  verifiedAt?: string;
  lastCheckedAt?: string;
};

// WKDDomainClaimResponse is the POST /api/pgp/wkd/domains response: the
// claim plus the literal DNS TXT record name/value to add (see
// wkdClaimResponse in backend/internal/api/pgp_wkd_publish.go).
export type WKDDomainClaimResponse = WKDDomainClaim & {
  recordName: string;
  recordValue: string;
};

export function listWKDDomains(): Promise<{ domains: WKDDomainClaim[] }> {
  return getJSON<{ domains: WKDDomainClaim[] }>("/api/pgp/wkd/domains");
}

export function claimWKDDomain(domain: string): Promise<WKDDomainClaimResponse> {
  return postJSON<WKDDomainClaimResponse>("/api/pgp/wkd/domains", { domain });
}

export function verifyWKDDomain(domain: string): Promise<{ verified: boolean }> {
  return postJSON<{ verified: boolean }>(`/api/pgp/wkd/domains/${encodeURIComponent(domain)}/verify`, {});
}

export function deleteWKDDomain(domain: string): Promise<void> {
  return deleteJSON<void>(`/api/pgp/wkd/domains/${encodeURIComponent(domain)}`);
}

// wkdDomainRecord derives the DNS TXT record a claim needs, the same way
// the backend does (wkdpublish.TXTRecordName + "kypost-wkd-verify=" +
// token — see handleWKDDomains). The GET list response only carries
// domain/token per claim (not a per-item recordName/recordValue — those
// are only on the POST response), so this lets already-claimed, still-
// unverified domains re-display their DNS instructions without a second
// POST.
export function wkdDomainRecord(claim: Pick<WKDDomainClaim, "domain" | "token">): {
  name: string;
  value: string;
} {
  return { name: `_kypost-wkd.${claim.domain}`, value: `kypost-wkd-verify=${claim.token}` };
}
