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
  // publishWKD controls whether this user's key is published at their mail
  // domain's Web Key Directory location, once an admin has verified that
  // domain via the (admin-only) WKD domain endpoints below. Default true.
  publishWKD: boolean;
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

// The WKD domain-management calls below (list/claim/verify/delete) hit
// admin-only endpoints (`s.withAdmin` on the backend) — they manage the
// instance-wide DNS verification for a mail domain, not any one user's
// key. A non-admin caller gets a 403. See ConfigPage's "WKD key
// publishing (domains)" admin section.

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

// ---- end-to-end (client-protected) key handling ----------------------------

/** The cold-start snapshot — see docs/E2E_PGP.md "Cold start". */
export type PGPBootstrap = {
  hasIdentity: boolean;
  /** "client" (end-to-end), "server" (legacy), or "" (no key). */
  protection: "client" | "server" | "";
  fingerprint: string;
  keyId: string;
  publicKey: string;
  keySource: string;
  createdAt: string;
  /** The self-describing wrapped envelope; empty unless protection is "client". */
  wrappedPrivateKey: string;
  unlockRequired: boolean;
  canDecryptServerSide: boolean;
  migrationAvailable: boolean;
  signerPublicKeys: string[];
  /**
   * Addresses a newly generated key must carry as User IDs — the IMAP
   * account address first, then verified send-as aliases. Empty means no
   * mail account is configured yet; do not guess from the login name, which
   * is often not an email address.
   */
  suggestedUserIDs: string[];
  displayName: string;
  /** Absent on a server older than the payload endpoint. */
  payloadEndpoint?: string;
};

export function getPGPBootstrap(): Promise<PGPBootstrap> {
  return getJSON<PGPBootstrap>("/api/pgp/bootstrap");
}

/** Stores a browser-generated or imported identity. `wrapped` is opaque to the server. */
export function storeClientPGPIdentity(
  publicKey: string,
  wrapped: string,
  source: "generated" | "imported"
): Promise<PGPIdentity> {
  return postJSON<PGPIdentity>("/api/pgp/identity/client", { publicKey, wrapped, source });
}

/** Replaces the wrapped envelope after a password change. */
export function rewrapPGPPrivateKey(wrapped: string): Promise<{ ok: boolean }> {
  return postJSON<{ ok: boolean }>("/api/pgp/identity/rewrap", { wrapped });
}

/**
 * One-time migration: hands a legacy server-held key back so the browser can
 * rewrap it. Requires the account password, not just a session.
 */
export function exportLegacyPGPKey(password: string): Promise<{ privateKey: string; publicKey: string }> {
  return postJSON<{ privateKey: string; publicKey: string }>("/api/pgp/identity/export-legacy", { password });
}

export type PGPMessagePayload = {
  messageId: number;
  mailbox: string;
  encryptedPayload: string;
  signaturePayload: string;
  body: string;
  signerPublicKeys: string[];
};

/** Fetches one message's ciphertext for local decryption. */
export function getPGPMessagePayload(mailbox: string, messageId: string | number): Promise<PGPMessagePayload> {
  const params = new URLSearchParams({ mailbox, messageId: String(messageId) });
  return getJSON<PGPMessagePayload>(`/api/mail/pgp-payload?${params.toString()}`);
}

export type ResolvedRecipientKey = {
  address: string;
  publicKey?: string;
  fingerprint?: string;
  tier: PGPRecipientTier;
  usable: boolean;
};

/** Resolves recipients to actual public keys, running the server's discovery ladder. */
export function resolveRecipientKeys(addresses: string[]): Promise<{ results: ResolvedRecipientKey[] }> {
  return postJSON<{ results: ResolvedRecipientKey[] }>("/api/pgp/recipients/resolve", { addresses });
}

export type ClientEncryptedDelivery = { recipients: string[]; ciphertext: string };

/** Sends browser-encrypted deliveries; the server only relays them. */
export function sendClientEncryptedMail(payload: {
  from: string;
  subject: string;
  deliveries: ClientEncryptedDelivery[];
  to: string[];
  cc: string[];
  bcc: string[];
  /** A complete PGP/MIME message encrypted to the sender's own key. */
  sentCopy: string;
  /** Asserts sentCopy is ciphertext. The server refuses to store it otherwise. */
  sentCopyEncrypted: boolean;
  mode: string;
}): Promise<{ ok: boolean; sentSaved?: boolean; warning?: string }> {
  return postJSON("/api/mail/send-pgp", payload);
}

/**
 * Stores a browser-sealed pickup blob and returns the link to email.
 *
 * The returned url contains the record id and fetch token but NOT the
 * decryption key — the caller appends that as a `#` fragment, which browsers
 * never transmit.
 */
export function createSealedPickup(
  recipient: string,
  sealed: unknown
): Promise<{ id: string; url: string; expiresAt: string }> {
  return postJSON("/api/pgp/pickup", { recipient, sealed: JSON.stringify(sealed) });
}
