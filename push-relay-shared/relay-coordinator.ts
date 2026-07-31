/**
 * RelayCoordinator — the strongly-consistent half of the relay's ownership
 * rules, shared by both relay Workers (worker/ and worker-apns/).
 *
 * Two invariants in this relay are check-then-write, and KV cannot hold either
 * of them. KV is eventually consistent: two concurrent requests both read "no
 * owner yet" and both write themselves in as the owner, and the loser's write
 * simply wins or loses by timing.
 *
 *   1. Device-token ownership ("the first key to deliver to a token owns it").
 *      Two relay keys racing the first send to one device token both saw it
 *      unclaimed, so both were allowed through — which is exactly the spoofed-
 *      notification path the pinning exists to close.
 *
 *   2. One active key per registering IP. The prior-key lookup, the revoke, the
 *      mint and the index update were four separate KV operations, so concurrent
 *      /register calls from one address left several permanent active keys.
 *
 * A Durable Object fixes both because every request for one token (or one IP)
 * routes to the same instance by name, and that instance handles them one at a
 * time — the read and the write cannot be interleaved by anyone else. This is
 * the "needs a strongly-consistent store (Durable Object)" that claimTokenForSend
 * previously only documented.
 *
 * Deliberately dumb: it stores an owner id and nothing else. Whether an owning
 * key is still *active* is a KV question (the key records live there), so the
 * caller answers it and comes back with a compare-and-swap (`takeoverFrom`)
 * rather than this class reaching into KV. That keeps the serialized section to
 * one storage read and one storage write.
 */

import { DurableObject } from "cloudflare:workers";

/** Storage keys inside one instance. The instance IS the token/IP, so these are fixed. */
const OWNER_KEY = "owner";
const SEEDED_KEY = "seeded";

export interface ClaimTokenOptions {
  /** The key attempting to claim. */
  keyId: string;
  /**
   * Owner recorded in the pre-Durable-Object KV index, used ONCE to seed this
   * instance so tokens claimed before this change keep their owner. Ignored
   * afterwards — otherwise a token released as dead would silently re-adopt the
   * stale KV value on its next send.
   */
  legacyOwner?: string | null;
  /**
   * Compare-and-swap: take ownership only if the current owner is still this
   * value. The caller sets it after confirming that owner's key is revoked,
   * disabled, expired or deleted. Without the comparison, that confirmation is
   * itself a check-then-write and races a legitimate re-claim.
   */
  takeoverFrom?: string | null;
}

export interface ClaimTokenResult {
  /** Who owns the token after this call. Equal to keyId when the claim succeeded. */
  owner: string;
  /** True when THIS call took ownership, so the caller knows whose claim to roll back. */
  newlyClaimed: boolean;
}

export class RelayCoordinator extends DurableObject {
  /** Reads the owner, seeding once from the legacy KV index if this instance is new. */
  private async currentOwner(legacyOwner?: string | null): Promise<string | undefined> {
    const seeded = await this.ctx.storage.get<boolean>(SEEDED_KEY);
    if (seeded) {
      return this.ctx.storage.get<string>(OWNER_KEY);
    }
    const owner = (legacyOwner ?? "").trim() || undefined;
    await this.ctx.storage.put(owner ? { [SEEDED_KEY]: true, [OWNER_KEY]: owner } : { [SEEDED_KEY]: true });
    return owner;
  }

  /**
   * Claims a device token for keyId. Returns the owner after the call, which the
   * caller compares against keyId to decide allow/deny — the decision and the
   * write happen in one turn here, which is the whole point.
   */
  async claimToken(opts: ClaimTokenOptions): Promise<ClaimTokenResult> {
    const owner = await this.currentOwner(opts.legacyOwner);
    if (owner === undefined) {
      await this.ctx.storage.put(OWNER_KEY, opts.keyId);
      return { owner: opts.keyId, newlyClaimed: true };
    }
    if (owner === opts.keyId) {
      return { owner, newlyClaimed: false };
    }
    if (opts.takeoverFrom && owner === opts.takeoverFrom) {
      await this.ctx.storage.put(OWNER_KEY, opts.keyId);
      return { owner: opts.keyId, newlyClaimed: true };
    }
    return { owner, newlyClaimed: false };
  }

  /**
   * Releases a claim, but only the caller's own — a release is a rollback of a
   * claim made moments earlier in the same request, and an unconditional delete
   * would let a failed send unpin a token that a different key has since taken.
   */
  async releaseToken(keyId: string): Promise<boolean> {
    const owner = await this.ctx.storage.get<string>(OWNER_KEY);
    if (owner !== keyId) {
      return false;
    }
    await this.ctx.storage.delete(OWNER_KEY);
    return true;
  }

  /**
   * Records newKeyId as the one active key for this IP and returns whichever key
   * held it before, for the caller to revoke. Swap-and-return in one turn, so
   * concurrent registrations from one address serialize into a chain: each sees
   * its immediate predecessor and revokes it, and exactly one key survives.
   */
  async claimRegistrationIp(newKeyId: string, legacyKeyId?: string | null): Promise<string | null> {
    const prior = await this.currentOwner(legacyKeyId);
    await this.ctx.storage.put(OWNER_KEY, newKeyId);
    return prior === undefined || prior === newKeyId ? null : prior;
  }
}
