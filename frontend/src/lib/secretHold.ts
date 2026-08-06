// A hold placed while a value the server issues ONCE, and cannot reissue, is on
// screen — a generated CardDAV app password, for instance.
//
// The component showing such a value is mounted inside a route. Any navigation
// unmounts it and destroys the only copy, silently. The tabbed pages guard
// their own tab strips, but a sidebar link is a route change and bypasses that
// entirely, which is exactly how a revealed CardDAV password could still be
// lost in one click.
//
// This is a module-level registry rather than context or a router blocker
// because BrowserRouter is not a data router, so useBlocker is unavailable, and
// because the holder and the navigation control are on opposite sides of the
// tree with no common owner below the app root.

let held = "";
const listeners = new Set<(reason: string) => void>();

function notify(): void {
  for (const listener of listeners) {
    listener(held);
  }
}

/**
 * Blocks navigation, with `reason` shown to the user as the explanation.
 * Idempotent: re-holding with the same reason does not re-notify.
 */
export function holdForSecret(reason: string): void {
  if (held === reason) {
    return;
  }
  held = reason;
  notify();
}

/** Releases the hold. Safe to call when nothing is held. */
export function releaseSecretHold(): void {
  if (!held) {
    return;
  }
  held = "";
  notify();
}

/** The current reason, or "" when navigation is free. */
export function secretHoldReason(): string {
  return held;
}

export function subscribeSecretHold(listener: (reason: string) => void): () => void {
  listeners.add(listener);
  listener(held);
  return () => {
    listeners.delete(listener);
  };
}
