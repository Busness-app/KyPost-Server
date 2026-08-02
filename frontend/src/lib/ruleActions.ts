import type { Action } from "../api/rules";

// Mirrors rules.ValidateRule in the backend. The server is the authority — it
// has to be, since the Sieve editor and any API client bypass this file — but
// the builder can construct a rejected rule in two clicks, and finding that out
// from a 400 after pressing Save is a worse way to learn the constraint than
// being told while composing it.

/** Same cap as maxActionsPerRule. */
export const MAX_ACTIONS_PER_RULE = 20;

/**
 * Actions that can take a message out of the poller's retry query: it looks for
 * UNSEEN messages in INBOX, so marking one read or moving it elsewhere means a
 * later action that fails can never be retried.
 */
export const VISIBILITY_CHANGING_ACTIONS = ["read", "move", "archive", "spam", "delete"] as const;

export function isVisibilityChanging(type: string): boolean {
  return (VISIBILITY_CHANGING_ACTIONS as readonly string[]).includes(type);
}

function actionNeedsValue(type: string): boolean {
  return type === "keyword" || type === "unkeyword" || type === "move";
}

/**
 * Returns a human-readable reason the action list would be rejected, or "" when
 * it is valid.
 */
export function ruleActionsError(actions: Action[]): string {
  if (actions.length > MAX_ACTIONS_PER_RULE) {
    return `A rule can have at most ${MAX_ACTIONS_PER_RULE} actions.`;
  }

  let visibilityAt = -1;
  for (let i = 0; i < actions.length; i++) {
    const a = actions[i];
    if (actionNeedsValue(a.type) && !(a.value ?? "").trim()) {
      return a.type === "move"
        ? "The “move” action needs a target folder."
        : `The “${a.type}” action needs a keyword.`;
    }
    if (!isVisibilityChanging(a.type)) continue;
    if (visibilityAt >= 0) {
      return `A rule can only do one of read/move/archive/spam/delete — it has “${actions[visibilityAt].type}” and “${a.type}”.`;
    }
    visibilityAt = i;
  }

  if (visibilityAt >= 0) {
    const last = actions.length - 1;
    const trailingStop = last === visibilityAt + 1 && actions[last].type === "stop";
    if (visibilityAt !== last && !trailingStop) {
      return `“${actions[visibilityAt].type}” has to be the last action (an optional “stop” aside), because anything after it cannot be retried if it fails.`;
    }
  }
  return "";
}
