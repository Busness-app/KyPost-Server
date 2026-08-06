import { getJSON, putJSON } from "../../api/client";

export type LabelPrefs = {
  autoApplyEnabled: boolean;
  /** Set once this account's list has been seeded from the house list. */
  seeded: boolean;
  allowlist: string[];
  keywordMappings: Record<string, string[]>;
};

const EMPTY: LabelPrefs = {
  autoApplyEnabled: true,
  seeded: false,
  allowlist: [],
  keywordMappings: {}
};

/** Fills in anything an older server omits, so callers never see undefined. */
function normalize(raw: Partial<LabelPrefs> | null | undefined): LabelPrefs {
  return {
    autoApplyEnabled: raw?.autoApplyEnabled ?? EMPTY.autoApplyEnabled,
    seeded: raw?.seeded ?? EMPTY.seeded,
    allowlist: raw?.allowlist ?? [],
    keywordMappings: raw?.keywordMappings ?? {}
  };
}

export async function loadLabelPrefs(): Promise<LabelPrefs> {
  return normalize(await getJSON<Partial<LabelPrefs>>("/api/labels/preferences"));
}

/**
 * Applies a patch to a freshly read copy and PUTs the whole document.
 *
 * PUT /api/labels/preferences replaces the account's entire label block. Two
 * separate controls write to it — the auto-apply toggle and the label list —
 * so a caller sending only its own field would blank the other's. Read fresh
 * rather than caching: the two live on different tabs, and a copy taken when
 * one mounted would overwrite whatever the other saved in between.
 */
export async function saveLabelPrefsPatch(patch: Partial<LabelPrefs>): Promise<LabelPrefs> {
  const current = await loadLabelPrefs();
  const next: LabelPrefs = { ...current, ...patch };
  await putJSON<{ ok: boolean }>("/api/labels/preferences", next);
  return next;
}
