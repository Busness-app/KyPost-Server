import { getJSON, putJSON } from "../../api/client";
import type { AppConfig } from "../../api/config";

/**
 * Applies a patch to a freshly loaded AppConfig and PUTs the whole object.
 *
 * PUT /api/config replaces the entire config. Application runtime and Label
 * rules live on different panels but share this endpoint, so each must send a
 * complete object built from a current read — never a partial or cached one,
 * or one panel's save can silently wipe fields the other just wrote.
 */
export async function saveConfigPatch(patch: Partial<AppConfig>): Promise<AppConfig> {
  const current = await getJSON<AppConfig>("/api/config");
  const next = { ...current, ...patch };
  await putJSON<{ ok: boolean }>("/api/config", next);
  return next;
}
