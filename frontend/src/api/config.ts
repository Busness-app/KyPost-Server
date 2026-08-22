// Global/system config document (admin-editable). Per-user notification
// delivery preferences moved to /api/notifications/preferences.
export type AppConfig = {
  timezone: string;
  logLevel: string;
  scan: { intervalSeconds: number };
  rateLimits: { perMinute: number; perHour: number };
  labels: { allowlist: string[]; keywordMappings: Record<string, string[]> };
  classifier: { baseUrl: string; apiKey: string; classifyPath: string; apiKeySet: boolean };
};

export function uniqueLabels(labels: string[]): string[] {
  return Array.from(new Set(labels.map((label) => label.trim()).filter(Boolean)));
}

function normalizeKeywordMappings(input: unknown): Record<string, string[]> {
  if (!input || typeof input !== "object") return {};
  const source = input as Record<string, unknown>;
  const out: Record<string, string[]> = {};

  for (const [label, rawValues] of Object.entries(source)) {
    const cleanLabel = String(label).trim();
    if (!cleanLabel) continue;

    const values = Array.isArray(rawValues)
      ? uniqueLabels(rawValues.map(String))
      : typeof rawValues === "string"
        ? uniqueLabels(rawValues.split(","))
        : [];

    if (values.length > 0) out[cleanLabel] = values;
  }
  return out;
}

/** obj narrows an unknown to a readable record, so a string or an array where
 *  an object belongs falls back to defaults instead of yielding `undefined`
 *  properties that the callers below would then hand out as typed values. */
function obj(input: unknown): Record<string, unknown> {
  return input !== null && typeof input === "object" && !Array.isArray(input)
    ? (input as Record<string, unknown>)
    : {};
}

function str(value: unknown, fallback: string): string {
  return typeof value === "string" ? value : fallback;
}

function num(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function strArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/**
 * normalizeConfig turns whatever the config endpoint actually returned into an
 * AppConfig, checking each field rather than asserting it.
 *
 * The response crosses a trust boundary: a mixed-version deployment or a
 * hand-edited config file can send `labels.allowlist` as a string, and the
 * previous `as Record<string, any>` handed it straight through as `string[]`.
 * The type system then stops helping — the crash surfaces at the first
 * `.map()`, far from the response that caused it. Every value the type claims
 * is now one this function has actually seen.
 */
export function normalizeConfig(input: unknown): AppConfig {
  const source = obj(input);
  const labels = obj(source.labels);
  const classifier = obj(source.classifier);
  const scan = obj(source.scan);
  const rateLimits = obj(source.rateLimits);

  return {
    timezone: str(source.timezone, "UTC"),
    logLevel: str(source.logLevel, "info"),
    scan: { intervalSeconds: num(scan.intervalSeconds, 90) },
    rateLimits: {
      perMinute: num(rateLimits.perMinute, 10),
      perHour: num(rateLimits.perHour, 20)
    },
    labels: {
      allowlist: strArray(labels.allowlist),
      keywordMappings: normalizeKeywordMappings(labels.keywordMappings)
    },
    classifier: {
      baseUrl: str(classifier.baseUrl, ""),
      // Write-only: the server never echoes the real API key back (see
      // handleConfig), so this is always populated blank here regardless of
      // whatever the response happens to contain. Only a user actively
      // typing into the field should ever put a value here.
      apiKey: "",
      classifyPath: str(classifier.classifyPath, ""),
      apiKeySet: Boolean(classifier.apiKeySet)
    }
  };
}
