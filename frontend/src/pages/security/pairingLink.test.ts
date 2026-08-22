import { describe, expect, it } from "vitest";
import { buildNativePairingLink } from "./pairingLink";

// A real CertificatePinner.pin() value containing both `+` and `/` — the same
// fixture the client's NativePairingDeepLinkParserTest round-trips.
const REAL_PIN = "sha256/A/8Tbwpsi7a5kM1oSL0mge8ce7V1tL+orlCtOCDaDWw=";

const BASE = {
  subscriberId: "sub-123",
  subscriberHash: "hash-abc",
  serverBaseUrl: "https://relay.example.com",
  registerEndpoint: "https://relay.example.com/api/notifications/native/register",
  pairingToken: "pt-xyz"
};

function query(link: string): URLSearchParams {
  return new URLSearchParams(link.slice(link.indexOf("?") + 1));
}

describe("buildNativePairingLink", () => {
  it("round-trips a real pin through the query string", () => {
    const link = buildNativePairingLink({ ...BASE, tlsPin: REAL_PIN });
    expect(query(link).get("pin")).toBe(REAL_PIN);
  });

  it("percent-encodes the base64 alphabet rather than trusting it to survive", () => {
    const link = buildNativePairingLink({ ...BASE, tlsPin: REAL_PIN });
    // A bare `+` here would decode to a space on the client and be refused.
    expect(link).toContain("pin=sha256%2FA%2F8Tbwpsi7a5kM1oSL0mge8ce7V1tL%2Borl");
    expect(link).not.toContain("tL+orl");
  });

  it("omits pin entirely when the server published none", () => {
    const link = buildNativePairingLink(BASE);
    expect(query(link).has("pin")).toBe(false);
    expect(link.startsWith("kypost://native-pair?")).toBe(true);
  });

  it("still carries the fields the app already depends on", () => {
    const params = query(buildNativePairingLink({ ...BASE, tlsPin: REAL_PIN }));
    expect(params.get("sub")).toBe("sub-123");
    expect(params.get("hash")).toBe("hash-abc");
    expect(params.get("srv")).toBe("https://relay.example.com");
    expect(params.get("reg")).toBe(BASE.registerEndpoint);
    expect(params.get("pt")).toBe("pt-xyz");
  });
});
