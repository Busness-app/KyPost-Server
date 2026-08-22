// The `kypost://native-pair?...` URI. Pure — no React — because the QR payload
// and the desktop deep link are the same string parsed by the same client
// parser, and the encoding of `pin` is the part worth pinning in a test.

export type PairingLinkFields = {
  subscriberId: string;
  subscriberHash?: string;
  serverBaseUrl?: string;
  registerEndpoint?: string;
  pairingToken?: string;
  /** Leaf SPKI pin, absent unless the server terminates TLS itself. */
  tlsPin?: string;
};

export function buildNativePairingLink(pairing: PairingLinkFields): string {
  const params = new URLSearchParams();
  params.set("sub", pairing.subscriberId);
  if (pairing.subscriberHash) {
    params.set("hash", pairing.subscriberHash);
  }
  if (pairing.serverBaseUrl) {
    params.set("srv", pairing.serverBaseUrl);
  }
  if (pairing.registerEndpoint) {
    params.set("reg", pairing.registerEndpoint);
  }
  if (pairing.pairingToken) {
    params.set("pt", pairing.pairingToken);
  }
  // The pin lets the app pin the registration call before it discloses the
  // pairing token and its push credentials, instead of sending them inside a
  // trust-on-first-use window. Absent means TOFU, which is what this did
  // before — see the server's leafSPKIPin.
  //
  // URLSearchParams percent-encodes the base64 alphabet's `+`, `/` and `=`.
  // That is not incidental: a bare `+` in a query string decodes to a space,
  // which corrupts roughly half of all pins, and the app fails closed on a
  // malformed pin rather than dropping back to TOFU. Do not hand-roll this.
  if (pairing.tlsPin) {
    params.set("pin", pairing.tlsPin);
  }
  return `kypost://native-pair?${params.toString()}`;
}
