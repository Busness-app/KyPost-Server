// Pulling real addresses out of a raw From/To/Cc header value.
//
// This exists because a display name is attacker-controlled and is not
// authenticated by anything: DKIM, SPF and DMARC all validate the domain a
// message was sent from, never the human-readable label in front of it. So a
// message can be perfectly aligned and still arrive as
//
//     From: "evil@attacker.tld" <bob@corp.com>
//
// The previous implementation scanned for the first email-shaped run of
// characters anywhere in the value, which found the address inside the display
// name. Reply, Reply All and Forward all feed from here and carry the quoted
// original, so that silently addressed a whole thread to a party who never sent
// it, while the header on screen still showed Bob.
//
// The rule, shared verbatim with the Android and Linux clients: the real
// address is the LAST angle-addr (`<...>`), because RFC 5322 puts the
// display-name first and the addr-spec last. A bare value with no angle
// brackets is the address itself. Anything without an "@" is not an address and
// yields empty rather than being passed through as a pseudo-recipient.
//
// Extracted from ReadPage.tsx so it can be tested directly — see
// addressText.test.ts, whose vectors are mirrored in the other two clients.

// Splits on commas that are not inside a quoted display name, so
// `"Smith, Bob" <bob@corp.com>` stays one recipient.
function splitTopLevel(value: string): string[] {
  const parts: string[] = [];
  let current = "";
  let inQuotes = false;
  for (const char of value) {
    if (char === '"') {
      inQuotes = !inQuotes;
      current += char;
    } else if (char === "," && !inQuotes) {
      parts.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  parts.push(current);
  return parts;
}

// The addr-spec of one address entry: the last <...> group, else the bare value.
// Returns "" when the result is not address-shaped.
function addressOfEntry(entry: string): string {
  const trimmed = entry.trim();
  if (trimmed === "") {
    return "";
  }
  let candidate = trimmed;
  const close = trimmed.lastIndexOf(">");
  const open = close === -1 ? -1 : trimmed.lastIndexOf("<", close);
  if (open !== -1 && close > open) {
    candidate = trimmed.slice(open + 1, close).trim();
  }
  // Not address-shaped -> not an address. Better to send nowhere than to
  // populate a recipient field with a display name.
  return candidate.includes("@") ? candidate : "";
}

export function firstAddressFromText(value: string): string {
  for (const entry of splitTopLevel(value)) {
    const address = addressOfEntry(entry);
    if (address !== "") {
      return address;
    }
  }
  return "";
}

export function listAddressesFromText(value: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of splitTopLevel(value)) {
    const address = addressOfEntry(entry);
    if (address === "" || seen.has(address.toLowerCase())) {
      continue;
    }
    seen.add(address.toLowerCase());
    out.push(address);
  }
  return out;
}
