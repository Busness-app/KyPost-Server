// Renders the fingerprint/expiry of a contact's armored PGP key, or the
// parse error. openpgp is imported lazily so the ~390 KB bundle is not pulled
// in until a contact actually has a key.

import { useEffect, useState } from "react";

export type PGPKeyResult = { fingerprint: string; keyId: string; expires?: string } | { error: string };

export async function validatePGPKey(armored: string): Promise<PGPKeyResult | null> {
  const trimmed = armored.trim();
  if (!trimmed) return null;
  try {
    const openpgp = await import("openpgp");
    const key = await openpgp.readKey({ armoredKey: trimmed });
    const expirationTime = await key.getExpirationTime();
    const expires = expirationTime instanceof Date ? expirationTime.toISOString().slice(0, 10) : undefined;
    return { fingerprint: key.getFingerprint(), keyId: key.getKeyID().toHex(), expires };
  } catch (error) {
    return { error: error instanceof Error ? error.message : "invalid key" };
  }
}

export function PGPKeyInfo({ armoredKey }: { armoredKey: string }) {
  const [info, setInfo] = useState<PGPKeyResult | null>(null);

  useEffect(() => {
    let cancelled = false;
    void validatePGPKey(armoredKey).then((result) => {
      if (!cancelled) setInfo(result);
    });
    return () => {
      cancelled = true;
    };
  }, [armoredKey]);

  if (!info) return null;
  if ("error" in info) {
    return <p className="contacts-pgp-error">Could not parse key: {info.error}</p>;
  }
  return (
    <p className="contacts-pgp-fingerprint">
      Fingerprint: {info.fingerprint}
      {info.expires ? ` · Expires ${info.expires}` : ""}
    </p>
  );
}
