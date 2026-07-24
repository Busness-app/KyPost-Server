# WKD Publishing Setup Guide

## Overview

Web Key Directory (WKD) lets strangers look up your PGP public key by email
address and send you end-to-end encrypted mail without you ever handing them
the key directly. Compatible clients (GnuPG, Thunderbird, etc.) resolve
`user@example.com` to an HTTPS URL under `example.com` and fetch the key from
there.

**The important part for operators: WKD has nothing to do with where your
mail is delivered.** It is a plain HTTPS lookup, not an MX record. Your mail
can keep flowing through Gmail, Fastmail, or anywhere else — this server only
needs to be reachable at a specific `openpgpkey.` subdomain to answer key
lookups for the domain. Nothing about your MX or mail routing changes.

**Quick Links:**
- For users: Security page → "Publish my key (Web Key Directory)"
- For operators: see [DNS Setup](#step-2-point-openpgpkey-at-this-server) below — this is the part that requires you, not the end user, to act
- For troubleshooting: see [Troubleshooting](#troubleshooting)

---

## How Publishing Works

Publishing a domain is a two-part proof, and **both parts are required**:

1. **Prove you own the domain** — add a DNS TXT record, verify it in-app.
   This tells the server it's allowed to serve your key for that domain.
2. **Make lookups actually reach this server** — point `openpgpkey.<domain>`
   at this instance with valid TLS. This is what makes the HTTPS lookup
   succeed at all.

Completing only step 1 proves ownership but nobody's WKD client will ever
reach the server, since their lookup goes to `openpgpkey.<domain>`, not to
wherever the TXT record lives. Completing only step 2 means the server
still won't serve the key, since it hasn't verified you're allowed to
publish for that domain.

---

## Step 1: Claim and verify the domain (in-app)

1. Go to **Security** in the app.
2. Under **"Publish my key (Web Key Directory)"**, enter a domain you send
   mail from and click **Add domain**.
   - You can only claim a domain that matches an address you actually send
     from: the address on your connected mail account, or a verified
     send-as alias. Domains that don't match either are rejected.
3. The app shows a DNS TXT record to add:
   - **Name:** `_kypost-wkd.<domain>`
   - **Value:** `kypost-wkd-verify=<token>` (a random token generated per
     claim)
4. Add that TXT record with your DNS provider.
5. Back in the app, click **Verify**. The server looks up the TXT record and
   marks the domain verified if the value matches.

Re-adding a domain you've already claimed mints a fresh token and resets it
to unverified — you'll need to update the DNS record and verify again.

## Step 2: Point `openpgpkey.<domain>` at this server

The TXT record above only proves ownership; it does not make lookups reach
this server. WKD clients query `https://openpgpkey.<domain>/.well-known/openpgpkey/...`,
so you also need:

- A DNS record for `openpgpkey.<domain>` — a CNAME or A record pointing at
  this instance, or a Cloudflare Tunnel public hostname if you're not
  exposing the server directly.
- A valid TLS certificate that covers `openpgpkey.<domain>`. WKD clients
  fetch over HTTPS and will not fall back to plaintext.

Once both the TXT proof (Step 1) and the `openpgpkey.` hostname (Step 2)
are in place, this server will answer key lookups for that domain.

### Direct-method alternative

If this same instance also serves the domain's apex (i.e. `https://<domain>/`
is this server, not a separate website), WKD also works via the "direct"
method at `https://<domain>/.well-known/openpgpkey/hu/<hash>` — no
`openpgpkey.` subdomain needed. Clients try the advanced method
(`openpgpkey.<domain>`) first and fall back to direct only if that fails, so
most operators serving mail from a subdomain or a different web host should
rely on the advanced method (Step 2) instead.

---

## Verifying it works

From any machine with GnuPG:

```bash
gpg --locate-keys user@example.com
```

If WKD is set up correctly, GnuPG fetches and imports the key automatically.
A couple of details worth knowing:

- The key is served in binary (unarmored) form, per the WKD spec — this is
  normal and expected.
- The WKD "policy" file at `.well-known/openpgpkey/policy` (and the
  domain-scoped `.../<domain>/policy`) is served as an empty 200 response,
  meaning no submission address and no special restrictions.

---

## Ongoing behavior: re-checks and suspension

Once verified, the server periodically re-confirms that the TXT proof is
still in place — every **12 hours** per domain. If the record is removed (or
changed) and a re-check genuinely fails to find it, the domain is marked
unverified and the server **stops serving that domain's key** until it's
verified again.

A transient DNS failure (the lookup itself erroring, rather than succeeding
and finding no matching record) does **not** suspend the domain — only a
completed lookup that comes back without the expected TXT value flips it to
unverified.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Clicking Verify returns "not verified" | TXT record hasn't propagated yet, or the value doesn't match | Wait for DNS propagation and re-check the exact value shown in-app (`kypost-wkd-verify=<token>`); re-click Verify |
| `gpg --locate-keys` 404s / finds nothing | `openpgpkey.<domain>` isn't pointed at this server, or has no valid TLS cert | Confirm the `openpgpkey.` DNS record and certificate cover that exact hostname |
| Address won't publish / domain rejected on Add | The email address isn't one you actually send from | Only your connected mail account's address or a verified send-as alias can be published; add/verify the alias first |
| Domain was verified but stopped serving | The TXT record was removed or changed, and the periodic re-check (every 12h) caught it | Re-add the TXT record and click Verify again |

---

## Companion feature: outbound Autocrypt headers

Separately from WKD, this server can add an `Autocrypt:` header to outgoing
mail so recipients whose clients support Autocrypt can discover your key
automatically — no DNS setup required. It's on by default; toggle it under
**Security → "Advertise my public key on outgoing mail (Autocrypt)"**.
