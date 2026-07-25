# WKD Publishing Setup Guide

## Overview

Web Key Directory (WKD) lets strangers look up a user's PGP public key by
email address and send them end-to-end encrypted mail without anyone
handing the key over directly. Compatible clients (GnuPG, Thunderbird, etc.)
resolve `user@example.com` to an HTTPS URL under `example.com` and fetch the
key from there.

**The important part for operators: WKD has nothing to do with where mail
is delivered.** It is a plain HTTPS lookup, not an MX record. Mail can keep
flowing through Gmail, Fastmail, or anywhere else — this server only needs
to be reachable at a specific `openpgpkey.` subdomain to answer key lookups
for the domain. Nothing about MX or mail routing changes.

**This is a two-role setup:**
- **Administrators** claim and verify domains at the instance level (DNS TXT
  record, once per domain) and point `openpgpkey.<domain>` at this server.
  Both of those are the operator's job, which is exactly why domain setup is
  admin-only: a user could verify the TXT record and still get nothing but
  404s forever if `openpgpkey.<domain>` was never wired up, and only the
  operator controls that DNS.
- **Users** then individually opt in (or out) of publishing their own key,
  with no DNS involvement on their end — publishing only requires an address
  they actually send from, on a domain the admin has already verified.

**Quick Links:**
- For admins: **Settings → Configuration → WKD Domains** tab — see
  [Step 1](#step-1-admin-claim-and-verify-the-domain) and
  [Step 2](#step-2-admin-point-openpgpkeydomain-at-this-server) below
- For users: **Security** page → "Publish my public key via Web Key
  Directory (WKD)" — see [Step 3](#step-3-user-opt-in-to-publishing) below
- For troubleshooting: see [Troubleshooting](#troubleshooting)

---

## How Publishing Works

Serving a key for `user@example.com` requires all three of these to be true
at once:

1. **The domain is verified at the instance level** — an admin proved
   control of `example.com` via a DNS TXT record.
2. **`openpgpkey.example.com` actually reaches this server** — otherwise no
   WKD client's lookup ever arrives here in the first place.
3. **The user has publishing turned on**, and `user@example.com` is an
   address that user actually sends from (their connected mail account, or
   a verified send-as alias) — this is the anti-impersonation check: a
   verified domain alone never lets one user's key be served under an
   address that belongs to someone else, or to nobody.

Steps 1 and 2 are one-time, admin-side DNS work per domain. Step 3 is a
per-user toggle, on by default, with nothing to configure beyond that.

---

## Step 1 (admin): Claim and verify the domain

1. Go to **Settings → Configuration**, then the **WKD Domains** tab (only
   visible to administrators).
2. Under **"Domain to publish keys for"**, enter a domain this instance's
   users send mail from and click **Add domain**. Any domain the admin
   controls can be added here — there's no restriction to a domain matching
   the admin's own address, since this is an instance-wide claim, not a
   personal one.
3. The app shows a DNS TXT record to add:
   - **Name:** `_kypost-wkd.<domain>`
   - **Value:** `kypost-wkd-verify=<token>` (a random token generated per
     claim)
4. Add that TXT record with your DNS provider.
5. Back in the app, click **Verify**. The server looks up the TXT record and
   marks the domain verified if the value matches.

Re-adding a domain that's already claimed mints a fresh token and resets it
to unverified — the DNS record needs updating and re-verifying.

## Step 2 (admin): Point `openpgpkey.<domain>` at this server

The TXT record above only proves ownership; it does not make lookups reach
this server. WKD clients query `https://openpgpkey.<domain>/.well-known/openpgpkey/...`,
so you also need:

- A DNS record for `openpgpkey.<domain>` — a CNAME or A record pointing at
  this instance, or a Cloudflare Tunnel public hostname if you're not
  exposing the server directly.
- A valid TLS certificate that covers `openpgpkey.<domain>`. WKD clients
  fetch over HTTPS and will not fall back to plaintext.

Once both the TXT proof (Step 1) and the `openpgpkey.` hostname (Step 2)
are in place, this server is capable of answering key lookups for that
domain — subject still to each individual user's opt-in (Step 3).

### Direct-method alternative

If this same instance also serves the domain's apex (i.e. `https://<domain>/`
is this server, not a separate website), WKD also works via the "direct"
method at `https://<domain>/.well-known/openpgpkey/hu/<hash>` — no
`openpgpkey.` subdomain needed. Clients try the advanced method
(`openpgpkey.<domain>`) first and fall back to direct only if that fails, so
most operators serving mail from a subdomain or a different web host should
rely on the advanced method (Step 2) instead.

## Step 3 (user): Opt in to publishing

Each user controls their own key independently, with no DNS involved:

1. Go to **Security** in the app.
2. Under **Key discovery**, toggle **"Publish my public key via Web Key
   Directory (WKD)"**. It's **on by default**.
3. That's all a user needs to do. If the domain of their mailbox address (or
   a verified send-as alias) has been claimed and verified by an admin
   (Steps 1–2), and their key exists, it becomes servable at that address as
   soon as the toggle is on.

Turning the toggle off immediately stops that user's key from being served,
even if the domain stays verified — the per-user setting is checked on every
lookup.

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
- The lookup only succeeds if all three conditions from
  [How Publishing Works](#how-publishing-works) hold for that exact address:
  domain verified, that user's publish toggle on, and `user@example.com`
  actually belonging to that user.

---

## Ongoing behavior: re-checks and suspension

Once a domain is verified, the server periodically re-confirms that its TXT
proof is still in place — every **12 hours** per domain, checked once more
at server startup. If the record is removed (or changed) and a re-check
genuinely fails to find it, the domain is marked unverified and the server
**stops serving any user's key for that domain** until it's verified again.

A transient DNS failure (the lookup itself erroring, rather than succeeding
and finding no matching record) does **not** suspend the domain — only a
completed lookup that comes back without the expected TXT value flips it to
unverified.

This re-check only concerns the admin-side domain claim. A user's own
publish toggle (Step 3) isn't touched by it — turning that on or off is
purely a user action.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Clicking Verify (Configuration → WKD Domains) returns "unverified" | TXT record hasn't propagated yet, or the value doesn't match | Wait for DNS propagation and re-check the exact value shown in-app (`kypost-wkd-verify=<token>`); re-click Verify |
| `gpg --locate-keys` 404s / finds nothing | Any one of: `openpgpkey.<domain>` isn't pointed at this server or lacks valid TLS; the domain isn't verified in Configuration → WKD Domains; the target user has their WKD publish toggle off; the address isn't that user's mailbox address or a verified send-as alias | Confirm the `openpgpkey.` DNS record/cert, the domain's verified status (admin), the user's Security-page toggle, and that the address matches an address they actually send from |
| "WKD Domains" tab isn't visible | The tab only renders for administrators | Only an admin account can manage domain claims; ask an admin to add/verify the domain |
| A user's key stopped being served, domain still shows verified | The user turned off "Publish my public key via Web Key Directory (WKD)" on their own Security page | Have that user re-enable the toggle if they want to be discoverable again |
| Domain was verified but stopped serving for everyone on it | The TXT record was removed or changed, and the periodic re-check (every 12h, plus at startup) caught it | Re-add the TXT record and click Verify again in Configuration → WKD Domains |

---

## Companion feature: outbound Autocrypt headers

Separately from WKD, this server can add an `Autocrypt:` header to outgoing
mail so recipients whose clients support Autocrypt can discover the
sender's key automatically — no DNS setup required. It's on by default;
toggle it under **Security → "Advertise my public key on outgoing mail
(Autocrypt)"**.
