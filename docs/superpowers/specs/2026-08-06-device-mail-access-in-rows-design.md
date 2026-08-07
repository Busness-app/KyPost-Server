# Device mail access belongs in the device row

Date: 2026-08-06
Status: approved, not yet implemented

## The problem

On the Security page's Devices tab, an account with four paired devices renders
its devices twice:

```
Card 1  Pair a new device
Card 2  Your devices        push checkbox, four device rows (version, updated,
                            masked token, user agent, approver checkbox,
                            Remove), the delivery toggle, revoke-all
Card 3  Encrypted mail on   the SAME four devices again, each with its
        your devices        enrollment state and an Enroll button
```

Card 2 is tall enough on its own to push card 3 below the fold, so the answer to
"can this device read my encrypted mail?" is invisible until you scroll — and
when you find it, it is a second list of the same hardware you were already
looking at.

The duplication runs deeper than the layout. `DeviceEnrollmentCard` calls
`listNativeDevices()` for a list `SecurityPage` has already fetched into
`nativeDevices`, and every `NativeDevice` already carries `encryptionEnrolled`
and `enrollmentPublicKey`. The two fetches even fail identically on purpose:
`SecurityPage.refreshDevices` and `DeviceEnrollmentCard.refresh` both empty the
list and show an error rather than leave a stale one asserting a sealing that no
longer exists, each with its own comment explaining why.

So the second list is a duplicate of the first at the data layer as well as on
screen, and removing it makes the tab shorter rather than merely rearranged.

## What this changes

"Can read encrypted mail" becomes a per-device capability rendered in the device
row, beside "Can approve sign-ins", which is already exactly that kind of fact
about exactly that hardware. Card 3 disappears.

### Data

`DeviceRow` (`pages/security/deviceJoin.ts`) gains:

```ts
mailAccess: "enrolled" | "available" | "unsupported" | "unknown"
```

derived from the device's `enrollmentPublicKey` and `encryptionEnrolled` — the
logic in today's `enrollmentState`, moved and made pure. `"unknown"` is returned
when `row.device` is absent, so a row the inventory does not know about (the
`missingFromInventory` case) never claims a state it cannot support.

`deviceJoin.ts` also gains `countMailEnrolled(rows)`, beside the existing
`countApprovers(rows)`.

`DeviceEnrollmentCard` stops calling `listNativeDevices()`. The list arrives as a
prop, sourced from `SecurityPage`'s existing `nativeDevices`.

**The identity-change refetch moves up with it.** `SecurityPage` must re-run
`refreshDevices()` when the PGP fingerprint changes. This is load-bearing:
replacing the identity clears every non-password envelope slot server-side, so a
list cached across that change would keep showing devices as able to read mail
they can no longer open. It is the guarantee the card's `fingerprint`-keyed
effect exists to provide, and it must not be lost in the move. The failure
behaviour needs no work — `refreshDevices` already clears the list and sets an
error, exactly as the card's `refresh` does.

### Components

`DeviceEnrollmentCard` becomes `DeviceMailAccess`, rendered inside each row's
capabilities cell rather than once as a card.

Its ceremony internals move unchanged: the open-time key snapshot, code
verification, sealing, the failure taxonomy, the three-attempt limit, and the
remove-sealing panel. The snapshot property survives the move by construction —
`openCeremony` captures `device.enrollmentPublicKey` into `ceremony`, and
`submit()` seals to that snapshot and never re-reads the list, so where the list
comes from cannot affect what gets sealed.

Only `openId: string` lifts to `Devices.tsx`. Opening a panel on any row closes
every other, which is today's rule — enroll and remove-sealing are mutually
exclusive so two "Account password" fields are never on screen at once —
extended across rows instead of within one card.

Everything else stays instance state on the row: the ceremony, the typed code,
the password, the attempt counter. A closed row renders no panel, so that state
is unmounted rather than reset by hand — which is what today's "clears the typed
password when the remove confirmation reopens for a different device" behaviour
becomes. The implementer should not carry the manual clearing over; the test
stays, and unmounting is what makes it pass.

The `clientProtected && fingerprint` gate stays: `DeviceMailAccess` renders
nothing without both, so a server-custody or keyless account sees an unchanged
row.

`DeviceList` takes `renderMailAccess?: (row: DeviceRow) => ReactNode` and stays
presentational.

### Row layout

The capabilities cell gains a line under "Can approve sign-ins":

| `mailAccess` | Line |
| --- | --- |
| `enrolled` | Can read encrypted mail — with **Remove sealing** |
| `available` | Not enrolled — cannot read encrypted mail — with **Enroll** |
| `unsupported` | This device's app is too old to be enrolled. Update it and pair again. |
| `unknown` | nothing |

The ceremony and remove-password panels render inline under the open row.

App version, `Updated:`, the masked push token and `UA:` collapse behind
`<details className="sec-details"><summary>Details</summary>`, the pattern
`MailKeys` already uses for "Show public key". Name, transport badge,
capabilities and Remove stay visible. The `missingFromInventory` warning stays
outside the collapse — it is the one thing in the row nobody should have to
click to see, because an approver the list cannot show is an approver the user
cannot revoke.

### Summary strip

The Encryption line on the page-level summary currently reads, under client
custody:

> Only this browser can open mail encrypted to you.

That is false the moment a device is enrolled — enrolling a device is precisely
the act of giving something other than this browser a copy of the key. It
becomes:

> Only this browser and 2 of your 4 devices can open mail encrypted to you.

falling back to the current wording when no device is enrolled. The count comes
from `countMailEnrolled(deviceRows)`, which `SecurityPage` can compute from state
it already holds. The denominator is `pairedCount` — the devices the inventory
knows — so it matches the "4 paired" the Devices line beside it already shows,
and a row that exists only in the MFA status does not inflate it. This is what
puts the answer above the fold on every tab.

## Testing

- `deviceJoin.test.ts`: the `mailAccess` derivation for all four states and
  `countMailEnrolled`. Pure, so cheap.
- `DeviceEnrollmentCard.test.tsx` (28 tests) is repointed at the new component.
  The ~24 covering the gate, the failure taxonomy, revocation and panel
  exclusivity keep their assertions through a new render helper. Four test the
  component's own fetch and move up to the page: identity-change refetch,
  failed-first-load error, and stale-list clearing on a failed refetch.
- New: two rows cannot both have a password field open.
- New: the summary sentence counts enrolled devices, and says the old sentence
  when none are.

The four relocated tests are the ones to be careful with. They currently prove
that a failed refetch clears the list rather than showing stale enrollment; that
proof has to end up asserted against `SecurityPage.refreshDevices`, not quietly
dropped because the component that used to own it no longer exists.

## Out of scope

- The delivery toggle ("How pushes reach your devices") and revoke-all stay
  where they are.
- No change to the enrollment protocol, its endpoints, or the sealing format.
- No change to pairing.
