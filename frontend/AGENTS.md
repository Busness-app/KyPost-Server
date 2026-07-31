# Frontend

## Purpose

React 19 single-page application for configuration, health monitoring, classification decision auditing, and log streaming. Served as static files from the Go API server after build.

## Ownership

All code under `frontend/`. Produces a static bundle under `frontend/dist/` consumed by the container.

## Local Contracts

- React 19.2, React Router 8.3, TypeScript 7, Vite 8, Quill (WYSIWYG compose editor), qrcode (mobile pairing QR)
- All HTTP calls go through `src/api/client.ts` (`getJSON`, `postJSON`, `putJSON`, `deleteJSON`, `postFormData`) — never use `fetch` directly in page components
- Auth state is owned by `App.tsx` and published through `AuthContext` (`src/auth.tsx`); pages read `{authenticated, userId, username, role, mustChangePassword}` via `useAuth()`, not via direct `/api/auth/me` calls
- RBAC: `protect(element, adminOnly)` in `App.tsx` gates routes (`/users` and `/logs` are admin-only, redirecting non-admins to `/read`); `settingsNavItems` entries carry an `adminOnly` flag that filters the settings nav; `ConfigPage` shows only the Email Settings tab (plus a local theme card) to non-admins — Application/Labels/Remote LLM tabs are admin-only. Frontend gating is UX only; the server enforces all policy
- All pages live under `src/pages/`; routing is defined in `App.tsx`
- Session cookie (`credentials: 'include'`) is required on every API call — this is handled by `client.ts`
- Compose window is owned by `App.tsx`; it always uses Quill WYSIWYG and sends via `POST /api/mail/send` (window auto-closes after successful SMTP send, including success-with-warning responses) and its surface colors follow the active theme tokens
- The compose window autosaves to `localStorage` every 1s (debounced) via `app/draftAutosave.ts`, scoped per user id, and restores on opening a blank compose with a notice. It is a safety net under the explicit **Save Draft** button, not a replacement: `POST /api/mail/draft` is a bare IMAP APPEND with no UID and no replace, so autosaving server-side would append a new draft per tick, and it rejects a draft with no recipient. Attachment BYTES are never stored (localStorage caps ~5MB, one attachment may be 25MB) — only names, so the restore notice can name what to re-attach. Cleared on send, on explicit Save Draft, on Trash, and on logout
- Large pages keep their hooks and state in the page component and push everything else into a sibling folder: `pages/read/` (ReadPage), `pages/contacts/` (ContactsPage), `pages/config/` (ConfigPage), `app/` (App.tsx). Those modules are pure logic, shared types, or presentational components that take every binding as a prop.

  **Never put a hook in a helper that the page calls inline** (a function invoked from JSX, an IIFE in a branch, a `format*`/`build*` module). Several are called conditionally, which would move hook order into a path that sometimes does not run — that is the hazard this rule exists for.

  A real child component with its own hooks is fine and is not what the rule prohibits: React tracks hook order per component instance, so a conditionally *rendered* `<Child />` is unaffected. `read/EmailBodyFrame.tsx` (frame sizing) and `contacts/PGPKeyInfo.tsx` are both this shape.
- `ReadPage.tsx`'s pure logic lives in `pages/read/`: `types.ts` (shared shapes and list/swipe constants), `format.ts` (display formatting), `compose.ts` (reply/forward body building and reply-all recipients, covered by `compose.test.ts`), `EmailBodyFrame.tsx` (the sandboxed iframe an HTML body renders in — see the isolation note below). Quoting in `compose.ts` MUST route through `processEmailHtml`, never `sanitizeEmailHtml` alone — the latter does not strip `<img>`, so quoting a message whose images the user declined would fire its tracking pixels into the compose editor
- `ReadPage.tsx` email-details modal includes `Reply`, `Reply All`, and `Forward` actions that open the shared compose window with prefilled recipient/subject/body context
- Push notifications use `public/sw.js`; `main.tsx` registers the service worker on page load so the Notifications page can subscribe devices and receive push events. The service worker also refreshes push subscriptions when the browser expires them.
- The Notifications page also renders a mobile pairing QR code (using the `qrcode` package): it reads `GET /api/notifications/pairing` and encodes a `kypost://native-pair?sub=&hash=&srv=&reg=&pt=` deep link. `pt` is a 90-second pairing token. A 4px bar under the QR shrinks over the 90-second window, transitions from green to red, stays red for the last 15 seconds, then disappears while the page refreshes the QR. The mobile app scans it and uses `reg` (with `srv` fallback) to register FCM token through `POST /api/notifications/native/register`. `POST /api/notifications/native/unpair` revokes paired native devices.
- On mobile user agents, switching Notifications delivery mode from `none` to `all` or `keywords` shows a browser popup reminder: "To help insure notifications work, please remove your browser from sleep state."
- On mobile touch devices, inbox rows in `ReadPage.tsx` support swipe actions: left swipe archives, right swipe deletes, visual cue appears at 15% swipe (yellow archive / red delete), inline row labels show `Archive` or `Delete` during swipe, action commits only when released past 50% swipe, and supported browsers receive vibration haptic cues at swipe hint/commit thresholds.
- `ReadPage.tsx` exposes a small per-user `Haptics` toggle in the inbox action bar (touch devices) and persists the preference in browser local storage (`kypost-read-swipe-haptics-enabled`).

### Page → API Mapping

| Page | Endpoints used |
|------|---------------|
| `LoginPage.tsx` | `POST /api/auth/login`, `POST /api/auth/password` (`/login` sign-in plus protected `/password` change-password mode), `GET /api/auth/pow-challenge` (`CAPTCHA_PROVIDER=pow` only) |
| `ReadPage.tsx` | `GET /api/inbox?limit=500&mailbox=<name>`, `POST /api/inbox/actions` (bulk inbox actions + read/unread state updates, includes current mailbox context; move actions are triggered by drag-drop from this page) |
| `HealthPage.tsx` | `GET /api/health`, `GET /api/status` (includes `emailsProcessedLastHour`), `POST /api/health/repair` |
| `ConfigPage.tsx` | `GET/PUT /api/config` (admin tabs), `GET/POST/DELETE /api/imap/config` (also carries SMTP host/port for sending), `POST /api/imap/test`, `POST /api/classifier/test` (admin tab), `GET /api/labels` |
| `NotificationsPage.tsx` | `GET/PUT /api/notifications/preferences` (per-user delivery mode + keywords), `GET /api/config` (read-only, for label options), `GET /api/labels`, `GET /api/notifications/vapid-public-key`, `POST /api/notifications/subscriptions`, `POST /api/notifications/test`, `GET /api/notifications/pairing`, `POST /api/notifications/native/unpair`, `GET /api/notifications/native/devices`, `DELETE /api/notifications/native/devices` |
| `ContactsPage.tsx` | `GET/POST /api/contacts`, `GET/PUT/DELETE /api/contacts/{id}`, `POST /api/contacts/dedupe` (the "Merge Duplicates" button — server-side duplicate merge, returns `{mergedCount, groups}`), `GET/POST/DELETE /api/contacts/dav-password` (app-specific CardDAV password; `POST` reveals the raw secret once) via `src/api/contacts.ts`. Mobile/CardDAV sync (`/api/contacts/sync`, `/dav/{username}/contacts/`) is not called from the web UI — see root `Mobile_Contact_Sync.md` |
| `UsersPage.tsx` (admin only) | `GET/POST /api/users`, `PUT /api/users/{id}`, `POST /api/users/{id}/reset-password`, `POST /api/users/{id}/deactivate`, `POST /api/users/{id}/reactivate` via `src/api/users.ts` |
| `TuningPage.tsx` | `GET/PUT /api/tuning` (caller's own prompt) |
| `LogsPage.tsx` (admin only) | `GET /api/logs?file=<name>.log&lines=<n>`, `GET /api/logs/list` |

### App Shell → API Mapping

| Component | Endpoints used |
|-----------|----------------|
| `App.tsx` | `GET /api/auth/me`, `GET /api/inbox/folders`, `POST /api/inbox/folders` (create child folder under Inbox), `PUT /api/inbox/folders` (rename custom Inbox child folder), `DELETE /api/inbox/folders?folder=<path>` (delete custom Inbox child folder after moving messages to its parent), `GET /api/inbox/folders?parent=Archive`, `POST /api/inbox/actions` (drag-drop folder moves), `POST /api/auth/logout`, `POST /api/mail/send`, `POST /api/mail/draft` |

### Theme System

- Client theme selection is local-only and persisted in browser storage (`localStorage` key `kypost-theme`)
- Theme presets are owned by `src/theme.ts`
- Preset names: Dark Matter, Light Matter, Tropics, Tropic Night, Ocean, Coffee, White Cliffs, Cyber Punk, Neon Purple, Space, Sky, Forest, Sun, Patina Ky, Polished Ky. **Patina Ky is the default** (`getStoredTheme`)
- **Every preset's `ink` AND `inkStrong` must clear 4.5:1 (WCAG AA body text) against BOTH `bg` and `panel`.** A mail client's text is the product, and a message the reader cannot see is indistinguishable from a message the client lost. `ink` is the one that slips: it is the secondary colour, so it is easy to treat as decoration, but it is also the smallest text in the reading pane (0.75rem at 0.7 opacity for the remote-images note) and therefore needs more contrast than `inkStrong`, not less. The default theme shipped `ink` at 4.03:1 on `bg` and 3.66:1 on `panel` while its `inkStrong` scored 15.55:1 — the only preset of the fifteen below the floor. A new or edited preset is checked by `pages/read/readability.test.tsx`, which drives every entry in `THEME_OPTIONS` through `applyTheme` and reads the custom properties back, so adding a preset needs no test change
- Theme initialization runs in `main.tsx` before rendering via `applyStoredTheme()`
- Config page includes a Theme selector and Apply Theme button in Application settings

### Auth Flow

1. App mounts → `App.useEffect` calls `GET /api/auth/me`
2. 401 → redirect to `LoginPage`
3. Successful login → session cookie set → redirect to `ReadPage`
4. First login with temporary password → `mustChangePassword` flag → redirect to password-change form

## Work Guidance

- Build: `cd frontend && npm run build`
- Dev server: `cd frontend && npm run dev` (proxies API calls to `localhost:5866`)
- Do not add direct `fetch` calls outside `src/api/client.ts`
- Add new pages to the router in `App.tsx` and the nav layout in the same file
- Left nav inbox links are driven by `GET /api/inbox/folders` for top-level non-Archive folders and `GET /api/inbox/folders?parent=Archive` for archive buckets
- Inbox row uses a right-side `+` toggle to expand/collapse the create-folder form
- Inbox sidebar folder creation uses `POST /api/inbox/folders` with `parent=INBOX`; folder names are single-level only so the server can choose the correct IMAP hierarchy delimiter
- Custom folder controls are behind a three-dot menu with Rename and Delete; built-in IMAP folders must not render this menu
- Dragging an email row from ReadPage and dropping onto a sidebar folder (including Inbox and Archive buckets) sends `POST /api/inbox/actions` with `action=move` and refreshes mailbox views via a `mailbox-move-complete` window event
- ReadPage no longer shows a manual refresh button; it shows a centered clickable "Updated Just Now" label at the bottom of the inbox page and switches to a localized time once the last inbox refresh is older than 3 minutes
- Rendered email HTML in ReadPage forces all links to open in a new tab with `target="_blank"` and `rel="noopener noreferrer"`
- `emailHtml.ts` pins its own URI-scheme allowlist (`ALLOWED_URI_REGEXP`: http/https/mailto/tel/cid plus scheme-less URLs) instead of relying on DOMPurify's default, because this app deliberately navigates to its own `kypost://` scheme in `NotificationsPage.tsx` and every client is that scheme's registered system handler — a widened library default would silently reopen a pairing-phishing hole. A link with a refused scheme is replaced by a visible `[Blocked link: <scheme>:]` text marker rather than having its `href` stripped, which would leave a dead link that looks live. The scheme check normalizes `\x00-\x20` out of the `href` first, matching what DOMPurify does before applying the same regex — otherwise the two disagree on an obfuscated scheme and the anchor slips past the marker only to have its `href` stripped anyway. Held in place by `emailHtml.test.ts`
- **Every path that turns an email body into DOM must call `processEmailHtml(body, showImages)`, not `sanitizeEmailHtml` directly.** `sanitizeEmailHtml` blocks `<style>`/`background`/`svg`/`video`/`audio` but does *not* strip `<img>`; only `processEmailHtml` does that, plus the link blocking. This covers reply and forward quoting, printing, and opening a draft — all of which feed `composeHtmlBody` → `editor.root.innerHTML` — as well as the read view. `sanitizeEmailHtml`'s `blockRemoteContent` parameter defaults to `true` so that a forgotten argument fails closed (a missing image) rather than open (a fired tracking pixel)
- **The read view renders an HTML body inside a sandboxed iframe** (`pages/read/EmailBodyFrame.tsx`), never into the app's own DOM. Sanitized markup used to go through `dangerouslySetInnerHTML`, which made DOMPurify the only structural boundary between a sender and a document holding the non-HttpOnly `csrf_token` cookie and, for a client-protected account, an unlocked private key in `keyVault.ts` module memory. The sandbox value is `allow-same-origin allow-popups allow-popups-to-escape-sandbox`: **never add `allow-scripts`** — omitting it is what blocks all script execution in the frame, and combined with `allow-same-origin` it would void the sandbox entirely. `allow-same-origin` is present only so the parent can read `contentDocument` to size the frame; an opaque-origin frame cannot be measured and every message renders clipped. The frame inherits NO app stylesheet by design, so anything it needs is injected into its own document: colours come from `--ink-strong`/`--bg` read at render time and validated against a colour pattern before interpolation. Do NOT use CSS system keywords there — `CanvasText` under `color-scheme: normal` resolves to black, and over the default `#1a1a1e` theme that rendered every HTML email black-on-black. Sizing feeds the measured height back into the frame's own containing block, so `measure` clamps to `MAX_FRAME_HEIGHT` and ignores sub-pixel changes: DOMPurify allows the presentational `height` attribute, making `<table height="150%">` a sender-triggered render loop without it. `onLoad` runs twice per mount (about:blank is `readyState === "complete"` before the srcdoc parses), so it disconnects any previous `ResizeObserver` before creating one. Geometry belongs on `.email-reader-body-frame`; `.email-reader-body-block` is the plain-text `<pre>` and its text properties do nothing to an iframe
- **Do not sniff whether a body is HTML, and never pick the body and its mode separately.** Call `displayBody(email, decrypted)` (`pages/read/body.ts`), which returns the pair. A message has up to two bodies — the server's and the locally decrypted one — each with its own mode, and they are not interchangeable: `email.bodyMode` describes the ENVELOPE, and a `multipart/encrypted` envelope says nothing about the plaintext inside it. Four call sites (reader, reply, forward, print) used to choose independently and three read `email.bodyMode` unconditionally.
- Sniffing is now the last resort for ONE case: a mail-cache entry written before the server reported `bodyMode`. Client-decrypted PGP no longer guesses — `lib/mimeContent.ts` parses the decrypted MIME entity and reads the mode off the part's own `Content-Type`, mirroring the server's `pgpmail.ParseContent` (change one, change both, or the same message renders differently for a client-protected account than a server-side one). It also strips the MIME headers, which used to be displayed as part of the message.
- When `looksLikeHtml` must guess, it requires a REAL element (not `HTMLUnknownElement`) *and* that parsing changed the text. Both previous attempts were wrong in opposite directions: `/<[^>]+>/` matched `<user@example.com>` and deleted the address; a 34-tag allowlist missed `<center>`/`<figure>`/`<code>` while calling `the <p> tag` markup. It deliberately errs toward `html` for prose mentioning a known tag — a known element renders as itself and the surrounding words survive — and never for an unknown one, which would swallow its content. **Do not relax the real-element check**
- **The reader supplies both halves of the colour contrast, so the sanitizer strips a sender's colours — `style`, `class`, `id`, `color` and `bgcolor` together.** A message is painted on the reader's theme background and the sender cannot see which theme that is, so `<font color="#000000">` is 1.05:1 on the default `#0d0f14`: invisible, and it reads as a lost message rather than a styling glitch. **Strip both directions or neither.** Half the pair is worse than all of it — a message that sets only a background keeps a dark panel under theme-light text, and one that sets only a foreground puts dark text on a dark theme. `color`/`bgcolor` used to survive while `style` did not, so the same message lost its CSS colours and kept its attribute ones. Layout attributes DOMPurify allows (`align`, `width`, `height`) are deliberately untouched: they do not affect legibility, and stripping them reflows real mail for nothing. Pinned by `pages/read/readability.test.tsx`
- **`EmailBodyFrame` resolves its foreground and background AS A PAIR** (`framePalette`), never each with its own fallback. Contrast is a property of two colours, so neither may be chosen alone: falling back independently gave the light-mode fallback ink `#111111` over the theme's real dark `--bg`, which is 1.09:1 — the identical black-on-near-black failure the colour injection exists to prevent, reached through one missing custom property instead of through a system colour keyword, and far likelier since it needs only one of the two to be absent or mid-transition. Either the theme supplies both or the fallback pair is used whole
- `processEmailHtml` parses into `document.body` and must never wrap content in an element and read that element's `innerHTML` back: the HTML parser closes the wrapper on the first stray `</div>`, dropping the rest of the message and skipping the link-hardening pass for anything after it. Unbalanced div nesting is routine in real mail. Regression cases live in `emailHtml.test.ts`
- Quoting, printing, and draft-open block remote content unconditionally; only the read view honors the per-message "Show Images" opt-in, since it is the only one acting on a single message the user has actually chosen to open
- ReadPage shows a `notice notice-error` banner above the PGP badge when a message carries the `$Phishing` IMAP keyword (`lib/phishing.ts`, matched case-insensitively — IMAP keywords are case-insensitive). Advisory only, with no confirm-modal friction, because `processEmailHtml` has already neutralized the dangerous links before render

## Verification

- `npm run build` must succeed with zero TypeScript errors
- `npm test` (vitest) must pass. `pages/read/readability.test.tsx` covers the reading surface across every theme × both body modes and is the check a new theme preset or a sanitizer allowlist change has to clear
- Playwright E2E tests live in `scripts/tests/`; run via `scripts/`

## Child DOX Index

No child AGENTS.md files. All frontend code is flat under `src/`.
