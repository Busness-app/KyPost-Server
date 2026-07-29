# Frontend

## Purpose

React 18 single-page application for configuration, health monitoring, classification decision auditing, and log streaming. Served as static files from the Go API server after build.

## Ownership

All code under `frontend/`. Produces a static bundle under `frontend/dist/` consumed by the container.

## Local Contracts

- React 18.3, React Router 6.30, TypeScript, Vite, Quill (WYSIWYG compose editor), qrcode (mobile pairing QR)
- All HTTP calls go through `src/api/client.ts` (`getJSON`, `postJSON`, `putJSON`, `deleteJSON`, `postFormData`) — never use `fetch` directly in page components
- Auth state is owned by `App.tsx` and published through `AuthContext` (`src/auth.tsx`); pages read `{authenticated, userId, username, role, mustChangePassword}` via `useAuth()`, not via direct `/api/auth/me` calls
- RBAC: `protect(element, adminOnly)` in `App.tsx` gates routes (`/users` and `/logs` are admin-only, redirecting non-admins to `/read`); `settingsNavItems` entries carry an `adminOnly` flag that filters the settings nav; `ConfigPage` shows only the Email Settings tab (plus a local theme card) to non-admins — Application/Labels/Remote LLM tabs are admin-only. Frontend gating is UX only; the server enforces all policy
- All pages live under `src/pages/`; routing is defined in `App.tsx`
- Session cookie (`credentials: 'include'`) is required on every API call — this is handled by `client.ts`
- Compose window is owned by `App.tsx`; it always uses Quill WYSIWYG and sends via `POST /api/mail/send` (window auto-closes after successful SMTP send, including success-with-warning responses) and its surface colors follow the active theme tokens
- The compose window autosaves to `localStorage` every 1s (debounced) via `app/draftAutosave.ts`, scoped per user id, and restores on opening a blank compose with a notice. It is a safety net under the explicit **Save Draft** button, not a replacement: `POST /api/mail/draft` is a bare IMAP APPEND with no UID and no replace, so autosaving server-side would append a new draft per tick, and it rejects a draft with no recipient. Attachment BYTES are never stored (localStorage caps ~5MB, one attachment may be 25MB) — only names, so the restore notice can name what to re-attach. Cleared on send, on explicit Save Draft, on Trash, and on logout
- Large pages keep their hooks and state in the page component and push everything else into a sibling folder: `pages/read/` (ReadPage), `pages/contacts/` (ContactsPage), `pages/config/` (ConfigPage), `app/` (App.tsx). Those modules are pure logic, shared types, or presentational components that take every binding as a prop — **do not add hooks to them**, since several render conditionally and would move hook order into a component that sometimes does not render.
- `ReadPage.tsx`'s pure logic lives in `pages/read/`: `types.ts` (shared shapes and list/swipe constants), `format.ts` (display formatting), `compose.ts` (reply/forward body building and reply-all recipients, covered by `compose.test.ts`). Quoting in `compose.ts` MUST route through `processEmailHtml`, never `sanitizeEmailHtml` alone — the latter does not strip `<img>`, so quoting a message whose images the user declined would fire its tracking pixels into the compose editor
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
- Preset names include: Dark Matter, Light Matter, Tropics, Tropic Night, Ocean, Coffee, White Cliffs, Cyber Punk, Neon Purple, Space, Sky, Forest, Sun
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
- Quoting, printing, and draft-open block remote content unconditionally; only the read view honors the per-message "Show Images" opt-in, since it is the only one acting on a single message the user has actually chosen to open
- ReadPage shows a `notice notice-error` banner above the PGP badge when a message carries the `$Phishing` IMAP keyword (`lib/phishing.ts`, matched case-insensitively — IMAP keywords are case-insensitive). Advisory only, with no confirm-modal friction, because `processEmailHtml` has already neutralized the dangerous links before render

## Verification

- `npm run build` must succeed with zero TypeScript errors
- Playwright E2E tests live in `scripts/tests/`; run via `scripts/`

## Child DOX Index

No child AGENTS.md files. All frontend code is flat under `src/`.
