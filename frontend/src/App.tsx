import { type DragEvent, useEffect, useRef, useState } from "react";
import { Link, Navigate, Route, Routes, useLocation, useNavigate } from "react-router";
import Quill from "quill";
import "quill/dist/quill.snow.css";
import { deleteJSON, getJSON, HttpError, postJSON, putJSON, toErrorMessage } from "./api/client";
import { checkPGPRecipients, getPGPDiscoverySettings, type DiscoverySettings, type PGPRecipientTier } from "./api/pgp";
import { listSendAsAliases, type SendAsAlias } from "./api/sendas";
import { AuthContext, type AuthState } from "./auth";
import { ContactPickerModal } from "./components/ContactPickerModal";
import { RecipientField } from "./components/RecipientField";
import { useDialogOpen } from "./hooks/useDialogOpen";
import { contactToToken, isDuplicateInField, parseRecipientField, pickupFallbackFlag, serializeRecipientField, splitAddressList } from "./lib/recipients";
import { isClientProtected, needsUnlock, loadPGPSession, clearPGPSession } from "./lib/pgpSession";
import { buildEncryptedDeliveries, buildEncryptedSentCopy, OUTER_PLACEHOLDER_SUBJECT } from "./lib/pgpClient";
import { sealPickup } from "./lib/pickupCrypto";
import { createSealedPickup, resolveRecipientKeys, sendClientEncryptedMail } from "./api/pgp";
import { PgpUnlockDialog } from "./components/PgpUnlockDialog";
import type { RecipientFieldState, RecipientToken } from "./lib/recipients";
import { ConfigPage } from "./pages/ConfigPage";
import { ContactsPage } from "./pages/ContactsPage";
import { HealthPage } from "./pages/HealthPage";
import { LoginPage } from "./pages/LoginPage";
import { LogsPage } from "./pages/LogsPage";
import { NotificationsPage } from "./pages/NotificationsPage";
import { ReadPage } from "./pages/ReadPage";
import { RulesPage } from "./pages/RulesPage";
import { SecurityPage } from "./pages/SecurityPage";
import { TuningPage } from "./pages/TuningPage";
import { UsersPage } from "./pages/UsersPage";
import { ReauthGate, clearReauth } from "./components/ReauthGate";
import agplLicenseText from "./agpl-3.0.txt?raw";

import { APP_VERSION, settingsNavItems } from "./app/navigation";
import type {
  BeforeInstallPromptEvent,
  InboxFolder,
  InboxFoldersResponse,
  CreateFolderResponse,
  DeleteFolderResponse,
  RenameFolderResponse,
  MoveInboxActionResponse,
  DragMessagePayload,
  DraftComposePayload,
  ComposeAttachment
} from "./app/types";
import {
  MAX_ATTACHMENT_BYTES,
  readFileAsAttachment,
  formatBytes,
  keylessRecipientsFrom409,
  deliverSealedPickupLinks,
  combineWarnings,
  secureLinkWarning
} from "./app/compose";
import {
  clearDraftSnapshot,
  loadDraftSnapshot,
  purgeExpiredDraftSnapshots,
  restoreNotice,
  saveDraftSnapshot
} from "./app/draftAutosave";

export function App() {
  const location = useLocation();
  const navigate = useNavigate();
  const [auth, setAuth] = useState<AuthState | null>(null);
  const [mailboxFolders, setMailboxFolders] = useState<InboxFolder[]>([]);
  const [mailboxFoldersLoading, setMailboxFoldersLoading] = useState(false);
  const [inboxCreateOpen, setInboxCreateOpen] = useState(false);
  const [createFolderName, setCreateFolderName] = useState("");
  const [createFolderLoading, setCreateFolderLoading] = useState(false);
  const [createFolderError, setCreateFolderError] = useState("");
  const [archiveOpen, setArchiveOpen] = useState(false);
  const [archiveFolders, setArchiveFolders] = useState<InboxFolder[]>([]);
  const [archiveFoldersLoading, setArchiveFoldersLoading] = useState(false);
  const [folderMenuPath, setFolderMenuPath] = useState("");
  const [deleteFolderLoading, setDeleteFolderLoading] = useState("");
  const [renameFolderLoading, setRenameFolderLoading] = useState("");
  const [deleteFolderError, setDeleteFolderError] = useState("");
  const [dragOverFolder, setDragOverFolder] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [pwaInstallPrompt, setPwaInstallPrompt] = useState<BeforeInstallPromptEvent | null>(null);
  const [pwaInstalled, setPwaInstalled] = useState(false);
  const [composeOpen, setComposeOpen] = useState(false);
  const [contactPickerOpen, setContactPickerOpen] = useState(false);
  const [composeFrom, setComposeFrom] = useState("");
  const [sendAsOptions, setSendAsOptions] = useState<SendAsAlias[]>([]);
  const [composeTo, setComposeTo] = useState<RecipientFieldState>({ tokens: [], draft: "" });
  const [composeCc, setComposeCc] = useState<RecipientFieldState>({ tokens: [], draft: "" });
  const [composeBcc, setComposeBcc] = useState<RecipientFieldState>({ tokens: [], draft: "" });
  const [composeSubject, setComposeSubject] = useState("");
  const [composeHtmlBody, setComposeHtmlBody] = useState("");
  const [composeSending, setComposeSending] = useState(false);
  const [composeUnlockOpen, setComposeUnlockOpen] = useState(false);
  // Opt-in: send keyless recipients a one-time pickup link rather than
  // failing the send. Off by default because it is weaker than PGP. For
  // client-custody accounts this drives a browser-side sealed-pickup flow;
  // for server-custody accounts it travels to the server as
  // allowPickupFallback on the /api/mail/send body, where it is not merely a
  // client-side branch — the server itself refuses the downgrade unless the
  // flag is set.
  const [composeSendLinkForKeyless, setComposeSendLinkForKeyless] = useState(false);
  const [composeSavingDraft, setComposeSavingDraft] = useState(false);
  const [composeError, setComposeError] = useState("");
  const [composeSuccess, setComposeSuccess] = useState("");
  const [composeNotice, setComposeNotice] = useState("");
  const [composeAttachments, setComposeAttachments] = useState<ComposeAttachment[]>([]);
  const [composeEncrypt, setComposeEncrypt] = useState(false);
  const [composeSign, setComposeSign] = useState(false);
  const [composeMissingKeyRecipients, setComposeMissingKeyRecipients] = useState<string[]>([]);
  const [composeRecipientTiers, setComposeRecipientTiers] = useState<Record<string, PGPRecipientTier>>({});
  const [pgpDiscoverySettings, setPgpDiscoverySettings] = useState<DiscoverySettings | null>(null);
  const [composeEncryptOverridden, setComposeEncryptOverridden] = useState(false);
  const quillEditorRef = useRef<HTMLDivElement | null>(null);
  const quillInstanceRef = useRef<Quill | null>(null);
  const composeDialogRef = useRef<HTMLDialogElement | null>(null);
  const attachmentInputRef = useRef<HTMLInputElement | null>(null);
  const composeNoticeTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [licenseOpen, setLicenseOpen] = useState(false);
  const licenseDialogRef = useRef<HTMLDialogElement | null>(null);
  const currentMailbox = new URLSearchParams(location.search).get("mailbox")?.trim() ?? "";
  const onReadPage = location.pathname === "/read";

  async function refreshAuth() {
    try {
      const next = await getJSON<AuthState>("/api/auth/me");
      setAuth(next);
    } catch {
      setAuth({ authenticated: false });
    }
  }

  useEffect(() => {
    refreshAuth();
  }, []);

  // Enforce the compose autosave's 24-hour bound. The snapshot is unencrypted
  // plaintext of a message that may have been headed for PGP encryption, and
  // expiring it on read is not an expiry: loadDraftSnapshot runs only when a
  // blank compose window is opened, so a user who closes the tab and never
  // composes again would keep it forever. Swept on mount for the ordinary
  // "opened the app" case, and hourly for a PWA tab that stays open for days
  // without ever reloading. Not scoped to the current user — a shared browser
  // is exactly where a previous account's draft outlives its session.
  useEffect(() => {
    purgeExpiredDraftSnapshots();
    const timer = window.setInterval(purgeExpiredDraftSnapshots, 60 * 60 * 1000);
    return () => window.clearInterval(timer);
  }, []);

  // Cold start: the unwrapped PGP key cannot survive a reload, so every
  // authenticated page load re-fetches the snapshot that says whether this
  // account has a key, which mode it is under, and whether an unlock is
  // needed. Nothing is unlocked here — that waits until something needs it.
  useEffect(() => {
    if (auth?.authenticated) {
      void loadPGPSession();
    }
  }, [auth?.authenticated]);

  useEffect(() => {
    const standalone = window.matchMedia("(display-mode: standalone)").matches ||
      (window.navigator as Navigator & { standalone?: boolean }).standalone === true;
    setPwaInstalled(standalone);

    function onBeforeInstallPrompt(event: Event) {
      event.preventDefault();
      setPwaInstallPrompt(event as BeforeInstallPromptEvent);
    }

    function onAppInstalled() {
      setPwaInstallPrompt(null);
      setPwaInstalled(true);
    }

    window.addEventListener("beforeinstallprompt", onBeforeInstallPrompt);
    window.addEventListener("appinstalled", onAppInstalled);
    return () => {
      window.removeEventListener("beforeinstallprompt", onBeforeInstallPrompt);
      window.removeEventListener("appinstalled", onAppInstalled);
    };
  }, []);

  // unsubscribeThisDevice removes the browser's push registration, server-side
  // then locally. Best-effort: a failure here must never block signing out.
  async function unsubscribeThisDevice() {
    try {
      if (!("serviceWorker" in navigator)) return;
      const reg = await navigator.serviceWorker.getRegistration();
      const subscription = await reg?.pushManager.getSubscription();
      if (!subscription) return;
      await deleteJSON<{ ok: boolean }>("/api/notifications/subscriptions", {
        endpoint: subscription.endpoint
      });
      await subscription.unsubscribe();
    } catch {
      // Ignored on purpose: logout must proceed regardless.
    }
  }

  async function logout() {
    try {
      // Drop this browser's push subscription BEFORE the session goes away.
      // The DELETE route requires a live session, so doing it afterwards would
      // 401 and leave the row in place — and a web-push subscription is not
      // tied to the session, so the previous user's mail notifications would
      // keep arriving on a shared browser indefinitely.
      await unsubscribeThisDevice();
      await postJSON<{ ok: boolean }>("/api/auth/logout", {});
    } finally {
      setMailboxFolders([]);
      setArchiveFolders([]);
      // Drop the unwrapped private key with the session. Leaving it in memory
      // after logout would let the next person at this browser read mail.
      clearPGPSession();
      // Same reasoning for the security page's re-auth: it is keyed to the
      // username, so a second sign-in as someone else could not inherit it, but
      // signing back in as the SAME user within the window would have walked
      // straight past a gate whose whole subject is who is sitting here.
      clearReauth();
      // Drop the autosaved compose buffer with the session, for the same
      // reason: the next person at this browser must not read it.
      if (auth?.userId) {
        clearDraftSnapshot(auth.userId);
      }
      setAuth({ authenticated: false });
    }
  }

  async function installPwa() {
    if (!pwaInstallPrompt) {
      return;
    }

    await pwaInstallPrompt.prompt();
    const choice = await pwaInstallPrompt.userChoice;
    setPwaInstallPrompt(null);
    if (choice.outcome === "accepted") {
      setPwaInstalled(true);
    }
  }

  async function loadMailboxFolders() {
    if (!auth?.authenticated) {
      setMailboxFolders([]);
      return;
    }
    setMailboxFoldersLoading(true);
    try {
      const data = await getJSON<InboxFoldersResponse>("/api/inbox/folders");
      setMailboxFolders(data.folders ?? []);
    } catch {
      setMailboxFolders([]);
    } finally {
      setMailboxFoldersLoading(false);
    }
  }

  async function createInboxFolder() {
    const name = createFolderName.trim();
    if (!name) {
      setCreateFolderError("Folder name is required.");
      return;
    }
    setCreateFolderLoading(true);
    setCreateFolderError("");
    setDeleteFolderError("");
    try {
      await postJSON<CreateFolderResponse>("/api/inbox/folders", {
        parent: "INBOX",
        name
      });
      setCreateFolderName("");
      setInboxCreateOpen(false);
      await loadMailboxFolders();
    } catch (e) {
      const message = toErrorMessage(e, "failed to create folder");
      setCreateFolderError(message);
    } finally {
      setCreateFolderLoading(false);
    }
  }

  async function loadArchiveFolders() {
    if (!auth?.authenticated) {
      setArchiveFolders([]);
      return;
    }
    setArchiveFoldersLoading(true);
    try {
      const data = await getJSON<InboxFoldersResponse>("/api/inbox/folders?parent=Archive");
      setArchiveFolders(data.folders ?? []);
    } catch {
      setArchiveFolders([]);
    } finally {
      setArchiveFoldersLoading(false);
    }
  }

  async function deleteInboxFolder(folder: InboxFolder) {
    if (!folder.deletable || deleteFolderLoading || renameFolderLoading) return;
    const confirmed = window.confirm(`Delete ${mailboxLabel(folder.path)} and move its emails to ${mailboxLabel(folder.path.slice(0, Math.max(folder.path.lastIndexOf("/"), folder.path.lastIndexOf(".")))) || "the parent folder"}?`);
    if (!confirmed) return;

    setDeleteFolderLoading(folder.path);
    setFolderMenuPath("");
    setDeleteFolderError("");
    setCreateFolderError("");
    try {
      await deleteJSON<DeleteFolderResponse>(`/api/inbox/folders?folder=${encodeURIComponent(folder.path)}`);
      const params = new URLSearchParams(location.search);
      if (location.pathname === "/read" && params.get("mailbox") === folder.path) {
        navigate("/read", { replace: true });
      }
      await loadMailboxFolders();
    } catch (e) {
      const message = toErrorMessage(e, "failed to delete folder");
      setDeleteFolderError(message);
    } finally {
      setDeleteFolderLoading("");
    }
  }

  async function renameInboxFolder(folder: InboxFolder) {
    if (!folder.deletable || renameFolderLoading || deleteFolderLoading) return;
    const current = mailboxLabel(folder.path);
    const nextName = window.prompt("Rename folder", current) ?? "";
    const name = nextName.trim();
    if (!name || name === current) {
      setFolderMenuPath("");
      return;
    }

    setRenameFolderLoading(folder.path);
    setFolderMenuPath("");
    setDeleteFolderError("");
    setCreateFolderError("");
    try {
      const response = await putJSON<RenameFolderResponse>("/api/inbox/folders", {
        folder: folder.path,
        name
      });
      const params = new URLSearchParams(location.search);
      if (location.pathname === "/read" && params.get("mailbox") === folder.path) {
        navigate(`/read?mailbox=${encodeURIComponent(response.renamed)}`, { replace: true });
      }
      await loadMailboxFolders();
    } catch (e) {
      const message = toErrorMessage(e, "failed to rename folder");
      setDeleteFolderError(message);
    } finally {
      setRenameFolderLoading("");
    }
  }

  function parseDragPayload(raw: string): DragMessagePayload | null {
    try {
      const parsed = JSON.parse(raw) as DragMessagePayload;
      if (!Array.isArray(parsed.messageIds) || parsed.messageIds.length === 0) return null;
      const messageIds = parsed.messageIds.map((value) => String(value).trim()).filter(Boolean);
      const mailbox = String(parsed.mailbox || "").trim();
      if (messageIds.length === 0 || mailbox === "") return null;
      return { messageIds, mailbox };
    } catch {
      return null;
    }
  }

  async function moveDraggedMessages(targetMailbox: string, event: DragEvent<HTMLElement>) {
    event.preventDefault();
    setDragOverFolder("");
    const payload = parseDragPayload(event.dataTransfer.getData("application/x-kypost-mailbox"));
    if (!payload) return;
    if (payload.mailbox.toLowerCase() === targetMailbox.toLowerCase()) return;

    setDeleteFolderError("");
    setCreateFolderError("");
    try {
      const response = await postJSON<MoveInboxActionResponse>("/api/inbox/actions", {
        action: "move",
        mailbox: payload.mailbox,
        targetMailbox,
        messageIds: payload.messageIds
      });
      if (response.failed.length > 0) {
        throw new Error(response.failed[0]?.error || "some emails could not be moved");
      }
      window.dispatchEvent(new CustomEvent("mailbox-move-complete", {
        detail: {
          sourceMailbox: payload.mailbox,
          targetMailbox
        }
      }));
    } catch (e) {
      const message = toErrorMessage(e, "failed to move email");
      setDeleteFolderError(message);
    }
  }

  useEffect(() => {
    if (!auth?.authenticated) {
      setMailboxFolders([]);
      setInboxCreateOpen(false);
      setCreateFolderError("");
      setCreateFolderName("");
      setFolderMenuPath("");
      setDeleteFolderError("");
      setDragOverFolder("");
      return;
    }
    void loadMailboxFolders();
  }, [auth?.authenticated]);

  useEffect(() => {
    if (!archiveOpen) return;
    void loadArchiveFolders();
  }, [archiveOpen, auth?.authenticated]);

  useEffect(() => {
    if (!composeOpen) return;
    if (!quillEditorRef.current) return;

    if (quillInstanceRef.current && quillInstanceRef.current.container !== quillEditorRef.current) {
      quillInstanceRef.current = null;
    }

    if (!quillInstanceRef.current) {
      const quill = new Quill(quillEditorRef.current, {
        theme: "snow"
      });
      quill.on("text-change", () => {
        setComposeHtmlBody(quill.root.innerHTML);
      });
      quillInstanceRef.current = quill;
    }

    const editor = quillInstanceRef.current;
    if (editor && editor.root.innerHTML !== composeHtmlBody) {
      editor.root.innerHTML = composeHtmlBody;
    }
  }, [composeOpen, composeHtmlBody]);

  useDialogOpen(composeDialogRef, composeOpen);
  useDialogOpen(licenseDialogRef, licenseOpen);

  function resetComposeForm() {
    setComposeFrom("");
    setComposeTo({ tokens: [], draft: "" });
    setComposeCc({ tokens: [], draft: "" });
    setComposeBcc({ tokens: [], draft: "" });
    setComposeSubject("");
    setComposeHtmlBody("");
    setComposeSending(false);
    setComposeError("");
    setComposeSuccess("");
    if (composeNoticeTimeoutRef.current) {
      clearTimeout(composeNoticeTimeoutRef.current);
      composeNoticeTimeoutRef.current = null;
    }
    setComposeNotice("");
    setComposeAttachments([]);
    setComposeEncrypt(false);
    setComposeEncryptOverridden(false);
    setComposeSign(false);
    setComposeSendLinkForKeyless(false);
    setComposeMissingKeyRecipients([]);
    setComposeRecipientTiers({});
    if (attachmentInputRef.current) {
      attachmentInputRef.current.value = "";
    }
    if (quillInstanceRef.current) {
      quillInstanceRef.current.setText("");
    }
  }

  async function handleAttachmentPick(event: React.ChangeEvent<HTMLInputElement>) {
    const files = Array.from(event.target.files ?? []);
    event.target.value = ""; // allow re-picking the same file
    if (files.length === 0) return;
    setComposeError("");
    try {
      const picked = await Promise.all(files.map(readFileAsAttachment));
      setComposeAttachments((current) => {
        const next = [...current, ...picked];
        const total = next.reduce((sum, a) => sum + a.size, 0);
        if (total > MAX_ATTACHMENT_BYTES) {
          setComposeError(`Attachments too large (max ${formatBytes(MAX_ATTACHMENT_BYTES)} total).`);
          return current;
        }
        return next;
      });
    } catch (e) {
      setComposeError(toErrorMessage(e, "failed to read attachment"));
    }
  }

  function removeComposeAttachment(index: number) {
    setComposeAttachments((current) => current.filter((_, i) => i !== index));
  }

  function loadSendAsOptions() {
    listSendAsAliases()
      .then((aliases) => setSendAsOptions(aliases.filter((alias) => alias.status === "verified")))
      .catch(() => setSendAsOptions([]));
  }

  // Debounced autosave of the open compose window. 1s after typing stops is
  // short enough that almost nothing is lost and long enough that a keystroke
  // is not a localStorage write.
  //
  // The Quill editor's live HTML is read here rather than relying on
  // composeHtmlBody: the editor writes through onChange, so on a hard crash
  // the last keystrokes may not have reached React state yet — which is
  // precisely the moment this exists for.
  useEffect(() => {
    if (!composeOpen || !auth?.userId) {
      return;
    }
    const userId = auth.userId;
    const timer = setTimeout(() => {
      saveDraftSnapshot(userId, {
        to: serializeRecipientField(composeTo),
        cc: serializeRecipientField(composeCc),
        bcc: serializeRecipientField(composeBcc),
        subject: composeSubject,
        body: quillInstanceRef.current?.root.innerHTML ?? composeHtmlBody,
        attachments: composeAttachments
      });
    }, 1000);
    return () => clearTimeout(timer);
  }, [composeOpen, auth?.userId, composeTo, composeCc, composeBcc, composeSubject, composeHtmlBody, composeAttachments]);

  // discardComposeDraft clears both the form and the autosaved snapshot. Used
  // wherever the work is finished or deliberately abandoned; closing the
  // window is NOT one of those, so it does not call this.
  function discardComposeDraft() {
    if (auth?.userId) {
      clearDraftSnapshot(auth.userId);
    }
    resetComposeForm();
  }

  function openComposeWindow() {
    resetComposeForm();
    setComposeError("");
    setComposeSuccess("");
    setComposeNotice("");
    // Recover anything the last session left behind. Only on a blank compose:
    // openDraftInCompose has explicit content and must never be overwritten by
    // a stale snapshot.
    const snapshot = auth?.userId ? loadDraftSnapshot(auth.userId) : null;
    if (snapshot) {
      setComposeTo(parseRecipientField(snapshot.to));
      setComposeCc(parseRecipientField(snapshot.cc));
      setComposeBcc(parseRecipientField(snapshot.bcc));
      setComposeSubject(snapshot.subject);
      setComposeHtmlBody(snapshot.body);
      setComposeNotice(restoreNotice(snapshot));
    }
    setComposeOpen(true);
    loadSendAsOptions();
  }

  function openDraftInCompose(payload: DraftComposePayload) {
    setComposeFrom("");
    setComposeTo(parseRecipientField(payload.sentTo ?? ""));
    setComposeCc(parseRecipientField(payload.cc ?? ""));
    setComposeBcc(parseRecipientField(payload.bcc ?? ""));
    setComposeSubject(payload.subject ?? "");
    setComposeHtmlBody(payload.body ?? "");
    setComposeError("");
    setComposeSuccess("");
    setComposeOpen(true);
    loadSendAsOptions();
  }

  function trashComposeDraft() {
    discardComposeDraft();
    setComposeOpen(false);
  }

  function closeComposeWindow() {
    setComposeOpen(false);
    resetComposeForm();
  }

  function mailboxLabel(path: string): string {
    const clean = path.trim();
    if (!clean) return "";
    const parts = clean.replace(/^INBOX[/.]/i, "").split(/[/.]/).filter(Boolean);
    return parts[parts.length - 1] ?? clean;
  }

  function standardMailboxKey(path: string): string {
    const value = mailboxLabel(path).trim().toLowerCase();
    if (!value) return "custom";
    if (["inbox", "draft", "drafts", "junk", "spam", "sent", "trash"].includes(value)) {
      return value;
    }
    return "custom";
  }

  useEffect(() => {
    if (!composeOpen) return;
    let cancelled = false;
    getPGPDiscoverySettings()
      .then((settings) => {
        if (!cancelled) setPgpDiscoverySettings(settings);
      })
      .catch(() => {
        if (!cancelled) setPgpDiscoverySettings(null);
      });
    return () => {
      cancelled = true;
    };
  }, [composeOpen]);

  // Spec §6: when autoEncryptWhenKeyKnown is on, silently flip Encrypt on once
  // every current recipient already has a usable pinned key. Uses only the
  // contact-data-only recipients-check (no network discovery), never
  // auto-disables, and backs off entirely once the user has touched the
  // checkbox themselves this compose.
  useEffect(() => {
    if (!pgpDiscoverySettings?.autoEncryptWhenKeyKnown) return;
    if (composeEncrypt) return;
    if (composeEncryptOverridden) return;
    const addresses = [composeTo, composeCc, composeBcc]
      .flatMap((f) => [...f.tokens.map((t) => t.email), f.draft])
      .map((a) => a.trim())
      .filter(Boolean);
    if (addresses.length === 0) return;
    let cancelled = false;
    const timeoutId = setTimeout(() => {
      checkPGPRecipients(addresses)
        .then(({ results }) => {
          if (cancelled) return;
          const byAddress = new Map(results.map((r) => [r.address.toLowerCase(), r]));
          const allVerified = addresses.every((addr) => byAddress.get(addr.toLowerCase())?.tier === "verified");
          if (allVerified) {
            setComposeEncrypt(true);
          }
        })
        .catch(() => {
          // Non-fatal: leave encryption off, user can still enable manually.
        });
    }, 300);
    return () => {
      cancelled = true;
      clearTimeout(timeoutId);
    };
  }, [pgpDiscoverySettings, composeEncrypt, composeEncryptOverridden, composeTo, composeCc, composeBcc]);

  useEffect(() => {
    if (!composeEncrypt) {
      setComposeMissingKeyRecipients([]);
      setComposeRecipientTiers({});
      return;
    }
    const addresses = [composeTo, composeCc, composeBcc]
      .flatMap((f) => [...f.tokens.map((t) => t.email), f.draft])
      .map((a) => a.trim())
      .filter(Boolean);
    if (addresses.length === 0) {
      setComposeMissingKeyRecipients([]);
      setComposeRecipientTiers({});
      return;
    }
    let cancelled = false;
    const timeoutId = setTimeout(() => {
      checkPGPRecipients(addresses)
        .then(({ results }) => {
          if (cancelled) return;
          const missing = results.filter((r) => !r.hasKey).map((r) => r.address);
          setComposeMissingKeyRecipients(missing);
          setComposeRecipientTiers(
            Object.fromEntries(results.map((r) => [r.address.toLowerCase(), r.tier ?? "none"]))
          );
        })
        .catch(() => {
          if (!cancelled) {
            setComposeMissingKeyRecipients([]);
            setComposeRecipientTiers({});
          }
        });
    }, 300);
    return () => {
      cancelled = true;
      clearTimeout(timeoutId);
    };
  }, [composeEncrypt, composeTo, composeCc, composeBcc]);

  // Derived, not stored: the wording depends on composeSendLinkForKeyless, which
  // the user can flip without triggering a fresh recipient-key check, so this
  // has to recompute on every render rather than lag behind the checkbox.
  const composeRecipientKeyWarning =
    composeMissingKeyRecipients.length === 0
      ? ""
      : composeSendLinkForKeyless
      ? `No PGP key on file for: ${composeMissingKeyRecipients.join(", ")} — they'll receive a one-time pickup link instead.`
      : `No PGP key on file for: ${composeMissingKeyRecipients.join(", ")} — sending will be refused unless you tick "Secure link if no key".`;

  /**
   * Seals the message for one keyless recipient and emails them a one-time
   * link. The key rides in the link's fragment, which the server never
   * receives on the fetch, so what it stores is ciphertext it cannot open.
   */
  async function sendSealedPickupLink(address: string, body: string) {
    const { sealed, fragmentKey } = await sealPickup({
      subject: composeSubject,
      body,
      mode: "html",
      from: composeFrom || ""
    });
    const created = await createSealedPickup(address, sealed);
    const link = `${created.url}#${fragmentKey}`;
    // The notice itself is ordinary mail: it carries the link, not the
    // message. It goes through the normal send path because there is no key
    // to encrypt it to — that is the whole situation being handled.
    await postJSON<{ ok: boolean }>("/api/mail/send", {
      from: composeFrom,
      to: address,
      subject: "[Encrypted] Email Sent by KyPost",
      body:
        "You've received a message that was sent encrypted.\n\n" +
        "Since there's no PGP key on file for your address, you can read it once at the link below. " +
        "The message is encrypted in your browser using a key contained in the link itself, " +
        "so the server storing it cannot read it.\n\n" +
        link +
        "\n\nThis link expires in 7 days or as soon as it's opened, whichever comes first.",
      mode: "plain",
      encrypt: false,
      sign: false
    });
  }

  /**
   * Encrypts and signs in the browser, then posts the ciphertext.
   *
   * Refuses rather than downgrading when a recipient has no usable key. The
   * server-side path falls back to a one-time pickup link for those, but that
   * works by storing the plaintext on the server — exactly what client-side
   * key protection exists to prevent — so it is not available here, and
   * quietly sending in the clear instead would be worse than failing.
   */
  async function sendComposeEncryptedLocally(to: string, body: string) {
    if (needsUnlock()) {
      // Open the prompt and stop. The composed body is deliberately not
      // stashed across the unlock: holding it would mean sending whatever was
      // captured at the moment of the first click, not what is on screen when
      // the user actually confirms.
      setComposeUnlockOpen(true);
      throw new Error("Your PGP key is locked — unlock it, then press Send again.");
    }

    const ccList = splitAddressList(serializeRecipientField(composeCc));
    const bccList = splitAddressList(serializeRecipientField(composeBcc));
    const toList = splitAddressList(to);

    const { results } = await resolveRecipientKeys([...toList, ...ccList, ...bccList]);
    const keyFor = new Map(results.filter((r) => r.usable && r.publicKey).map((r) => [r.address.toLowerCase(), r.publicKey!]));
    const missing = [...toList, ...ccList, ...bccList].filter((addr) => !keyFor.has(addr.toLowerCase()));

    // Recipients with no key get a secure link instead: the message is
    // sealed here under a random key that travels in the link's fragment,
    // so the server stores ciphertext it cannot read. This is weaker than
    // PGP — whoever can read their mail has the key — so it is an explicit
    // choice, never a silent fallback.
    if (missing.length > 0 && !composeSendLinkForKeyless) {
      throw new Error(
        `No usable PGP key for: ${missing.join(", ")}. Add their key in Contacts, tick "send a secure link" to send those recipients a one-time encrypted link instead, or turn off encryption.`
      );
    }
    const keyed = [toList, ccList, bccList].map((list) => list.filter((a) => keyFor.has(a.toLowerCase())));
    const [keyedTo, keyedCc, keyedBcc] = keyed;

    const envelope = {
      from: composeFrom || "",
      to: keyedTo,
      cc: keyedCc,
      subject: composeSubject
    };
    // To/Cc share one ciphertext; each Bcc gets its own so they never appear
    // in one another's encryption headers.
    const groups = [
      {
        recipients: [...keyedTo, ...keyedCc],
        publicKeys: [...keyedTo, ...keyedCc].map((a) => keyFor.get(a.toLowerCase())!)
      },
      ...keyedBcc.map((addr) => ({ recipients: [addr], publicKeys: [keyFor.get(addr.toLowerCase())!] }))
    ].filter((g) => g.recipients.length > 0);

    let warning = "";
    if (groups.length > 0) {
      const deliveries = await buildEncryptedDeliveries(envelope, "text/html; charset=UTF-8", body, groups, composeSign);
      // The Sent copy is encrypted to our own key before it leaves the browser.
      // It used to be the raw composer HTML, which handed the server the
      // cleartext of a message it had just been given only as ciphertext — and
      // the real subject with it. The server refuses an unencrypted copy now,
      // so this is not optional.
      const sentCopy = await buildEncryptedSentCopy(envelope, "text/html; charset=UTF-8", body, composeSign);
      const result = await sendClientEncryptedMail({
        from: composeFrom || "",
        // The real subject travels inside the ciphertext as a protected
        // header, exactly as it does for the deliveries.
        subject: OUTER_PLACEHOLDER_SUBJECT,
        deliveries,
        to: keyedTo,
        cc: keyedCc,
        bcc: keyedBcc,
        sentCopy,
        sentCopyEncrypted: true,
        mode: "html"
      });
      warning = result.warning ?? "";
    }

    if (groups.length === 0 && missing.length === 0) {
      throw new Error("Nothing to send: no recipients.");
    }

    // The keyed ciphertext above is already delivered and cannot be recalled,
    // so a link that fails here must not throw: that would report the whole
    // send as failed, and the retry it invites would deliver the keyed copy
    // twice. Every keyless recipient is attempted and the ones that got nothing
    // are named in the warning, which is the only form of this the user can
    // actually act on.
    //
    // The all-keyless case is the exception: nothing has been delivered, so
    // there is nothing to duplicate and a total failure is a real failure.
    const failedLinks = await deliverSealedPickupLinks(missing, (address) =>
      sendSealedPickupLink(address, body)
    );
    if (groups.length === 0 && failedLinks.length === missing.length) {
      throw new Error(
        `Could not send a secure link to any recipient (${failedLinks.join(", ")}). Nothing was sent.`
      );
    }
    return combineWarnings(warning, secureLinkWarning(failedLinks, missing.length));
  }

  async function sendComposeEmail() {
    if (composeSending) return;
    const to = serializeRecipientField(composeTo);
    if (!to) {
      setComposeError("TO is required.");
      return;
    }
    setComposeSending(true);
    setComposeError("");
    setComposeSuccess("");
    const body = quillInstanceRef.current?.root.innerHTML ?? composeHtmlBody;
    try {
      // A client-protected account's key is not on the server, so the server
      // cannot sign or encrypt on its behalf — the browser does it and posts
      // ciphertext. Falling through to /api/mail/send here would get a 409
      // (the server refuses rather than silently sending in the clear).
      let warning = "";
      if ((composeEncrypt || composeSign) && isClientProtected()) {
        warning = await sendComposeEncryptedLocally(to, body);
      } else {
        const result = await postJSON<{ ok: boolean; sentSaved?: boolean; warning?: string }>("/api/mail/send", {
          from: composeFrom,
          to,
          cc: serializeRecipientField(composeCc),
          bcc: serializeRecipientField(composeBcc),
          subject: composeSubject,
          body,
          mode: "html",
          attachments: composeAttachments.map(({ name, mimeType, dataBase64 }) => ({ name, mimeType, dataBase64 })),
          encrypt: composeEncrypt,
          sign: composeSign,
          allowPickupFallback: pickupFallbackFlag(composeEncrypt, composeSendLinkForKeyless)
        });
        warning = result.warning ?? "";
      }
      // A 200 with a warning means the message went out but something after
      // it did not — the Sent copy failed to save, some BCC deliveries
      // failed, or a pickup link could not be delivered. Closing the window
      // on that is how it used to reach nobody. Empty the form first (so the
      // window cannot be used to send the same message twice) and keep it
      // open carrying the warning; a clean send still closes as before.
      discardComposeDraft();
      if (warning) {
        setComposeNotice(`Sent — ${warning}`);
      } else {
        setComposeOpen(false);
      }
    } catch (e) {
      const keyless = keylessRecipientsFrom409(e);
      const message =
        keyless !== null
          ? `No PGP key on file for: ${keyless.join(", ")}. Tick "Secure link if no key" to send those recipients a one-time pickup link instead (stored on this server in plaintext for 7 days), or remove them from the recipients.`
          : toErrorMessage(e, "failed to send email");
      setComposeError(message);
    } finally {
      setComposeSending(false);
    }
  }

  async function saveComposeDraft() {
    if (composeSavingDraft) return;
    const to = serializeRecipientField(composeTo);
    if (!to) {
      setComposeError("TO is required.");
      return;
    }
    setComposeSavingDraft(true);
    setComposeError("");
    setComposeSuccess("");
    const body = quillInstanceRef.current?.root.innerHTML ?? composeHtmlBody;
    try {
      await postJSON<{ ok: boolean }>("/api/mail/draft", {
        to,
        cc: serializeRecipientField(composeCc),
        bcc: serializeRecipientField(composeBcc),
        subject: composeSubject,
        body,
        mode: "html",
        attachments: composeAttachments.map(({ name, mimeType, dataBase64 }) => ({ name, mimeType, dataBase64 }))
      });
      // The work is now a real IMAP draft, so the local safety net has
      // nothing left to protect. Clear it rather than leave a stale copy to
      // resurrect over the saved one on next open.
      if (auth?.userId) {
        clearDraftSnapshot(auth.userId);
      }
      setComposeSuccess("Draft saved.");
    } catch (e) {
      const message = toErrorMessage(e, "failed to save draft");
      setComposeError(message);
    } finally {
      setComposeSavingDraft(false);
    }
  }

  function addTokenToField(field: "to" | "cc" | "bcc", token: RecipientToken) {
    const setters: Record<"to" | "cc" | "bcc", typeof setComposeTo> = {
      to: setComposeTo,
      cc: setComposeCc,
      bcc: setComposeBcc
    };
    const setField = setters[field];
    setField((prev) => {
      if (isDuplicateInField(prev.tokens, token.email)) {
        if (composeNoticeTimeoutRef.current) {
          clearTimeout(composeNoticeTimeoutRef.current);
        }
        setComposeNotice(`${token.name ?? token.email} is already in ${field.toUpperCase()}.`);
        composeNoticeTimeoutRef.current = setTimeout(() => {
          setComposeNotice("");
          composeNoticeTimeoutRef.current = null;
        }, 3000);
        return prev;
      }
      return { tokens: [...prev.tokens, token], draft: "" };
    });
  }

  if (auth === null) {
    // Same field as the sign-in page, so resolving the session does not flash a
    // differently-coloured screen on the way to it.
    return (
      <div className="auth-page">
        <div className="auth-shell">
          <p className="auth-footnote">Checking your session…</p>
        </div>
      </div>
    );
  }

  const isAdmin = auth.role === "admin";

  // Sign-in gets its own full-page layout rather than the app shell. Everything
  // in that shell — New Email, the mailbox list, the folder tree — is mail
  // chrome a signed-out visitor cannot use, and wrapping the one thing they CAN
  // do inside it made the front door read as a broken mail client. /password is
  // deliberately NOT here: that route is reached from inside the app and stays
  // an ordinary in-app panel.
  if (location.pathname === "/login") {
    return (
      <div className="auth-page">
        <LoginPage auth={auth} onAuthChanged={refreshAuth} />
      </div>
    );
  }

  function protect(element: JSX.Element, adminOnly = false) {
    if (!auth?.authenticated) {
      return <Navigate to="/login" replace />;
    }
    if (adminOnly && !isAdmin) {
      return <Navigate to="/read" replace />;
    }
    return element;
  }

  return (
    <AuthContext.Provider value={auth}>
    <div className="shell">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <img className="sidebar-app-logo" src="/ky.png" alt="KyPost" style={{ width: "100%", maxWidth: 180, display: "block", margin: "0 auto 0.75rem" }} />
        </div>
        <button type="button" className="new-email-button" onClick={openComposeWindow}>
          New Email
        </button>
        <nav>
          <p className="sidebar-section-label">Mailboxes</p>
          <div className="mobile-quick-nav" aria-label="Mobile mailboxes">
            <Link className={onReadPage && currentMailbox === "" ? "sidebar-link-active" : ""} to="/read">Inbox</Link>
            <Link className={onReadPage && currentMailbox.toLowerCase() === "drafts" ? "sidebar-link-active" : ""} to="/read?mailbox=Drafts">Drafts</Link>
            <Link className={onReadPage && currentMailbox.toLowerCase() === "junk" ? "sidebar-link-active" : ""} to="/read?mailbox=Junk">Junk</Link>
            <Link className={onReadPage && currentMailbox.toLowerCase() === "sent" ? "sidebar-link-active" : ""} to="/read?mailbox=Sent">Sent</Link>
            <Link className={onReadPage && currentMailbox.toLowerCase() === "trash" ? "sidebar-link-active" : ""} to="/read?mailbox=Trash">Trash</Link>
            <button
              type="button"
              className="mobile-settings-toggle"
              aria-label="Toggle settings"
              title="Settings"
              onClick={() => setSettingsOpen((open) => !open)}
            >
              Settings
            </button>
          </div>
          <div className="inbox-nav-row">
            <Link
              to="/read"
              className={[dragOverFolder === "INBOX" ? "drop-target-active" : "", onReadPage && currentMailbox === "" ? "sidebar-link-active" : ""].filter(Boolean).join(" ")}
              onDragOver={(event) => {
                event.preventDefault();
                setDragOverFolder("INBOX");
              }}
              onDragLeave={() => setDragOverFolder("")}
              onDrop={(event) => {
                void moveDraggedMessages("INBOX", event);
              }}
            >
              Inbox
            </Link>
            <button
              type="button"
              className="inbox-expand-button"
              aria-expanded={inboxCreateOpen}
              onClick={() => {
                setInboxCreateOpen((open) => !open);
                setCreateFolderError("");
              }}
            >
              +
            </button>
          </div>
          <div className="nav-group">
            {inboxCreateOpen ? (
              <form
                className="sidebar-folder-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  void createInboxFolder();
                }}
              >
                <input
                  type="text"
                  value={createFolderName}
                  onChange={(event) => setCreateFolderName(event.target.value)}
                  placeholder="New folder under Inbox"
                  disabled={createFolderLoading}
                />
                <button type="submit" disabled={createFolderLoading}>
                  {createFolderLoading ? "Creating..." : "Create Folder"}
                </button>
              </form>
            ) : null}
            {createFolderError ? <span className="sidebar-folder-error">{createFolderError}</span> : null}
            {deleteFolderError ? <span className="sidebar-folder-error">{deleteFolderError}</span> : null}
            {mailboxFoldersLoading ? <span>Loading folders...</span> : null}
            {!mailboxFoldersLoading
              ? mailboxFolders.map((folder) => (
                  <div key={folder.path} className="sidebar-folder-row" data-folder-kind={standardMailboxKey(folder.path)}>
                    <Link
                      to={`/read?mailbox=${encodeURIComponent(folder.path)}`}
                      className={[
                        dragOverFolder === folder.path ? "drop-target-active" : "",
                        onReadPage && currentMailbox.toLowerCase() === folder.path.toLowerCase() ? "sidebar-link-active" : ""
                      ].filter(Boolean).join(" ")}
                      onDragOver={(event) => {
                        event.preventDefault();
                        setDragOverFolder(folder.path);
                      }}
                      onDragLeave={() => setDragOverFolder("")}
                      onDrop={(event) => {
                        void moveDraggedMessages(folder.path, event);
                      }}
                    >
                      {mailboxLabel(folder.path)}
                    </Link>
                    {folder.deletable ? (
                      <div className="sidebar-folder-menu-wrap">
                        <button
                          type="button"
                          className="sidebar-folder-menu-button"
                          aria-label={`Folder options for ${mailboxLabel(folder.path)}`}
                          onClick={() => setFolderMenuPath((current) => (current === folder.path ? "" : folder.path))}
                          disabled={deleteFolderLoading === folder.path || renameFolderLoading === folder.path}
                        >
                          ...
                        </button>
                        {folderMenuPath === folder.path ? (
                          <div className="sidebar-folder-menu">
                            <button
                              type="button"
                              onClick={() => void renameInboxFolder(folder)}
                              disabled={renameFolderLoading === folder.path}
                            >
                              {renameFolderLoading === folder.path ? "Renaming..." : "Rename"}
                            </button>
                            <button
                              type="button"
                              onClick={() => void deleteInboxFolder(folder)}
                              disabled={deleteFolderLoading === folder.path}
                            >
                              {deleteFolderLoading === folder.path ? "Deleting..." : "Delete"}
                            </button>
                          </div>
                        ) : null}
                      </div>
                    ) : null}
                  </div>
                ))
              : null}
          </div>

          <button
            type="button"
            className="nav-heading archive-toggle"
            aria-expanded={archiveOpen}
            onClick={() => setArchiveOpen((open) => !open)}
          >
            Archive {archiveOpen ? "-" : "+"}
          </button>

          {archiveOpen ? (
            <div className="nav-group archive-group">
              {archiveFoldersLoading ? <span>Loading folders...</span> : null}
              {!archiveFoldersLoading && archiveFolders.length === 0 ? <span>No archive folders</span> : null}
              {!archiveFoldersLoading
                ? archiveFolders.map((folder) => (
                    <Link
                      key={folder.path}
                      to={`/read?mailbox=${encodeURIComponent(folder.path)}`}
                      className={[
                        dragOverFolder === folder.path ? "drop-target-active" : "",
                        onReadPage && currentMailbox.toLowerCase() === folder.path.toLowerCase() ? "sidebar-link-active" : ""
                      ].filter(Boolean).join(" ")}
                      onDragOver={(event) => {
                        event.preventDefault();
                        setDragOverFolder(folder.path);
                      }}
                      onDragLeave={() => setDragOverFolder("")}
                      onDrop={(event) => {
                        void moveDraggedMessages(folder.path, event);
                      }}
                    >
                      {mailboxLabel(folder.path)}
                    </Link>
                  ))
                : null}
            </div>
          ) : null}

          <Link
            to="/contacts"
            className={["nav-heading", location.pathname === "/contacts" ? "sidebar-link-active" : ""].filter(Boolean).join(" ")}
          >
            Contacts
          </Link>

          <button
            type="button"
            className="nav-heading settings-heading"
            aria-expanded={settingsOpen}
            onClick={() => setSettingsOpen((open) => !open)}
          >
            Settings {settingsOpen ? "-" : "+"}
          </button>

          {settingsOpen ? (
            <div className="nav-group">
              {settingsNavItems
                .filter(({ adminOnly }) => !adminOnly || isAdmin)
                .map(({ to, label }) => (
                <Link
                  key={to}
                  className={(to === "/login" && auth.authenticated ? "/password" : to) === location.pathname ? "sidebar-link-active" : ""}
                  to={to === "/login" && auth.authenticated ? "/password" : to}
                >
                  {to === "/login" && auth.authenticated ? "Change Password" : label}
                </Link>
              ))}
              {!pwaInstalled ? (
                <button
                  type="button"
                  className="nav-link-button"
                  onClick={() => void installPwa()}
                  disabled={!pwaInstallPrompt}
                  title={pwaInstallPrompt ? "Install this site as a PWA" : "Wait for browser install support"}
                >
                  Install PWA
                </button>
              ) : (
                <span title="This site is already installed as a PWA">PWA Installed</span>
              )}
            </div>
          ) : null}
          {auth.authenticated ? (
            <button type="button" className="nav-link-button nav-heading" onClick={logout}>
              Logout
            </button>
          ) : null}
        </nav>
        <div className="sidebar-footer">
          <p>
            <button type="button" className="license-link" onClick={() => setLicenseOpen(true)}>
              &copy; {new Date().getFullYear()} &ndash; Licensed Under AGPL&nbsp;V3
            </button>
          </p>
        </div>
      </aside>
      <main className="content">
        <Routes>
            <Route path="/" element={<Navigate to={auth.authenticated ? "/read" : "/login"} replace />} />
          <Route path="/login" element={<LoginPage auth={auth} onAuthChanged={refreshAuth} />} />
          <Route path="/password" element={protect(<LoginPage auth={auth} onAuthChanged={refreshAuth} mode="password" />)} />
              <Route path="/read" element={protect(<ReadPage onOpenDraft={openDraftInCompose} />)} />
          <Route path="/health" element={protect(<HealthPage />)} />
          <Route path="/config" element={protect(<ConfigPage />)} />
          <Route path="/notifications" element={protect(<NotificationsPage />)} />
          <Route
            path="/security"
            element={protect(
              <ReauthGate what="your security settings">
                <SecurityPage />
              </ReauthGate>
            )}
          />
          <Route path="/rules" element={protect(<RulesPage />)} />
          <Route path="/contacts" element={protect(<ContactsPage />)} />
          <Route path="/tuning" element={protect(<TuningPage />)} />
          <Route path="/users" element={protect(<UsersPage />, true)} />
          <Route path="/logs" element={protect(<LogsPage />, true)} />
        </Routes>
      </main>
      <dialog
        ref={licenseDialogRef}
        className="compose-backdrop"
        onCancel={() => setLicenseOpen(false)}
        onClick={(event) => {
          if (event.target === licenseDialogRef.current) {
            setLicenseOpen(false);
          }
        }}
      >
        <div className="license-window">
          <div className="license-window-header">
            <div className="license-window-title">
              <div className="license-title-main">
                <span className="license-app-name">KyPost</span>
                <span className="license-version-badge">v{APP_VERSION}</span>
              </div>
              <p className="license-title-sub">Developed by Busnes Games</p>
              <p className="license-title-sub">
                &copy; {new Date().getFullYear()} &middot; Licensed under AGPL&nbsp;v3
              </p>
            </div>
            <button type="button" className="nav-link-button" onClick={() => setLicenseOpen(false)}>
              Close
            </button>
          </div>
          <textarea className="license-text" readOnly value={agplLicenseText} />
        </div>
      </dialog>
      <dialog
        ref={composeDialogRef}
        className="compose-backdrop"
        onCancel={(event) => {
          if (composeSending) {
            event.preventDefault();
            return;
          }
          closeComposeWindow();
        }}
        onClick={(event) => {
          if (event.target === composeDialogRef.current && !composeSending) {
            closeComposeWindow();
          }
        }}
      >
          <section
            className={`compose-window${composeSending ? " compose-window-sending" : ""}`}
            onClick={(event) => event.stopPropagation()}
          >
            <div className="compose-topbar">
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <button type="button" className="compose-send" onClick={() => void sendComposeEmail()} disabled={composeSending || composeSavingDraft}>{composeSending ? "Sending..." : "Send"}</button>
                <button type="button" className="compose-save-draft" onClick={() => void saveComposeDraft()} disabled={composeSending || composeSavingDraft}>Save Draft</button>
                <button type="button" className="compose-attach" onClick={() => attachmentInputRef.current?.click()} disabled={composeSending || composeSavingDraft}>📎 Attach</button>
                <button type="button" className="compose-attach" onClick={() => setContactPickerOpen(true)} disabled={composeSending || composeSavingDraft}>📇 Contacts</button>
                <button type="button" className="compose-trash" onClick={trashComposeDraft} disabled={composeSending || composeSavingDraft}>Trash</button>
                <label style={{ display: "flex", alignItems: "center", gap: 4, fontSize: "0.85rem" }}>
                  <input
                    type="checkbox"
                    checked={composeEncrypt}
                    onChange={(e) => {
                      setComposeEncryptOverridden(true);
                      setComposeEncrypt(e.target.checked);
                    }}
                  />
                  Encrypt
                </label>
                <label style={{ display: "flex", alignItems: "center", gap: 4, fontSize: "0.85rem" }}>
                  <input type="checkbox" checked={composeSign} onChange={(e) => setComposeSign(e.target.checked)} />
                  Sign
                </label>
                {composeEncrypt ? (
                  <label
                    style={{ display: "flex", alignItems: "center", gap: 4, fontSize: "0.85rem" }}
                    title={
                      isClientProtected()
                        ? "Recipients with no PGP key get a one-time link instead. The message is encrypted in your browser " +
                          "and this server only stores ciphertext — but the key is in the link, so anyone who can read that " +
                          "email can read the message. Weaker than PGP."
                        : "Recipients with no PGP key get a one-time link instead. The message is stored on this server in " +
                          "plaintext for 7 days, and the link travels as ordinary unencrypted mail. Weaker than PGP."
                    }
                  >
                    <input
                      type="checkbox"
                      checked={composeSendLinkForKeyless}
                      onChange={(e) => setComposeSendLinkForKeyless(e.target.checked)}
                    />
                    {isClientProtected() ? "Secure link if no key (browser-sealed)" : "Secure link if no key (server-held, 7 days)"}
                  </label>
                ) : null}
                <input
                  ref={attachmentInputRef}
                  type="file"
                  multiple
                  style={{ display: "none" }}
                  onChange={(event) => void handleAttachmentPick(event)}
                />
              </div>
              <button type="button" className="compose-close" onClick={closeComposeWindow} disabled={composeSending || composeSavingDraft}>Close</button>
            </div>
            {composeRecipientKeyWarning ? (
              <p className="compose-pgp-warning">{composeRecipientKeyWarning}</p>
            ) : null}

            {composeError ? <p className="notice notice-error" style={{ margin: 0 }}>Send failed: {composeError}</p> : null}
            <PgpUnlockDialog
              open={composeUnlockOpen}
              reason="to sign and encrypt this message"
              onUnlocked={() => setComposeUnlockOpen(false)}
              onCancel={() => setComposeUnlockOpen(false)}
            />
            {composeSuccess ? <p className="notice notice-success" style={{ margin: 0 }}>{composeSuccess}</p> : null}
            {composeNotice ? <p className="notice notice-warning">{composeNotice}</p> : null}

            <div className="compose-form-grid">
              {sendAsOptions.length > 0 ? (
                <label className="compose-field-row">
                  <span>FROM:</span>
                  <select
                    value={composeFrom}
                    onChange={(event) => setComposeFrom(event.target.value)}
                    disabled={composeSending || composeSavingDraft}
                  >
                    <option value="">Default (your account address)</option>
                    {sendAsOptions.map((alias) => (
                      <option key={alias.id} value={alias.email}>
                        {alias.displayName ? `${alias.displayName} <${alias.email}>` : alias.email}
                      </option>
                    ))}
                  </select>
                </label>
              ) : null}
              <div className="compose-field-row">
                <span>TO:</span>
                <RecipientField
                  label="To"
                  state={composeTo}
                  onDraftChange={(draft) => setComposeTo((prev) => ({ ...prev, draft }))}
                  onAddToken={(token) => addTokenToField("to", token)}
                  onRemoveToken={(index) => setComposeTo((prev) => ({ ...prev, tokens: prev.tokens.filter((_, i) => i !== index) }))}
                  tiers={composeRecipientTiers}
                />
              </div>
              <div className="compose-field-row">
                <span>CC:</span>
                <RecipientField
                  label="Cc"
                  state={composeCc}
                  onDraftChange={(draft) => setComposeCc((prev) => ({ ...prev, draft }))}
                  onAddToken={(token) => addTokenToField("cc", token)}
                  onRemoveToken={(index) => setComposeCc((prev) => ({ ...prev, tokens: prev.tokens.filter((_, i) => i !== index) }))}
                  tiers={composeRecipientTiers}
                />
              </div>
              <div className="compose-field-row">
                <span>BCC:</span>
                <RecipientField
                  label="Bcc"
                  state={composeBcc}
                  onDraftChange={(draft) => setComposeBcc((prev) => ({ ...prev, draft }))}
                  onAddToken={(token) => addTokenToField("bcc", token)}
                  onRemoveToken={(index) => setComposeBcc((prev) => ({ ...prev, tokens: prev.tokens.filter((_, i) => i !== index) }))}
                  tiers={composeRecipientTiers}
                />
              </div>
              <label className="compose-field-row">
                <span>Subject:</span>
                <input type="text" value={composeSubject} onChange={(event) => setComposeSubject(event.target.value)} placeholder="Subject" disabled={composeSending || composeSavingDraft} />
              </label>
            </div>

            {composeAttachments.length > 0 ? (
              <div className="compose-attachments">
                {composeAttachments.map((attachment, index) => (
                  <span key={`${attachment.name}-${index}`} className="compose-attachment-chip">
                    <span className="compose-attachment-name">{attachment.name}</span>
                    <span className="compose-attachment-size">({formatBytes(attachment.size)})</span>
                    <button
                      type="button"
                      className="compose-attachment-remove"
                      aria-label={`Remove ${attachment.name}`}
                      onClick={() => removeComposeAttachment(index)}
                      disabled={composeSending || composeSavingDraft}
                    >
                      ✕
                    </button>
                  </span>
                ))}
              </div>
            ) : null}

            <div
              ref={quillEditorRef}
              className="compose-editor compose-editor-html"
              onKeyDown={(event) => {
                if (event.key === "Escape") {
                  event.preventDefault();
                }
              }}
            />
          </section>
      </dialog>
      <ContactPickerModal
        isOpen={contactPickerOpen}
        onClose={() => setContactPickerOpen(false)}
        toTokens={composeTo.tokens}
        ccTokens={composeCc.tokens}
        bccTokens={composeBcc.tokens}
        onAdd={(field, contact) => {
          const token = contactToToken(contact);
          if (token) addTokenToField(field, token);
        }}
      />
    </div>
    </AuthContext.Provider>
  );
}
