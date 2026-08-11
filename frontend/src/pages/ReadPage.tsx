import { useEffect, useMemo, useRef, useState, type TouchEvent } from "react";
import { useSearchParams } from "react-router";
import { escapeHtmlText, processEmailHtml } from "../lib/emailHtml";
import { EmailBodyFrame } from "./read/EmailBodyFrame";
import { EncryptionCell } from "./read/EncryptionCell";
import { SignatureBadge } from "./read/SignatureBadge";
import { displayBody } from "./read/body";
import { firstAddressFromText, listAddressesFromText } from "../lib/addressText";
import { isFlaggedPhishing } from "../lib/phishing";
import { decryptMessage, verifySignedMessage } from "../lib/pgpClient";
import { getPGPMessagePayload } from "../api/pgp";
import { isClientProtected, needsUnlock, subscribePGPSession, type PGPSessionState } from "../lib/pgpSession";
import { PgpUnlockDialog } from "../components/PgpUnlockDialog";
import { getJSON, postJSON, toErrorMessage } from "../api/client";
import { usePagination } from "../hooks/usePagination";
import { useDialogOpen } from "../hooks/useDialogOpen";
import { PageTabs } from "../components/PageTabs";

import type {
  InboxEmail,
  DecryptedView,
  AttachmentInfo,
  ReadPageProps,
  InboxResponse,
  InboxAction,
  InboxActionResponse,
  KeywordActionResponse,
  SortKey,
  SortDirection,
  SwipeTone,
  SwipeRowState
} from "./read/types";
import {
  EMAILS_PER_PAGE,
  SWIPE_HINT_THRESHOLD,
  SWIPE_ACTIVATE_THRESHOLD,
  SWIPE_DISMISS_RATIO,
  SWIPE_MAX_OFFSET_RATIO,
  SWIPE_HAPTICS_STORAGE_KEY
} from "./read/types";
import { formatBytes, formatTimestamp, formatInboxListTime, formatUpdatedLabel } from "./read/format";
import {
  ensureSubjectPrefix,
  escapeHtml,
  buildReplyBody,
  buildForwardBody,
  buildReplyAllRecipients
} from "./read/compose";

export function ReadPage({ onOpenDraft }: ReadPageProps) {
  const [searchParams, setSearchParams] = useSearchParams();
  const mailbox = (searchParams.get("mailbox") || "").trim();
  const isInboxMailbox = mailbox.length === 0;
  const [tabs, setTabs] = useState<string[]>([]);
  const [byTab, setByTab] = useState<Record<string, InboxEmail[]>>({});
  const [activeTab, setActiveTab] = useState<string>("");
  const [selected, setSelected] = useState<InboxEmail | null>(null);
  // Locally decrypted bodies for client-protected accounts, keyed by message
  // id. The server hands over ciphertext only (see /api/mail/pgp-payload);
  // nothing decrypted here is ever sent back to it.
  const [decrypted, setDecrypted] = useState<Record<string, DecryptedView>>({});
  const [decryptingId, setDecryptingId] = useState("");
  const [verifyingId, setVerifyingId] = useState("");
  const [pgpUnlockOpen, setPgpUnlockOpen] = useState(false);
  const [, setPgpSession] = useState<PGPSessionState | null>(null);
  const [attachments, setAttachments] = useState<AttachmentInfo[]>([]);
  const [attachmentsLoading, setAttachmentsLoading] = useState(false);
  const [attachmentsError, setAttachmentsError] = useState("");
  const [keywordDraft, setKeywordDraft] = useState("");
  const [availableKeywords, setAvailableKeywords] = useState<string[]>([]);
  const emailReaderDialogRef = useRef<HTMLDialogElement | null>(null);
  const [selectedMessageIds, setSelectedMessageIds] = useState<string[]>([]);
  // run-4 finding M7: this used to be a bare boolean, cleared by
  // openEmailDetails. That made the opt-in correct only for messages opened
  // through that one function — and the search-results table called
  // setSelected directly, so a user who unblocked a newsletter's images and
  // then opened an attacker's message from search rendered it through the
  // permissive branch having never opted in for it, firing every tracking
  // pixel in it.
  //
  // Storing the message the grant was made for, rather than a bare "granted",
  // makes that drift impossible: any future route to a selected message fails
  // closed, because a grant for some other message simply doesn't match.
  const [showImagesFor, setShowImagesFor] = useState<string | null>(null);
  const showImages = selected !== null && showImagesFor === selected.messageId;
  const [showRawEmail, setShowRawEmail] = useState(false);
  const [loading, setLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState("");
  const [actionError, setActionError] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("time");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const [lastLoadedAt, setLastLoadedAt] = useState<Date | null>(null);
  const [clockTick, setClockTick] = useState(0);
  const [swipeRows, setSwipeRows] = useState<Record<string, SwipeRowState>>({});
  const [searchMode, setSearchMode] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchField, setSearchField] = useState<"all" | "sender" | "subject" | "body">("all");
  const [searchResults, setSearchResults] = useState<InboxEmail[]>([]);
  const [searching, setSearching] = useState(false);
  const [swipeRemovedIds, setSwipeRemovedIds] = useState<string[]>([]);
  const [swipeHapticsEnabled, setSwipeHapticsEnabled] = useState<boolean>(() => {
    try {
      return window.localStorage.getItem(SWIPE_HAPTICS_STORAGE_KEY) !== "false";
    } catch {
      return true;
    }
  });
  const [refillAnimationTick, setRefillAnimationTick] = useState(0);
  const isDraftMailbox = mailbox.toLowerCase().includes("drafts");
  const sourceMailbox = mailbox || "INBOX";

  useEffect(() => subscribePGPSession(setPgpSession), []);

  // Fetch and decrypt a client-protected message when it is opened.
  //
  // The server no longer decrypts for these accounts — it cannot — so an
  // encrypted message arrives with pgpEncrypted set, no body, and no
  // decryptError. That combination is the signal to fetch the ciphertext and
  // do the work here.
  useEffect(() => {
    const message = selected;
    if (!message || !message.pgpEncrypted || message.pgpDecryptError) {
      return;
    }
    if (!isClientProtected() || decrypted[message.messageId]) {
      return;
    }
    if (needsUnlock()) {
      setPgpUnlockOpen(true);
      return;
    }

    let cancelled = false;
    setDecryptingId(message.messageId);
    (async () => {
      try {
        const payload = await getPGPMessagePayload(sourceMailbox, message.messageId);
        const result = await decryptMessage(
          payload.encryptedPayload,
          payload.signerKeys ?? [],
          firstAddressFromText(message.sender || "")
        );
        if (cancelled) return;
        setDecrypted((prev) => ({
          ...prev,
          [message.messageId]: {
            body: result.body,
            // Read off the decrypted entity's own Content-Type by pgpClient.
            // The server's bodyMode describes the outer envelope and must not
            // be used for this body — see read/body.ts.
            bodyMode: result.bodyMode,
            signed: result.signed,
            verified: result.verified,
            signerFingerprint: result.signerFingerprint,
            error: ""
          }
        }));
      } catch (e) {
        if (cancelled) return;
        setDecrypted((prev) => ({
          ...prev,
          [message.messageId]: {
            body: "",
            signed: false,
            verified: false,
            signerFingerprint: "",
            error: toErrorMessage(e, "could not decrypt this message")
          }
        }));
      } finally {
        if (!cancelled) setDecryptingId("");
      }
    })();
    return () => {
      cancelled = true;
    };
    // decrypted is intentionally not a dependency: including it would re-run
    // this effect on every successful decrypt, and the guard above already
    // reads the latest value through the closure on each selection change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected, sourceMailbox, pgpUnlockOpen]);

  // Verify a signed-but-not-encrypted message when it is opened.
  //
  // The sibling of the decrypt effect above, and deliberately separate: this
  // one runs under BOTH protection modes, needs no unlocked vault (a signature
  // check uses public keys only), and fetches the signed part rather than
  // ciphertext. The server no longer verifies these at all — it cannot, since a
  // detached signature covers the part's transmitted bytes and every
  // server-side path holds a decoded copy — so this is the only thing standing
  // between a signed message and no verdict.
  useEffect(() => {
    const message = selected;
    if (!message || !message.pgpSigned || message.pgpEncrypted) {
      return;
    }
    if (decrypted[message.messageId]) {
      return;
    }

    let cancelled = false;
    setVerifyingId(message.messageId);
    (async () => {
      try {
        const payload = await getPGPMessagePayload(sourceMailbox, message.messageId);
        if (cancelled) return;
        if (!payload.signedPartBase64 || !payload.signaturePayload) {
          // Nothing usable came back: the raw fetch failed, or the message is
          // not the RFC 3156 shape the extractor handles. Signed with no
          // verdict — which the badge reads as "could not be checked", never as
          // a failure.
          throw new Error("no signed content available");
        }
        const result = await verifySignedMessage(
          payload.signedPartBase64,
          payload.signaturePayload,
          payload.signerKeys ?? [],
          firstAddressFromText(message.sender || "")
        );
        if (cancelled) return;
        setDecrypted((prev) => ({
          ...prev,
          [message.messageId]: {
            body: result.body,
            bodyMode: result.bodyMode,
            signed: result.signed,
            verified: result.verified,
            signerFingerprint: result.signerFingerprint,
            error: ""
          }
        }));
      } catch {
        if (cancelled) return;
        // No body here on purpose: an unverifiable signature must not cost the
        // reader the message. displayBody falls through to the server's copy on
        // an empty body, which is what the pane was already showing.
        setDecrypted((prev) => ({
          ...prev,
          [message.messageId]: {
            body: "",
            signed: true,
            verified: false,
            signerFingerprint: "",
            error: ""
          }
        }));
      } finally {
        if (!cancelled) setVerifyingId("");
      }
    })();
    return () => {
      cancelled = true;
    };
    // decrypted is intentionally not a dependency, for the same reason as the
    // decrypt effect above: including it would re-run on every success, and the
    // guard reads the latest value through the closure on each selection change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected, sourceMailbox]);

  const swipeSessionRef = useRef<{
    messageId: string;
    startX: number;
    startY: number;
    width: number;
    shouldSwipe: boolean;
    didSwipe: boolean;
    tone: SwipeTone;
    hintBuzzed: boolean;
    armedBuzzed: boolean;
  } | null>(null);
  const swipeLiveRef = useRef<Record<string, Omit<SwipeRowState, "phase">>>({});
  const swipeClickSuppressRef = useRef<Set<string>>(new Set());
  const isTouchSwipeEnabled =
    window.matchMedia("(pointer: coarse)").matches &&
    !isDraftMailbox;
  const hapticsSupported =
    typeof navigator !== "undefined" &&
    typeof (navigator as Navigator & { vibrate?: (pulse: number | number[]) => boolean }).vibrate === "function";

  useEffect(() => {
    try {
      window.localStorage.setItem(SWIPE_HAPTICS_STORAGE_KEY, swipeHapticsEnabled ? "true" : "false");
    } catch {
      // Ignore storage failures.
    }
  }, [swipeHapticsEnabled]);

  function triggerHaptic(pattern: number | number[]) {
    if (!isTouchSwipeEnabled || !swipeHapticsEnabled || typeof navigator === "undefined") {
      return;
    }
    const target = navigator as Navigator & {
      vibrate?: (pulse: number | number[]) => boolean;
    };
    if (typeof target.vibrate !== "function") {
      return;
    }
    try {
      target.vibrate(pattern);
    } catch {
      // Ignore unsupported vibration API failures.
    }
  }

  function computeSwipeOffset(deltaX: number, width: number): number {
    const direction = Math.sign(deltaX) || 1;
    const absolute = Math.abs(deltaX);
    const activatePx = width * SWIPE_ACTIVATE_THRESHOLD;

    if (absolute <= activatePx) {
      return deltaX * 1.14;
    }

    const beyond = absolute - activatePx;
    const base = activatePx * 1.14;
    const resisted = base + beyond * 0.4;
    const maxOffset = width * SWIPE_MAX_OFFSET_RATIO;
    return direction * Math.min(resisted, maxOffset);
  }

  const loadIdRef = useRef(0);
  async function loadInbox() {
    const loadId = ++loadIdRef.current;
    setLoading(true);
    setError("");
    try {
      const mailboxQuery = mailbox ? `&mailbox=${encodeURIComponent(mailbox)}` : "";
      const data = await getJSON<InboxResponse>(`/api/inbox?limit=500${mailboxQuery}`);
      if (loadId !== loadIdRef.current) return;
      setLastLoadedAt(new Date());
      const nextTabs = data.tabs ?? [];
      const nextByTab = data.byTab ?? {};
      setTabs(nextTabs);
      setByTab(nextByTab);
      setActiveTab((current) => {
        if (current && nextTabs.includes(current)) return current;
        return nextTabs[0] ?? "";
      });
      setSwipeRows({});
      setSwipeRemovedIds([]);
      setSelectedMessageIds((current) => {
        if (current.length === 0) return current;
        const nextIDSet = new Set<string>();
        Object.values(nextByTab).forEach((items) => {
          items.forEach((item) => nextIDSet.add(item.messageId));
        });
        return current.filter((id) => nextIDSet.has(id));
      });
    } catch (e) {
      if (loadId !== loadIdRef.current) return;
      const message = toErrorMessage(e, "failed to load inbox");
      setError(message);
      setTabs([]);
      setByTab({});
      setActiveTab("");
      setSelectedMessageIds([]);
    } finally {
      if (loadId === loadIdRef.current) setLoading(false);
    }
  }

  useEffect(() => {
    // ponytail: clear stale mailbox data synchronously so switching between
    // Inbox and Trash does not show the previous mailbox for several seconds
    // while the new fetch is in flight. Generation guard also drops late
    // arrivals from a slow previous-mailbox request.
    setSelected(null);
    setSelectedMessageIds([]);
    setTabs([]);
    setByTab({});
    setActiveTab("");
    setSwipeRows({});
    setSwipeRemovedIds([]);
    setError("");
    void loadInbox();
    const timer = setInterval(() => void loadInbox(), 15_000);
    return () => clearInterval(timer);
  }, [mailbox]);

  useDialogOpen(emailReaderDialogRef, selected);

  // Deep-link support: a push notification click lands here with
  // ?message=<id>&tab=<label> (see maybeSendPushNotification on the
  // backend). Find that email once its tab has loaded and open it, instead
  // of always leaving the user on the generic inbox view.
  useEffect(() => {
    const targetMessageId = searchParams.get("message");
    if (!targetMessageId) return;
    const targetTab = searchParams.get("tab") || "";

    const candidateTabs = targetTab && byTab[targetTab] ? [targetTab] : tabs;
    let match: InboxEmail | undefined;
    let matchTab = "";
    for (const tab of candidateTabs) {
      match = (byTab[tab] ?? []).find((item) => item.messageId === targetMessageId);
      if (match) {
        matchTab = tab;
        break;
      }
    }

    if (match) {
      if (isInboxMailbox && matchTab) {
        setActiveTab(matchTab);
      }
      void openEmailDetails(match);
    }

    setSearchParams(
      (current) => {
        const next = new URLSearchParams(current);
        next.delete("message");
        next.delete("tab");
        return next;
      },
      { replace: true }
    );
  }, [byTab, tabs, searchParams, isInboxMailbox, setSearchParams]);

  useEffect(() => {
    const timer = setInterval(() => {
      setClockTick((current) => current + 1);
    }, 30_000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const handleMailboxMove = () => {
      void loadInbox();
    };
    window.addEventListener("mailbox-move-complete", handleMailboxMove as EventListener);
    return () => {
      window.removeEventListener("mailbox-move-complete", handleMailboxMove as EventListener);
    };
  }, [mailbox]);

  useEffect(() => {
    if (!selected) return;
    let cancelled = false;
    getJSON<{ configured: string[]; imap: string[] }>("/api/labels")
      .then((data) => {
        if (cancelled) return;
        const merged = new Set([...(data.configured ?? []), ...(data.imap ?? [])]);
        setAvailableKeywords(Array.from(merged).sort());
      })
      .catch(() => {
        if (!cancelled) setAvailableKeywords([]);
      });
    return () => {
      cancelled = true;
    };
  }, [selected?.messageId]);

  const rows = useMemo(() => {
    if (isInboxMailbox) {
      if (!activeTab) return [];
      return byTab[activeTab] ?? [];
    }
    return tabs.flatMap((tab) => byTab[tab] ?? []);
  }, [isInboxMailbox, activeTab, byTab, tabs]);

  const sortedRows = useMemo(() => {
    const next = [...rows];
    const compareText = (left: string | undefined, right: string | undefined) =>
      (left ?? "").localeCompare(right ?? "", undefined, { sensitivity: "base" });
    const compareTime = (left: string, right: string) => {
      const leftTime = Date.parse(left);
      const rightTime = Date.parse(right);
      const safeLeft = Number.isNaN(leftTime) ? 0 : leftTime;
      const safeRight = Number.isNaN(rightTime) ? 0 : rightTime;
      return safeLeft - safeRight;
    };

    next.sort((left, right) => {
      const base =
        sortKey === "subject"
          ? compareText(left.subject, right.subject)
          : sortKey === "sender"
            ? compareText(left.sender, right.sender)
            : compareTime(left.atUtc, right.atUtc);
      return sortDirection === "asc" ? base : -base;
    });

    return next;
  }, [rows, sortDirection, sortKey]);

  const visibleRows = useMemo(() => {
    if (swipeRemovedIds.length === 0) {
      return sortedRows;
    }
    const removed = new Set(swipeRemovedIds);
    return sortedRows.filter((row) => !removed.has(row.messageId));
  }, [sortedRows, swipeRemovedIds]);

  const selectedInTab = useMemo(
    () => visibleRows.filter((row) => selectedMessageIds.includes(row.messageId)),
    [visibleRows, selectedMessageIds]
  );

  const { currentPage, setCurrentPage, totalPages, pageItems: pageRows } = usePagination(
    visibleRows,
    EMAILS_PER_PAGE
  );

  const allRowsSelected = pageRows.length > 0 && pageRows.every((row) => selectedMessageIds.includes(row.messageId));
  const updatedLabel = useMemo(
    () => formatUpdatedLabel(lastLoadedAt, Date.now()),
    [clockTick, lastLoadedAt]
  );

  const batchActions = [
    {
      key: "delete",
      label: "Delete",
      icon: "🗑",
      onClick: () => applyInboxAction("delete", selectedMessageIds),
      disabled: selectedMessageIds.length === 0 || actionLoading
    },
    {
      key: "archive",
      label: "Archive",
      icon: "📥",
      onClick: () => applyInboxAction("archive", selectedMessageIds),
      disabled: selectedMessageIds.length === 0 || actionLoading
    },
    {
      key: "spam",
      label: "Spam",
      icon: "⚠",
      onClick: () => applyInboxAction("spam", selectedMessageIds),
      disabled: selectedMessageIds.length === 0 || actionLoading
    },
    {
      key: "read",
      label: "Read",
      icon: "✓",
      onClick: () => applyInboxAction("read", selectedMessageIds),
      disabled: selectedMessageIds.length === 0 || actionLoading
    },
    {
      key: "print",
      label: "Print",
      icon: "🖨",
      onClick: () => printEmails(selectedInTab),
      disabled: selectedInTab.length === 0 || actionLoading
    }
  ] as const;

  useEffect(() => {
    setCurrentPage(1);
  }, [mailbox, activeTab, sortKey, sortDirection]);

  function updateSort(nextKey: SortKey) {
    if (sortKey === nextKey) {
      setSortDirection((current) => (current === "asc" ? "desc" : "asc"));
      return;
    }
    setSortKey(nextKey);
    setSortDirection(nextKey === "time" ? "desc" : "asc");
  }

  function sortLabel(column: SortKey, label: string): string {
    if (sortKey !== column) return label;
    return `${label} ${sortDirection === "asc" ? "↑" : "↓"}`;
  }

  function dragMessagePayload(item: InboxEmail): string {
    const dragged = selectedMessageIds.includes(item.messageId) ? selectedMessageIds : [item.messageId];
    return JSON.stringify({
      messageIds: dragged,
      mailbox: sourceMailbox
    });
  }

  async function applyInboxAction(action: InboxAction, messageIds: string[], options?: { closeModal?: boolean }): Promise<boolean> {
    if (messageIds.length === 0 || actionLoading) return false;
    setActionLoading(true);
    setActionError("");
    try {
      const response = await postJSON<InboxActionResponse>("/api/inbox/actions", {
        action,
        messageIds,
        mailbox
      });
      if (response.failed.length > 0) {
        const first = response.failed[0];
        throw new Error(first?.error || "some messages could not be updated");
      }
      if (action === "read") {
        const updated = new Set(messageIds);
        setByTab((current) => {
          const next: Record<string, InboxEmail[]> = {};
          Object.entries(current).forEach(([tab, items]) => {
            next[tab] = items.map((item) =>
              updated.has(item.messageId) ? { ...item, status: "read" } : item
            );
          });
          return next;
        });
        setSelected((current) => {
          if (!current || !updated.has(current.messageId)) return current;
          return { ...current, status: "read" };
        });
      } else {
        setSelectedMessageIds((current) => current.filter((id) => !messageIds.includes(id)));
        await loadInbox();
      }
      if (options?.closeModal) {
        setSelected(null);
      }
      return true;
    } catch (e) {
      const message = toErrorMessage(e, "failed to apply inbox action");
      setActionError(message);
      return false;
    } finally {
      setActionLoading(false);
    }
  }

  // updateSelectedKeywords patches the keywords for one specific message
  // (messageId, captured by the caller when its in-flight request started)
  // into both selected and byTab. It takes messageId explicitly — rather
  // than trusting whatever `selected` happens to be when this runs — so
  // that if the user opens a different email while an add/remove request
  // for the first one is still in flight, the late-arriving response can't
  // stamp its keyword update onto the now-selected message.
  function updateSelectedKeywords(messageId: string, next: string[]) {
    setSelected((current) => (current && current.messageId === messageId ? { ...current, keywords: next } : current));
    setByTab((current) => {
      const updated: Record<string, InboxEmail[]> = {};
      Object.entries(current).forEach(([tab, items]) => {
        updated[tab] = items.map((item) =>
          item.messageId === messageId ? { ...item, keywords: next } : item
        );
      });
      return updated;
    });
  }

  async function addKeywordToSelected(rawKeyword: string) {
    const keyword = rawKeyword.trim();
    if (!selected || !keyword) return;
    if ((selected.keywords ?? []).some((k) => k.toLowerCase() === keyword.toLowerCase())) {
      setKeywordDraft("");
      return;
    }
    const messageId = selected.messageId;
    const nextKeywords = [...(selected.keywords ?? []), keyword];
    try {
      const response = await postJSON<KeywordActionResponse>("/api/inbox/actions", {
        action: "label",
        messageIds: [messageId],
        keyword,
        mailbox
      });
      if (response.failed.length > 0) {
        const first = response.failed[0];
        throw new Error(first?.error || "failed to add keyword");
      }
      setKeywordDraft("");
      updateSelectedKeywords(messageId, nextKeywords);
    } catch (e) {
      setActionError(toErrorMessage(e, "failed to add keyword"));
    }
  }

  async function removeKeywordFromSelected(keyword: string) {
    if (!selected) return;
    const messageId = selected.messageId;
    const nextKeywords = (selected.keywords ?? []).filter((k) => k !== keyword);
    try {
      const response = await postJSON<KeywordActionResponse>("/api/inbox/actions", {
        action: "unlabel",
        messageIds: [messageId],
        keyword,
        mailbox
      });
      if (response.failed.length > 0) {
        const first = response.failed[0];
        throw new Error(first?.error || "failed to remove keyword");
      }
      updateSelectedKeywords(messageId, nextKeywords);
    } catch (e) {
      setActionError(toErrorMessage(e, "failed to remove keyword"));
    }
  }

  async function performSearch() {
    if (!searchQuery.trim()) {
      setSearchMode(false);
      setSearchResults([]);
      return;
    }
    setSearching(true);
    setActionError("");
    try {
      const response = await getJSON<{ results: InboxEmail[] }>(
        `/api/mail/search?q=${encodeURIComponent(searchQuery)}&field=${encodeURIComponent(searchField)}&mailbox=${encodeURIComponent(mailbox || "INBOX")}&limit=100`
      );
      setSearchResults(response.results ?? []);
      setSearchMode(true);
    } catch (e) {
      const message = toErrorMessage(e, "search failed");
      setActionError(message);
    } finally {
      setSearching(false);
    }
  }

  function clearSearch() {
    setSearchMode(false);
    setSearchQuery("");
    setSearchResults([]);
  }

  function updateSwipeState(messageId: string, offset: number, width: number, ratioOverride?: number) {
    const tone: SwipeTone = offset < 0 ? "archive" : "delete";
    const ratio = ratioOverride ?? Math.abs(offset) / Math.max(width, 1);
    const showHint = ratio >= SWIPE_HINT_THRESHOLD;
    const armed = ratio >= SWIPE_ACTIVATE_THRESHOLD;
    swipeLiveRef.current[messageId] = { offset, tone, showHint, armed };
    setSwipeRows((current) => ({
      ...current,
      [messageId]: {
        offset,
        phase: "dragging",
        tone,
        showHint,
        armed
      }
    }));
  }

  function clearSwipeRow(messageId: string) {
    setSwipeRows((current) => {
      if (!current[messageId]) {
        return current;
      }
      const next = { ...current };
      delete next[messageId];
      return next;
    });
    delete swipeLiveRef.current[messageId];
  }

  function markSwipeRemoved(messageId: string, removed: boolean) {
    setSwipeRemovedIds((current) => {
      if (removed) {
        if (current.includes(messageId)) {
          return current;
        }
        return [...current, messageId];
      }
      return current.filter((id) => id !== messageId);
    });
  }

  function handleSwipeStart(messageId: string, event: TouchEvent<HTMLTableRowElement>) {
    if (!isTouchSwipeEnabled || actionLoading) {
      return;
    }
    const touch = event.touches[0];
    swipeSessionRef.current = {
      messageId,
      startX: touch.clientX,
      startY: touch.clientY,
      width: Math.max(event.currentTarget.clientWidth, 1),
      shouldSwipe: false,
      didSwipe: false,
      tone: "delete",
      hintBuzzed: false,
      armedBuzzed: false
    };
  }

  function handleSwipeMove(event: TouchEvent<HTMLTableRowElement>) {
    const session = swipeSessionRef.current;
    if (!isTouchSwipeEnabled || !session || event.touches.length !== 1) {
      return;
    }
    const touch = event.touches[0];
    const deltaX = touch.clientX - session.startX;
    const deltaY = touch.clientY - session.startY;

    if (!session.shouldSwipe) {
      if (Math.abs(deltaX) < 10) {
        return;
      }
      if (Math.abs(deltaX) <= Math.abs(deltaY)) {
        swipeSessionRef.current = null;
        return;
      }
      session.shouldSwipe = true;
    }

    event.preventDefault();
    session.didSwipe = true;
    const swipeRatio = Math.abs(deltaX) / Math.max(session.width, 1);
    const tone: SwipeTone = deltaX < 0 ? "archive" : "delete";
    if (tone !== session.tone) {
      session.tone = tone;
      session.hintBuzzed = false;
      session.armedBuzzed = false;
    }

    if (swipeRatio >= SWIPE_HINT_THRESHOLD && !session.hintBuzzed) {
      triggerHaptic(9);
      session.hintBuzzed = true;
    }
    if (swipeRatio < SWIPE_HINT_THRESHOLD) {
      session.hintBuzzed = false;
    }

    if (swipeRatio >= SWIPE_ACTIVATE_THRESHOLD && !session.armedBuzzed) {
      triggerHaptic([12, 18, 16]);
      session.armedBuzzed = true;
    }
    if (swipeRatio < SWIPE_ACTIVATE_THRESHOLD) {
      session.armedBuzzed = false;
    }

    const resisted = computeSwipeOffset(deltaX, session.width);
    updateSwipeState(session.messageId, resisted, session.width, swipeRatio);
  }

  async function handleSwipeEnd() {
    const session = swipeSessionRef.current;
    swipeSessionRef.current = null;
    if (!isTouchSwipeEnabled || !session) {
      return;
    }

    const state = swipeLiveRef.current[session.messageId];

    if (!state || !session.shouldSwipe) {
      return;
    }

    if (session.didSwipe) {
      swipeClickSuppressRef.current.add(session.messageId);
      window.setTimeout(() => {
        swipeClickSuppressRef.current.delete(session.messageId);
      }, 280);
    }

    if (!state.armed) {
      setSwipeRows((current) => ({
        ...current,
        [session.messageId]: {
          ...state,
          offset: 0,
          phase: "snapback"
        }
      }));
      window.setTimeout(() => clearSwipeRow(session.messageId), 320);
      return;
    }

    const dismissOffset = state.tone === "delete" ? session.width * SWIPE_DISMISS_RATIO : -session.width * SWIPE_DISMISS_RATIO;
    triggerHaptic([16, 14, 20]);
    setSwipeRows((current) => ({
      ...current,
      [session.messageId]: {
        ...state,
        offset: dismissOffset,
        phase: "dismiss"
      }
    }));

    window.setTimeout(() => {
      markSwipeRemoved(session.messageId, true);
      setRefillAnimationTick((tick) => tick + 1);
    }, 170);

    const action: InboxAction = state.tone === "delete" ? "delete" : "archive";
    const ok = await applyInboxAction(action, [session.messageId]);
    if (!ok) {
      markSwipeRemoved(session.messageId, false);
      setSwipeRows((current) => ({
        ...current,
        [session.messageId]: {
          ...state,
          offset: 0,
          phase: "snapback"
        }
      }));
      window.setTimeout(() => clearSwipeRow(session.messageId), 320);
      return;
    }

    window.setTimeout(() => clearSwipeRow(session.messageId), 260);
  }

  async function openEmailDetails(item: InboxEmail) {
    if (isDraftMailbox && onOpenDraft) {
      const draft = displayBody(item, decrypted[item.messageId]);
      onOpenDraft({
        sentTo: item.sentTo,
        cc: item.cc,
        bcc: item.bcc,
        subject: item.subject,
        // Same sink as buildReplyBody/buildForwardBody (composeHtmlBody ->
        // editor.root.innerHTML): a draft's stored body is HTML and must be
        // sanitized before it can become live markup, same as any other
        // untrusted HTML entering the compose editor. Same pipeline too, so a
        // draft quoting a hostile message doesn't fetch remote content that the
        // read view refused to fetch.
        //
        // BOTH branches, not just the html one. A plain-mode body reaches the
        // same innerHTML assignment, so handing it over raw made "<img src=x
        // onerror=...>" live script in the app document — the one place the
        // sandboxed read frame does not cover. Plain text becomes markup by
        // being escaped, not by being sanitized: escaping is what preserves it
        // verbatim, and running a plain body through the HTML sanitizer would
        // silently eat anything that looked like a tag.
        body: draft.mode === "html" ? processEmailHtml(draft.body, false) : escapeHtmlText(draft.body)
      });
      return;
    }
    setSelected(item);
    // Keying the grant to a message ID already stops it leaking to a different
    // message. Clearing it here additionally keeps the older, stronger property
    // that rendering anything unblocked always costs a deliberate click in this
    // viewing session — reopening a message you unblocked earlier starts blocked
    // again.
    setShowImagesFor(null);
    setShowRawEmail(false);
    setActionError("");
    setAttachments([]);
    setAttachmentsError("");
    if (item.hasAttachments) {
      void loadAttachments(item);
    }
    if (item.status !== "read") {
      await applyInboxAction("read", [item.messageId]);
    }
  }

  function attachmentQuery(item: InboxEmail): string {
    const mailboxParam = mailbox ? `&mailbox=${encodeURIComponent(mailbox)}` : "";
    return `messageId=${encodeURIComponent(item.messageId)}${mailboxParam}`;
  }

  async function loadAttachments(item: InboxEmail) {
    setAttachmentsLoading(true);
    setAttachmentsError("");
    try {
      const data = await getJSON<{ ok: boolean; attachments: AttachmentInfo[] }>(
        `/api/mail/attachments?${attachmentQuery(item)}`
      );
      setAttachments(data.attachments ?? []);
    } catch (e) {
      setAttachmentsError(toErrorMessage(e, "failed to load attachments"));
    } finally {
      setAttachmentsLoading(false);
    }
  }

  function replyToSelectedEmail() {
    if (!selected || !onOpenDraft) return;
    onOpenDraft({
      sentTo: firstAddressFromText(selected.sender || ""),
      subject: ensureSubjectPrefix(selected.subject, "Re:"),
      body: buildReplyBody(selected, decrypted[selected.messageId])
    });
    setSelected(null);
  }

  function forwardSelectedEmail() {
    if (!selected || !onOpenDraft) return;
    onOpenDraft({
      sentTo: "",
      subject: ensureSubjectPrefix(selected.subject, "Fwd:"),
      body: buildForwardBody(selected, decrypted[selected.messageId])
    });
    setSelected(null);
  }

  function replyAllToSelectedEmail() {
    if (!selected || !onOpenDraft) return;
    const recipients = buildReplyAllRecipients(selected);
    onOpenDraft({
      sentTo: recipients.to,
      cc: recipients.cc,
      subject: ensureSubjectPrefix(selected.subject, "Re:"),
      body: buildReplyBody(selected, decrypted[selected.messageId])
    });
    setSelected(null);
  }

  function printEmails(items: InboxEmail[]) {
    if (items.length === 0) return;
    const sections = items
      .map((item) => {
        // displayBody, so printing a client-protected account's mail prints the
        // decrypted text at its own render mode rather than the envelope's.
        const resolved = displayBody(item, decrypted[item.messageId]);
        const body = resolved.body || "No message body available.";
        const isHtml = resolved.mode === "html" && Boolean(resolved.body);
        // Sender-controlled HTML must pass through the sanitizer here just like
        // every other render path (see sanitizeEmailHtml's invariant): the
        // print document is a same-origin window that inherits the app CSP, so
        // an unsanitized body would be a script-injection sink.
        //
        // Remote content is blocked unconditionally rather than following the
        // reader's per-message "Show Images" opt-in: printing acts on a whole
        // selection, so honoring that opt-in would mean firing the tracking
        // pixels of every other message in the batch — messages the user may
        // never have opened — on the strength of a choice made about one.
        const renderedBody = isHtml
          ? processEmailHtml(body, false)
          : `<pre style="white-space: pre-wrap; margin: 0;">${escapeHtml(body)}</pre>`;
        return `
          <article style="page-break-inside: avoid; border: 1px solid #bbb; border-radius: 8px; padding: 12px; margin-bottom: 14px;">
            <h2 style="margin: 0 0 8px; font-size: 18px;">${escapeHtml(item.subject || "(no subject)")}</h2>
            <p style="margin: 0 0 6px;"><strong>Sender:</strong> ${escapeHtml(item.sender || "-")}</p>
            <p style="margin: 0 0 10px;"><strong>Time:</strong> ${escapeHtml(formatTimestamp(item.atUtc))}</p>
            <div>${renderedBody}</div>
          </article>
        `;
      })
      .join("\n");

    const printWindow = window.open("", "_blank", "width=900,height=700");
    if (!printWindow) {
      setActionError("Popup blocked by browser; allow popups to print selected emails.");
      return;
    }
    printWindow.document.open();
    printWindow.document.write(`
      <!doctype html>
      <html>
        <head>
          <meta charset="utf-8" />
          <title>Inbox Print</title>
          <style>
            body { font-family: Arial, sans-serif; color: #111; margin: 24px; }
          </style>
        </head>
        <body>
          ${sections}
        </body>
      </html>
    `);
    printWindow.document.close();
    printWindow.focus();
    printWindow.print();
  }

  return (
    <section className="panel read-page-panel">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
        <div>
          <h2 style={{ marginTop: 0, marginBottom: 6 }}>{mailbox ? mailbox : "Inbox"}</h2>
        </div>
        <div className="inbox-action-bar">
          {isTouchSwipeEnabled ? (
            <label className="inbox-haptics-toggle" title={hapticsSupported ? "Enable or disable swipe haptics on this browser profile" : "Haptics are not supported by this browser"}>
              <input
                type="checkbox"
                checked={swipeHapticsEnabled}
                onChange={(event) => setSwipeHapticsEnabled(event.target.checked)}
                disabled={!hapticsSupported}
              />
              <span>Haptics</span>
            </label>
          ) : null}
          {batchActions.map((action) => (
            <button
              key={action.key}
              type="button"
              onClick={action.onClick}
              disabled={action.disabled}
              className="inbox-action-button"
              aria-label={action.label}
              title={action.label}
            >
              <span className="inbox-action-icon" aria-hidden="true">{action.icon}</span>
              <span className="inbox-action-text">{action.label}</span>
            </button>
          ))}
        </div>
      </div>

      {error ? <p className="notice notice-error">Failed to load inbox: {error}</p> : null}
      {actionError ? <p className="notice notice-error">Inbox action failed: {actionError}</p> : null}

      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginTop: 14, marginBottom: 14 }}>
        <div style={{ flex: 1, minWidth: 200, display: "flex", gap: 4, alignItems: "center" }}>
          <input
            type="text"
            placeholder="Search..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                void performSearch();
              }
            }}
            style={{
              flex: 1,
              padding: "6px 8px",
              borderRadius: "4px",
              border: "1px solid var(--line)",
              backgroundColor: "var(--panel)",
              color: "var(--ink-strong)",
              fontSize: "0.9rem"
            }}
          />
          <select
            value={searchField}
            onChange={(e) => setSearchField(e.target.value as any)}
            style={{
              padding: "6px 8px",
              borderRadius: "4px",
              border: "1px solid var(--line)",
              backgroundColor: "var(--panel)",
              color: "var(--ink-strong)",
              fontSize: "0.9rem"
            }}
          >
            <option value="all">All</option>
            <option value="sender">Sender</option>
            <option value="subject">Subject</option>
            <option value="body">Body</option>
          </select>
          <button
            type="button"
            onClick={() => void performSearch()}
            disabled={searching}
            style={{ padding: "6px 12px" }}
          >
            {searching ? "Searching..." : "Search"}
          </button>
          {searchMode ? (
            <button type="button" onClick={clearSearch} style={{ padding: "6px 12px" }}>
              Clear
            </button>
          ) : null}
        </div>
      </div>

      {searchMode ? (
        <div className="inbox-list-region">
          <div style={{ marginBottom: 8 }}>
            <p style={{ fontSize: "0.9rem", color: "var(--ink-weaker)" }}>
              Found {searchResults.length} result{searchResults.length === 1 ? "" : "s"}
            </p>
          </div>
          {searchResults.length === 0 ? (
            <div className="inbox-empty-state">
              <p>No emails match your search.</p>
            </div>
          ) : (
            <div className="inbox-table-wrap">
              <div className="inbox-table-scroll">
                <table className="inbox-table">
                  <thead>
                    <tr>
                      <th className="inbox-col-heading inbox-col-lock" aria-label="Encrypted" />
                      <th className="inbox-col-heading">Subject</th>
                      <th className="inbox-col-heading inbox-desktop-col">Sender</th>
                      <th className="inbox-col-heading inbox-col-time inbox-desktop-col">Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {searchResults.map((item) => {
                      const isRead = item.status === "read";
                      const displayTime = formatInboxListTime(item.atUtc);
                      return (
                        <tr
                          key={item.messageId}
                          className={`inbox-row ${isRead ? "" : "inbox-row-unread"}`.trim()}
                          // Not setSelected: opening a message is more than
                          // assigning it. openEmailDetails also clears the
                          // previous message's attachment list — otherwise a
                          // link labelled invoice.pdf downloads attachment #N
                          // of whatever was open before — and marks it read.
                          onClick={() => void openEmailDetails(item)}
                          style={{ cursor: "pointer" }}
                        >
                          <EncryptionCell email={item} local={decrypted[item.messageId]} clientProtected={isClientProtected()} />
                          <td className="inbox-cell">
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                void openEmailDetails(item);
                              }}
                              style={{
                                background: "none",
                                border: "none",
                                cursor: "pointer",
                                textAlign: "left",
                                padding: 0,
                                fontSize: "0.95rem",
                                fontWeight: isRead ? "normal" : "600"
                              }}
                            >
                              {item.subject || "(no subject)"}
                            </button>
                          </td>
                          <td className="inbox-cell inbox-desktop-col" style={{ fontSize: "0.9rem", color: "var(--ink-weaker)" }}>
                            {item.sender}
                          </td>
                          <td className="inbox-cell inbox-col-time inbox-desktop-col" style={{ fontSize: "0.85rem", color: "var(--ink-weaker)" }}>
                            {displayTime}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      ) : isInboxMailbox ? (
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 14, marginBottom: 14 }}>
          {tabs.map((tab) => {
            const unreadCount = (byTab[tab] ?? []).filter((item) => item.status !== "read").length;
            const isActive = activeTab === tab;
            return (
              <button
                key={tab}
                type="button"
                onClick={() => setActiveTab(tab)}
                style={{
                  background: isActive ? "var(--accent)" : "transparent",
                  color: isActive ? "var(--accent-contrast)" : "var(--ink-strong)",
                  border: "1px solid var(--line)",
                  borderRadius: 999,
                  padding: "0.38rem 0.78rem",
                  fontSize: "0.82rem",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 8
                }}
              >
                <span>{tab}</span>
                <span
                  style={{
                    minWidth: 18,
                    height: 18,
                    borderRadius: 999,
                    border: "1px solid var(--line)",
                    background: isActive ? "var(--chip-active-bg)" : "var(--accent-soft)",
                    color: isActive ? "var(--accent-contrast)" : "var(--ink-strong)",
                    display: "inline-flex",
                    alignItems: "center",
                    justifyContent: "center",
                    padding: "0 6px",
                    fontSize: "0.72rem",
                    fontWeight: 700,
                    lineHeight: 1
                  }}
                >
                  {unreadCount}
                </span>
              </button>
            );
          })}
        </div>
      ) : null}

      {visibleRows.length === 0 ? (
        <div className="inbox-list-region">
          <div className="inbox-empty-state">
            <p>{isInboxMailbox ? "No emails in this tab yet." : "No emails yet."}</p>
          </div>
        </div>
      ) : (
        <div className="inbox-list-region">
          <PageTabs
            totalPages={totalPages}
            currentPage={currentPage}
            onSelect={setCurrentPage}
            classPrefix="inbox"
            ariaLabel="Email pages"
          />
          <div className="inbox-table-wrap">
            <div className="inbox-table-scroll">
              <table className="inbox-table">
                <thead>
                  <tr>
                    <th className="inbox-col-select inbox-col-heading">
                      {/* The label is the hit target, not decoration: it grows to
                          fill the cell so a near miss still toggles. A bare
                          <label> forwards the click natively — no handler. */}
                      <label className="inbox-select-hit">
                        <input
                          type="checkbox"
                          className="inbox-checkbox"
                          checked={allRowsSelected}
                          onChange={(e) => {
                            if (e.target.checked) {
                              const ids = pageRows.map((row) => row.messageId);
                              setSelectedMessageIds((current) => {
                                const merged = new Set(current);
                                ids.forEach((id) => merged.add(id));
                                return Array.from(merged);
                              });
                              return;
                            }
                            const pageIDs = new Set(pageRows.map((row) => row.messageId));
                            setSelectedMessageIds((current) => current.filter((id) => !pageIDs.has(id)));
                          }}
                          aria-label="Select all emails in page"
                        />
                      </label>
                    </th>
                    <th className="inbox-col-heading inbox-col-lock" aria-label="Encrypted" />
                    <th className="inbox-col-heading">
                      <button type="button" onClick={() => updateSort("subject")} className="inbox-sort-button">
                        {sortLabel("subject", "Subject")}
                      </button>
                    </th>
                    <th className="inbox-col-heading inbox-desktop-col">
                      <button type="button" onClick={() => updateSort("sender")} className="inbox-sort-button">
                        {sortLabel("sender", "Sender")}
                      </button>
                    </th>
                    <th className="inbox-col-heading inbox-col-time inbox-desktop-col">
                      <button type="button" onClick={() => updateSort("time")} className="inbox-sort-button">
                        {sortLabel("time", "Time")}
                      </button>
                    </th>
                  </tr>
                </thead>
                <tbody className={`inbox-body-refill-${refillAnimationTick % 2}`}>
                  {pageRows.map((item) => {
                    const isRead = item.status === "read";
                    const displayTime = formatInboxListTime(item.atUtc);
                    const swipeState = swipeRows[item.messageId];
                    const swipeClass = swipeState
                      ? [
                          swipeState.phase === "dragging" ? "inbox-row-swipe-dragging" : "",
                          swipeState.phase === "snapback" ? "inbox-row-swipe-snapback" : "",
                          swipeState.phase === "dismiss" ? "inbox-row-swipe-dismiss" : "",
                          swipeState.showHint ? (swipeState.tone === "delete" ? "inbox-row-swipe-delete-hint" : "inbox-row-swipe-archive-hint") : "",
                          swipeState.armed ? "inbox-row-swipe-armed" : ""
                        ]
                          .filter(Boolean)
                          .join(" ")
                      : "";
                    return (
                    <tr
                      key={`${item.messageId}-${item.atUtc}`}
                      draggable={!isTouchSwipeEnabled}
                      onDragStart={(event) => {
                        event.dataTransfer.setData("application/x-kypost-mailbox", dragMessagePayload(item));
                        event.dataTransfer.effectAllowed = "move";
                      }}
                      onTouchStart={(event) => handleSwipeStart(item.messageId, event)}
                      onTouchMove={handleSwipeMove}
                      onTouchEnd={() => void handleSwipeEnd()}
                      onTouchCancel={() => void handleSwipeEnd()}
                      className={`inbox-row ${isRead ? "" : "inbox-row-unread"} ${swipeClass}`.trim()}
                      style={swipeState ? { transform: `translateX(${swipeState.offset}px)` } : undefined}
                    >
                      <td className="inbox-cell inbox-col-select">
                        <label className="inbox-select-hit">
                          <input
                            type="checkbox"
                            className="inbox-checkbox"
                            checked={selectedMessageIds.includes(item.messageId)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setSelectedMessageIds((current) => (current.includes(item.messageId) ? current : [...current, item.messageId]));
                                return;
                              }
                              setSelectedMessageIds((current) => current.filter((id) => id !== item.messageId));
                            }}
                            aria-label={`Select email ${item.subject || item.messageId}`}
                          />
                        </label>
                      </td>
                      <EncryptionCell email={item} local={decrypted[item.messageId]} clientProtected={isClientProtected()} />
                      <td className="inbox-cell">
                        {swipeState?.showHint ? (
                          <span
                            className={`inbox-row-swipe-label ${swipeState.tone === "delete" ? "delete" : "archive"} ${swipeState.armed ? "armed" : ""}`}
                            aria-live="polite"
                          >
                            {swipeState.tone === "delete" ? "Delete" : "Archive"}
                          </span>
                        ) : null}
                        <button
                          type="button"
                          onClick={() => {
                            if (swipeClickSuppressRef.current.has(item.messageId)) {
                              return;
                            }
                            void openEmailDetails(item);
                          }}
                          className={`inbox-subject-button ${isRead ? "" : "inbox-subject-unread"}`}
                        >
                          {item.hasAttachments ? <span className="inbox-attachment-icon" title="Has attachments" aria-label="Has attachments">📎 </span> : null}
                          {item.subject || "(no subject)"}
                        </button>
                        <div className="inbox-row-meta">
                          <span>{item.sender || "-"}</span>
                          <span>{displayTime}</span>
                          {(item.keywords ?? []).map((kw) => (
                            <span key={kw} className="inbox-keyword-chip">{kw}</span>
                          ))}
                        </div>
                      </td>
                      <td className="inbox-cell inbox-sender-cell inbox-desktop-col">{item.sender || "-"}</td>
                      <td className="inbox-cell inbox-time-cell inbox-desktop-col">{displayTime}</td>
                    </tr>
                  )})}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      <div className="inbox-updated-footer">
        <button
          type="button"
          onClick={loadInbox}
          disabled={loading || actionLoading}
          className="inbox-updated-button"
          aria-label="Refresh inbox"
          title="Refresh inbox"
        >
          {updatedLabel}
        </button>
      </div>

      <dialog
        ref={emailReaderDialogRef}
        className="email-reader-backdrop"
        onCancel={(event) => {
          event.preventDefault();
          setSelected(null);
        }}
        onClick={(event) => {
          if (event.target === emailReaderDialogRef.current) {
            setSelected(null);
          }
        }}
      >
        {selected ? (
          <div
            className="email-reader-window"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="email-reader-head">
              <h3 style={{ margin: 0 }}>Email Details</h3>
              <div className="email-reader-actions">
                <div className="email-reader-actions-row">
                  <button
                    type="button"
                    onClick={() => applyInboxAction("archive", [selected.messageId], { closeModal: true })}
                    disabled={actionLoading}
                  >
                    Archive
                  </button>
                  <button
                    type="button"
                    onClick={() => applyInboxAction("read", [selected.messageId])}
                    disabled={actionLoading}
                  >
                    Mark as Read
                  </button>
                  <button
                    type="button"
                    onClick={() => applyInboxAction("spam", [selected.messageId], { closeModal: true })}
                    disabled={actionLoading}
                  >
                    Mark as Spam
                  </button>
                  <button
                    type="button"
                    onClick={() => applyInboxAction("delete", [selected.messageId], { closeModal: true })}
                    disabled={actionLoading}
                  >
                    Delete
                  </button>
                  <button type="button" onClick={() => printEmails([selected])} disabled={actionLoading}>Print</button>
                </div>
                <div className="email-reader-actions-row">
                  <button type="button" onClick={replyToSelectedEmail} disabled={actionLoading}>Reply</button>
                  <button type="button" onClick={replyAllToSelectedEmail} disabled={actionLoading}>Reply All</button>
                  <button type="button" onClick={forwardSelectedEmail} disabled={actionLoading}>Forward</button>
                      <button
                        type="button"
                        onClick={() => setShowImagesFor((current) => (current === selected.messageId ? null : selected.messageId))}
                      >
                        {showImages ? "Hide Remote Content" : "Show Remote Content"}
                      </button>
                  <button type="button" onClick={() => setSelected(null)}>Close</button>
                </div>
              </div>
            </div>

            <PgpUnlockDialog
              open={pgpUnlockOpen}
              reason="to read this encrypted message"
              onUnlocked={() => setPgpUnlockOpen(false)}
              onCancel={() => setPgpUnlockOpen(false)}
            />
            <div className="email-reader-content">
              {/*
                Sits above the PGP badge because it is the more urgent thing to
                read: PGP describes how a message was protected, this says the
                message is trying to take over the user's device.

                Advisory only, and no confirm-modal friction, because the
                dangerous capability is already gone -- processEmailHtml has
                replaced every non-allowlisted link with a visible
                "[Blocked link:]" marker before this renders. Friction here
                would protect nothing and train the user to click through
                warnings.
              */}
              {isFlaggedPhishing(selected) ? (
                <p className="notice notice-error" style={{ margin: "0 0 12px" }}>
                  {/*
                    run-4 M17: this used to assert "Links to KyPost app
                    addresses have been blocked." That is only true for a
                    kypost:// deep link, which the scheme allowlist refuses. The
                    other two rules fire on ordinary https links and on subject
                    lines, and an allowlisted https link renders live and
                    untouched — so the sentence was telling the user something
                    protective had happened when nothing had. A warning that
                    overstates itself is worse than a quieter accurate one,
                    because the first time a user checks and finds the link
                    working, the banner stops meaning anything.
                  */}
                  <strong>This message looks like it is impersonating KyPost.</strong> Treat anything it asks you to
                  open or confirm as untrusted, and check the sender before acting. KyPost will never ask you to confirm
                  a pairing request by email — never approve one you did not start yourself, on this device.
                </p>
              ) : null}
              {(() => {
                // For client-protected accounts the verdict comes from the
                // local decrypt or the local signature check, not from the
                // server. Fall back to the server's fields for legacy accounts'
                // encrypted mail — the one case where the server still has one.
                const local = decrypted[selected.messageId];
                const decryptFailed = Boolean(selected.pgpDecryptError || local?.error);
                const decryptingNow = decryptingId === selected.messageId;
                const verifyingNow = verifyingId === selected.messageId;
                if (!selected.pgpEncrypted && !selected.pgpSigned) {
                  return null;
                }
                return (
                  <p style={{ margin: 0 }}>
                    {selected.pgpEncrypted ? (
                      <span className={`security-badge ${decryptFailed ? "security-badge-off" : "security-badge-on"}`}>
                        <span className="security-dot" aria-hidden="true" />
                        {decryptingNow
                          ? "PGP: decrypting…"
                          : decryptFailed
                            ? "PGP: could not decrypt"
                            : "PGP: encrypted"}
                      </span>
                    ) : null}
                    {/*
                      Suppressed while an encrypted message is still closed:
                      until it decrypts there is no signature to describe, and a
                      badge next to "could not decrypt" would be describing
                      nothing. A signed-only message has no such gate — its
                      content was readable all along.
                    */}
                    {selected.pgpEncrypted && (decryptFailed || decryptingNow) ? null : (
                      <SignatureBadge email={selected} local={local} checking={verifyingNow} />
                    )}
                    {local?.error ? (
                      <span className="contacts-muted" style={{ marginLeft: 6 }}>{local.error}</span>
                    ) : null}
                    {selected.pgpEncrypted &&
                    !local &&
                    !decryptingNow &&
                    !selected.pgpDecryptError &&
                    needsUnlock() ? (
                      <button
                        type="button"
                        className="contacts-action"
                        style={{ marginLeft: 6 }}
                        onClick={() => setPgpUnlockOpen(true)}
                      >
                        Unlock to read
                      </button>
                    ) : null}
                  </p>
                );
              })()}
              <p style={{ margin: 0 }}><strong>Subject:</strong> {selected.subject || "(no subject)"}</p>
              <p style={{ margin: 0 }}><strong>Sender:</strong> {selected.sender || "-"}</p>
              <p style={{ margin: 0 }}><strong>Sent To:</strong> {selected.sentTo || "-"}</p>
              <div className="email-keyword-editor">
                <strong>Keywords:</strong>
                <div className="compose-token-field-wrap">
                  <div className="compose-token-field">
                    {(selected.keywords ?? []).map((kw) => (
                      <span key={kw} className="compose-token-pill">
                        <span className="compose-token-pill-label">{kw}</span>
                        <button
                          type="button"
                          className="compose-token-pill-remove"
                          aria-label={`Remove keyword ${kw}`}
                          onClick={() => removeKeywordFromSelected(kw)}
                        >
                          &times;
                        </button>
                      </span>
                    ))}
                    <input
                      type="text"
                      className="compose-token-input"
                      list="inbox-keyword-options"
                      value={keywordDraft}
                      placeholder="Add keyword"
                      onChange={(e) => setKeywordDraft(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          void addKeywordToSelected(keywordDraft);
                        }
                      }}
                      onBlur={() => {
                        if (keywordDraft.trim()) void addKeywordToSelected(keywordDraft);
                      }}
                    />
                  </div>
                </div>
                <datalist id="inbox-keyword-options">
                  {availableKeywords.map((kw) => (
                    <option key={kw} value={kw} />
                  ))}
                </datalist>
              </div>
              <p style={{ margin: 0 }}><strong>Status:</strong> {selected.status || "-"}</p>
              <p style={{ margin: 0 }}><strong>Time:</strong> {formatTimestamp(selected.atUtc)}</p>
              {selected.detail ? <p style={{ margin: 0 }}><strong>Detail:</strong> {selected.detail}</p> : null}
              {selected.hasAttachments ? (
                <div className="email-attachments">
                  <strong>Attachments:</strong>
                  {attachmentsLoading ? <span className="email-attachments-status"> loading…</span> : null}
                  {attachmentsError ? <span className="email-attachments-status email-attachments-error"> {attachmentsError}</span> : null}
                  {!attachmentsLoading && !attachmentsError && attachments.length === 0 ? (
                    <span className="email-attachments-status"> none</span>
                  ) : null}
                  <div className="email-attachment-list">
                    {attachments.map((attachment) => (
                      <a
                        key={attachment.index}
                        className="email-attachment-link"
                        href={`/api/mail/attachment?${attachmentQuery(selected)}&index=${attachment.index}`}
                        download={attachment.name}
                      >
                        📎 {attachment.name} <span className="email-attachment-size">({formatBytes(attachment.size)})</span>
                      </a>
                    ))}
                  </div>
                </div>
              ) : null}
              <div className="email-reader-body-wrap">
                {showRawEmail ? (
                  <pre
                    key="raw"
                    className="email-reader-body-block"
                  >
                    {displayBody(selected, decrypted[selected.messageId]).body || "No message body available."}
                  </pre>
                ) : null}
                {!showRawEmail ? (() => {
                  // Body and mode come from one place, together. See
                  // read/body.ts for why picking them separately is the bug.
                  const { body, mode } = displayBody(selected, decrypted[selected.messageId]);
                  const shown = body || "No message body available.";

                  if (mode === "html" && body) {
                    return (
                      <EmailBodyFrame
                        key="html"
                        className="email-reader-body-frame"
                        html={processEmailHtml(body, showImages)}
                      />
                    );
                  } else {
                    return (
                      <pre
                        key="text"
                        className="email-reader-body-block"
                      >
                        {shown}
                      </pre>
                    );
                  }
                })() : null}
                <div style={{ marginTop: 8, display: "flex", gap: 12, fontSize: "0.75rem", opacity: 0.7 }}>
                  {!showRawEmail && (
                    <p style={{ margin: 0 }}>Remote images are not loaded by default.</p>
                  )}
                  <button
                    type="button"
                    onClick={() => setShowRawEmail(!showRawEmail)}
                    style={{
                      padding: 0,
                      border: 0,
                      background: "transparent",
                      color: "var(--accent)",
                      cursor: "pointer",
                      textDecoration: "underline",
                      font: "inherit"
                    }}
                  >
                    {showRawEmail ? "Hide raw email" : "View raw email"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        ) : null}
      </dialog>
    </section>
  );
}
