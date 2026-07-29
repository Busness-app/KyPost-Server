import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { toErrorMessage } from "../api/client";
import {
  bulkDeleteContacts,
  contactPhotoUrl,
  createContact,
  dedupeContacts,
  deleteContact,
  deleteContactPhoto,
  exportContactsUrl,
  importContacts,
  listContacts,
  setContactAsSelf,
  updateContact,
  uploadContactPhoto,
  IM_SERVICES,
  type Contact,
  type ContactAddress,
  type ContactCustomField,
  type ContactEvent,
  type ContactIM,
  type ContactInput,
  type ContactRelation,
  type ContactURL,
  type ContactValue,
  type IMService
} from "../api/contacts";
import { createGroup, deleteGroup, listGroups, renameGroup, type Group } from "../api/groups";
import { getPGPIdentity, lookupPGPKeyserver, suppressContactDiscovery } from "../api/pgp";
import { usePagination } from "../hooks/usePagination";
import { useDialogOpen } from "../hooks/useDialogOpen";
import { PageTabs } from "../components/PageTabs";
import { MultiValueField } from "../components/MultiValueField";

import {
  contactToFormState,
  formStateToInput,
  contactDisplayLine,
  safeWebsiteHref,
  emptyFormState,
  CONTACTS_PER_PAGE,
  RELATION_LABELS,
  type FormState
} from "./contacts/formState";
import { PGPKeyInfo } from "./contacts/PGPKeyInfo";
import { ContactAvatar } from "./contacts/ContactAvatar";
import { ContactDetailsDialog } from "./contacts/ContactDetailsDialog";

export function ContactsPage() {
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [newGroupName, setNewGroupName] = useState("");
  const [creatingGroup, setCreatingGroup] = useState(false);
  const [renamingGroupId, setRenamingGroupId] = useState("");
  const [renameGroupName, setRenameGroupName] = useState("");
  const [groupBusyId, setGroupBusyId] = useState("");
  const [pgpLookupBusy, setPgpLookupBusy] = useState(false);
  const [photoUploading, setPhotoUploading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState("");
  const [busyId, setBusyId] = useState("");
  const [deduping, setDeduping] = useState(false);
  const [search, setSearch] = useState("");

  const [form, setForm] = useState<FormState>(emptyFormState);
  const [editingUid, setEditingUid] = useState("");
  const [saving, setSaving] = useState(false);

  const [selectedContact, setSelectedContact] = useState<Contact | null>(null);
  // The account's real PGP identity (Security page), not the self-marked
  // contact's own pgpKey field — that field is never kept in sync with
  // whatever identity the account currently has (see handlePGPQRKey, which
  // deliberately ignores it for the same reason), so it can't be trusted to
  // show "your" key on your own contact card.
  const [myPgpKey, setMyPgpKey] = useState("");
  const [formOpen, setFormOpen] = useState(false);
  const [selectedUids, setSelectedUids] = useState<string[]>([]);
  const [bulkDeleting, setBulkDeleting] = useState(false);
  const [importing, setImporting] = useState(false);

  const contactDialogRef = useRef<HTMLDialogElement | null>(null);
  const contactFormDialogRef = useRef<HTMLDialogElement | null>(null);
  const importFileInputRef = useRef<HTMLInputElement | null>(null);

  const statusTone = status.toLowerCase().includes("failed") ? "notice notice-error" : "notice notice-success";

  const groupName = (id: string) => groups.find((g) => g.id === id)?.name ?? id;

  const filteredContacts = useMemo(() => {
    if (!search.trim()) {
      return contacts;
    }
    const lowerQuery = search.toLowerCase();
    return contacts.filter((contact) => {
      const searchableText = [
        contact.fn,
        contact.givenName,
        contact.familyName,
        contact.org,
        ...(contact.emails?.map((e) => e.value) ?? []),
        ...(contact.phones?.map((p) => p.value) ?? [])
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return searchableText.includes(lowerQuery);
    });
  }, [contacts, search]);

  const { currentPage, setCurrentPage, totalPages, pageItems: pageContacts } = usePagination(
    filteredContacts,
    CONTACTS_PER_PAGE
  );

  useEffect(() => {
    setCurrentPage(1);
  }, [search, setCurrentPage]);

  async function loadContacts(): Promise<Contact[]> {
    const next = await listContacts();
    next.sort((a, b) => {
      if (a.isSelf !== b.isSelf) {
        return a.isSelf ? -1 : 1;
      }
      return a.fn.localeCompare(b.fn);
    });
    setContacts(next);
    return next;
  }

  async function refresh() {
    try {
      await loadContacts();
    } catch (error: unknown) {
      setStatus(`Failed to load contacts: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
    void listGroups()
      .then(setGroups)
      .catch(() => {});
    void getPGPIdentity()
      .then((identity) => setMyPgpKey(identity.publicKey))
      .catch(() => setMyPgpKey(""));
  }, []);

  useDialogOpen(contactDialogRef, selectedContact);
  useDialogOpen(contactFormDialogRef, formOpen);

  function startCreate() {
    setEditingUid("");
    setForm(emptyFormState);
  }

  function startEdit(contact: Contact) {
    setEditingUid(contact.uid);
    setForm(contactToFormState(contact));
  }

  function openCreateForm() {
    startCreate();
    setFormOpen(true);
  }

  function openEditForm(contact: Contact) {
    startEdit(contact);
    setFormOpen(true);
  }

  function closeForm() {
    startCreate();
    setFormOpen(false);
  }

  async function submitForm(e: FormEvent) {
    e.preventDefault();
    if (saving) return;
    if (!form.fn.trim()) {
      setStatus("Failed: full name is required.");
      return;
    }
    setSaving(true);
    setStatus("");
    try {
      const input = formStateToInput(form);
      if (editingUid) {
        await updateContact(editingUid, input);
        setStatus(`${input.fn} updated.`);
        closeForm();
        await refresh();
      } else {
        const created = await createContact(input);
        setStatus(`${input.fn} added.`);
        closeForm();
        const next = await loadContacts();
        const idx = next.findIndex((c) => c.uid === created.uid);
        if (idx >= 0) {
          setCurrentPage(Math.floor(idx / CONTACTS_PER_PAGE) + 1);
        }
      }
    } catch (error: unknown) {
      setStatus(`Failed to save contact: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setSaving(false);
    }
  }

  async function mergeDuplicates() {
    if (!window.confirm("Scan for duplicate contacts and merge them? This can't be undone.")) {
      return;
    }
    setDeduping(true);
    setStatus("");
    try {
      const report = await dedupeContacts();
      if (report.mergedCount === 0) {
        setStatus("No duplicate contacts found.");
      } else {
        setStatus(`Merged ${report.mergedCount} duplicate contact${report.mergedCount === 1 ? "" : "s"}.`);
        await refresh();
      }
    } catch (error: unknown) {
      setStatus(`Failed to merge duplicates: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setDeduping(false);
    }
  }

  async function removeContact(contact: Contact) {
    if (!window.confirm(`Delete ${contact.fn}?`)) {
      return;
    }
    setBusyId(contact.uid);
    setStatus("");
    try {
      await deleteContact(contact.uid);
      setStatus(`${contact.fn} deleted.`);
      if (editingUid === contact.uid) {
        closeForm();
      }
      if (selectedContact?.uid === contact.uid) {
        setSelectedContact(null);
      }
      await refresh();
    } catch (error: unknown) {
      setStatus(`Failed to delete contact: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setBusyId("");
    }
  }

  async function toggleSelfContact(contact: Contact) {
    setBusyId(contact.uid);
    setStatus("");
    try {
      const updated = await setContactAsSelf(contact.uid, !contact.isSelf);
      setStatus(updated.isSelf ? `${updated.fn} set as your contact card.` : `${updated.fn} removed as your contact card.`);
      const next = await loadContacts();
      if (selectedContact?.uid === updated.uid) {
        setSelectedContact(next.find((c) => c.uid === updated.uid) ?? null);
      }
    } catch (error: unknown) {
      setStatus(`Failed to update contact card: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setBusyId("");
    }
  }

  async function handleSuppressContactDiscovery(contact: Contact) {
    setStatus("");
    try {
      await suppressContactDiscovery(contact.uid);
      const next = await loadContacts();
      setSelectedContact(next.find((c) => c.uid === contact.uid) ?? null);
    } catch (error: unknown) {
      setStatus(`Failed to remove key: ${toErrorMessage(error, "unknown error")}`);
    }
  }

  async function deleteBulk() {
    if (!window.confirm(`Delete ${selectedUids.length} contact${selectedUids.length === 1 ? "" : "s"}?`)) {
      return;
    }
    setBulkDeleting(true);
    setStatus("");
    try {
      const result = await bulkDeleteContacts(selectedUids);
      setSelectedUids([]);
      setStatus(`Deleted ${result.processed} contact${result.processed === 1 ? "" : "s"}.`);
      await refresh();
    } catch (error: unknown) {
      setStatus(`Failed to delete contacts: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setBulkDeleting(false);
    }
  }

  async function handleImportFile() {
    const file = importFileInputRef.current?.files?.[0];
    if (!file) return;

    setImporting(true);
    setStatus("");
    try {
      const result = await importContacts(file);
      // errorCount is the true total; result.errors may be truncated by the
      // server, so use errorCount (falling back to errors.length for
      // resilience) rather than assuming the array length is the total.
      const errorTotal = result.errorCount ?? result.errors.length;
      setStatus(`Imported ${result.imported} contact${result.imported === 1 ? "" : "s"}.${errorTotal > 0 ? ` (${errorTotal} error${errorTotal === 1 ? "" : "s"})` : ""}`);
      await refresh();
      if (importFileInputRef.current) {
        importFileInputRef.current.value = "";
      }
    } catch (error: unknown) {
      setStatus(`Failed to import contacts: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setImporting(false);
    }
  }

  async function handleCreateGroup() {
    const name = newGroupName.trim();
    if (!name) return;
    setCreatingGroup(true);
    try {
      const group = await createGroup(name);
      setGroups((prev) => [...prev, group].sort((a, b) => a.name.localeCompare(b.name)));
      setForm((f) => ({ ...f, groupIDs: [...f.groupIDs, group.id] }));
      setNewGroupName("");
    } catch (error: unknown) {
      setStatus(`Failed to create group: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setCreatingGroup(false);
    }
  }

  function beginRenameGroup(group: Group) {
    setRenamingGroupId(group.id);
    setRenameGroupName(group.name);
  }

  function cancelRenameGroup() {
    setRenamingGroupId("");
    setRenameGroupName("");
  }

  async function handleRenameGroup(id: string) {
    const name = renameGroupName.trim();
    if (!name) return;
    setGroupBusyId(id);
    setStatus("");
    try {
      const updated = await renameGroup(id, name);
      setGroups((prev) => [...prev.filter((g) => g.id !== id), updated].sort((a, b) => a.name.localeCompare(b.name)));
      cancelRenameGroup();
    } catch (error: unknown) {
      setStatus(`Failed to rename group: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setGroupBusyId("");
    }
  }

  async function handleDeleteGroup(group: Group) {
    if (!window.confirm(`Delete group "${group.name}"? It will be removed from any contacts that have it.`)) {
      return;
    }
    setGroupBusyId(group.id);
    setStatus("");
    try {
      await deleteGroup(group.id);
      setGroups((prev) => prev.filter((g) => g.id !== group.id));
      setForm((f) => ({ ...f, groupIDs: f.groupIDs.filter((id) => id !== group.id) }));
      if (renamingGroupId === group.id) {
        cancelRenameGroup();
      }
      await refresh();
    } catch (error: unknown) {
      setStatus(`Failed to delete group: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setGroupBusyId("");
    }
  }

  async function handleLookupPGPKeyserver() {
    const email = form.emails.map((e) => e.value.trim()).find((v) => v !== "");
    if (!email) {
      setStatus("Add an email address before looking up a key on the keyserver.");
      return;
    }
    setPgpLookupBusy(true);
    setStatus("");
    try {
      const result = await lookupPGPKeyserver(email);
      setForm((f) => ({ ...f, pgpKey: result.publicKey }));
      const warnings = [result.revoked ? "revoked" : "", result.expired ? "expired" : ""].filter(Boolean);
      setStatus(
        warnings.length > 0
          ? `Found a key for ${email}, but it is ${warnings.join(" and ")} — review before saving.`
          : `Found a key for ${email}. Review the fingerprint below, then save to attach it.`
      );
    } catch (error: unknown) {
      setStatus(`Keyserver lookup for ${email} failed: ${toErrorMessage(error, "no key found")}`);
    } finally {
      setPgpLookupBusy(false);
    }
  }

  async function handlePhotoUpload(file: File | undefined) {
    if (!file || !editingUid) return;
    setPhotoUploading(true);
    setStatus("");
    try {
      const result = await uploadContactPhoto(editingUid, file);
      setForm((f) => ({ ...f, photoRef: result.photoRef }));
      await refresh();
    } catch (error: unknown) {
      setStatus(`Failed to upload photo: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setPhotoUploading(false);
    }
  }

  async function handlePhotoDelete() {
    if (!editingUid) return;
    setPhotoUploading(true);
    setStatus("");
    try {
      await deleteContactPhoto(editingUid);
      setForm((f) => ({ ...f, photoRef: undefined }));
      await refresh();
    } catch (error: unknown) {
      setStatus(`Failed to remove photo: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setPhotoUploading(false);
    }
  }

  function updateAddress(index: number, patch: Partial<ContactAddress>) {
    setForm({ ...form, addresses: form.addresses.map((a, i) => (i === index ? { ...a, ...patch } : a)) });
  }

  function removeAddress(index: number) {
    setForm({ ...form, addresses: form.addresses.filter((_, i) => i !== index) });
  }

  function addAddress() {
    setForm({
      ...form,
      addresses: [...form.addresses, { label: "", street: "", city: "", region: "", postalCode: "", country: "" }]
    });
  }

  const allPageSelected = pageContacts.length > 0 && pageContacts.every((c) => selectedUids.includes(c.uid));
  const somePageSelected = pageContacts.some((c) => selectedUids.includes(c.uid));

  function toggleAllOnPage() {
    if (allPageSelected) {
      setSelectedUids(selectedUids.filter((uid) => !pageContacts.some((c) => c.uid === uid)));
    } else {
      const newUids = new Set(selectedUids);
      pageContacts.forEach((c) => newUids.add(c.uid));
      setSelectedUids(Array.from(newUids));
    }
  }

  function toggleContact(uid: string) {
    setSelectedUids(
      selectedUids.includes(uid) ? selectedUids.filter((u) => u !== uid) : [...selectedUids, uid]
    );
  }

  // For your own contact card, show the account's real PGP identity rather
  // than this contact's own (unsynced) pgpKey field.
  const selectedContactPgpKey = selectedContact?.isSelf ? myPgpKey : selectedContact?.pgpKey ?? "";

  return (
    <section className="panel contacts-page">
      <header className="contacts-header">
        <div>
          <h2>Contacts</h2>
        </div>
        <div className="contacts-header-actions">
          {!loading && contacts.length > 0 ? (
            <div className="contacts-stats">
              <span className="contacts-stat">
                <strong>{contacts.length}</strong> contact{contacts.length === 1 ? "" : "s"}
              </span>
            </div>
          ) : null}
          {!loading && contacts.length > 1 ? (
            <button
              type="button"
              className="contacts-action"
              onClick={() => void mergeDuplicates()}
              disabled={deduping}
            >
              {deduping ? "Merging..." : "Merge Duplicates"}
            </button>
          ) : null}
          {!loading && selectedUids.length > 0 ? (
            <button
              type="button"
              className="contacts-action contacts-action-danger"
              onClick={() => void deleteBulk()}
              disabled={bulkDeleting}
            >
              {bulkDeleting ? "Deleting..." : `Delete Selected (${selectedUids.length})`}
            </button>
          ) : null}
          {!loading && contacts.length > 0 ? (
            <>
              <a href={exportContactsUrl("vcard")} className="contacts-action" download="contacts.vcf">
                Export vCard
              </a>
              <a href={exportContactsUrl("csv")} className="contacts-action" download="contacts.csv">
                Export CSV
              </a>
              <button
                type="button"
                className="contacts-action"
                onClick={() => importFileInputRef.current?.click()}
                disabled={importing}
              >
                {importing ? "Importing..." : "Import"}
              </button>
              <input
                ref={importFileInputRef}
                type="file"
                accept=".vcf"
                onChange={() => void handleImportFile()}
                style={{ display: "none" }}
              />
            </>
          ) : null}
          <button type="button" onClick={openCreateForm}>
            New Contact
          </button>
        </div>
      </header>

      <div className="contacts-card contacts-list-card">
        <div className="contacts-list-head">
          <h3>Address Book</h3>
          {!loading && contacts.length > 0 ? (
            <span className="contacts-count">
              {filteredContacts.length}
              {search.trim() ? ` of ${contacts.length}` : ""}
            </span>
          ) : null}
        </div>

        {!loading && contacts.length > 0 ? (
          <div style={{ marginBottom: "12px" }}>
            <input
              type="text"
              placeholder="Search by name, email, phone, or organization..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{
                width: "100%",
                padding: "8px",
                borderRadius: "4px",
                border: "1px solid var(--border-color)",
                backgroundColor: "var(--bg-color)"
              }}
            />
          </div>
        ) : null}

        {loading ? <p className="contacts-muted">Loading contacts...</p> : null}
        {!loading && contacts.length === 0 ? <div className="contacts-empty">No contacts yet.</div> : null}
        {!loading && contacts.length > 0 && filteredContacts.length === 0 ? (
          <div className="contacts-empty">No contacts match your search.</div>
        ) : null}

        {!loading && contacts.length > 0 ? (
          <>
            <PageTabs
              totalPages={totalPages}
              currentPage={currentPage}
              onSelect={setCurrentPage}
              classPrefix="contacts"
              ariaLabel="Contact pages"
            />

            <div className="contacts-table-wrap">
              <div className="contacts-table-scroll">
                <table className="contacts-table">
                  <thead>
                    <tr>
                      <th style={{ width: "40px", textAlign: "center" }}>
                        <input
                          type="checkbox"
                          checked={allPageSelected}
                          ref={(el) => {
                            if (el) el.indeterminate = somePageSelected && !allPageSelected;
                          }}
                          onChange={() => toggleAllOnPage()}
                          aria-label="Select all on page"
                        />
                      </th>
                      <th>Name</th>
                      <th>Contact Info</th>
                      <th className="contacts-col-actions">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pageContacts.map((contact) => {
                      const busy = busyId === contact.uid;
                      const isSelected = selectedUids.includes(contact.uid);
                      return (
                        <tr
                          key={contact.uid}
                          className={busy ? "contacts-row contacts-row-busy" : "contacts-row"}
                          onClick={() => setSelectedContact(contact)}
                        >
                          <td style={{ width: "40px", textAlign: "center" }} onClick={(e) => e.stopPropagation()}>
                            <input
                              type="checkbox"
                              checked={isSelected}
                              onChange={() => toggleContact(contact.uid)}
                              aria-label={`Select ${contact.fn}`}
                            />
                          </td>
                          <td>
                            <button
                              type="button"
                              className="contacts-identity contacts-row-open"
                              onClick={() => setSelectedContact(contact)}
                            >
                              <ContactAvatar contact={contact} />
                              <div className="contacts-identity-text">
                                <span className="contacts-name">{contact.fn}</span>
                                {contact.isSelf ? <span className="contacts-sub">Your contact card</span> : null}
                                {contact.org ? <span className="contacts-sub">{contact.org}</span> : null}
                              </div>
                              <span className="contacts-row-chevron" aria-hidden="true">
                                &rsaquo;
                              </span>
                            </button>
                          </td>
                          <td>{contactDisplayLine(contact) || <span className="contacts-muted">—</span>}</td>
                          <td className="contacts-col-actions">
                            <div className="contacts-actions" onClick={(e) => e.stopPropagation()}>
                              <button
                                type="button"
                                className="contacts-action"
                                onClick={() => openEditForm(contact)}
                                disabled={busy}
                              >
                                Edit
                              </button>
                              <button
                                type="button"
                                className="contacts-action contacts-action-danger"
                                onClick={() => void removeContact(contact)}
                                disabled={busy}
                              >
                                {busy ? "Deleting..." : "Delete"}
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        ) : null}
      </div>

      {status ? <p className={statusTone}>{status}</p> : null}

      <dialog
        ref={contactFormDialogRef}
        className="contact-details-backdrop"
        onCancel={(event) => {
          event.preventDefault();
          closeForm();
        }}
        onClick={(event) => {
          if (event.target === contactFormDialogRef.current) {
            closeForm();
          }
        }}
      >
        <div className="contact-form-window" onClick={(e) => e.stopPropagation()}>
          <form onSubmit={submitForm} className="contacts-form-card">
            <h3>{editingUid ? "Edit Contact" : "Add Contact"}</h3>

            <div className="contacts-multivalue">
              <div className="contacts-multivalue-label">Photo</div>
              <div className="contacts-photo-row">
                {editingUid && form.photoRef ? (
                  <img src={contactPhotoUrl(editingUid)} alt="" className="contacts-avatar contacts-photo-preview" />
                ) : (
                  <span className="contacts-avatar contacts-photo-preview" aria-hidden="true">
                    {form.fn.slice(0, 1).toUpperCase() || "?"}
                  </span>
                )}
                <input
                  type="file"
                  accept="image/*"
                  disabled={!editingUid || photoUploading}
                  onChange={(e) => void handlePhotoUpload(e.target.files?.[0])}
                />
                {form.photoRef ? (
                  <button
                    type="button"
                    className="contacts-action"
                    onClick={() => void handlePhotoDelete()}
                    disabled={photoUploading}
                  >
                    Remove
                  </button>
                ) : null}
              </div>
              {!editingUid ? <p className="contacts-muted">Save the contact first to add a photo.</p> : null}
            </div>

            <label>
              <div>Full Name</div>
              <input value={form.fn} onChange={(e) => setForm({ ...form, fn: e.target.value })} autoComplete="off" />
            </label>
            <label>
              <div>Prefix</div>
              <input value={form.prefix} onChange={(e) => setForm({ ...form, prefix: e.target.value })} autoComplete="off" />
            </label>
            <label>
              <div>Given Name</div>
              <input
                value={form.givenName}
                onChange={(e) => setForm({ ...form, givenName: e.target.value })}
                autoComplete="off"
              />
            </label>
            <label>
              <div>Middle Name</div>
              <input
                value={form.middleName}
                onChange={(e) => setForm({ ...form, middleName: e.target.value })}
                autoComplete="off"
              />
            </label>
            <label>
              <div>Family Name</div>
              <input
                value={form.familyName}
                onChange={(e) => setForm({ ...form, familyName: e.target.value })}
                autoComplete="off"
              />
            </label>
            <label>
              <div>Suffix</div>
              <input value={form.suffix} onChange={(e) => setForm({ ...form, suffix: e.target.value })} autoComplete="off" />
            </label>
            <label>
              <div>Nickname</div>
              <input value={form.nickname} onChange={(e) => setForm({ ...form, nickname: e.target.value })} autoComplete="off" />
            </label>
            <label>
              <div>Phonetic Given Name</div>
              <input
                value={form.phoneticGivenName}
                onChange={(e) => setForm({ ...form, phoneticGivenName: e.target.value })}
                autoComplete="off"
              />
            </label>
            <label>
              <div>Phonetic Family Name</div>
              <input
                value={form.phoneticFamilyName}
                onChange={(e) => setForm({ ...form, phoneticFamilyName: e.target.value })}
                autoComplete="off"
              />
            </label>
            <label>
              <div>Pronouns</div>
              <div className="contacts-pronoun-chips">
                {["He/Him", "She/Her", "They/Them"].map((p) => (
                  <button
                    key={p}
                    type="button"
                    className={`contacts-action contacts-pronoun-chip ${form.pronouns === p ? "active" : ""}`}
                    onClick={() => setForm({ ...form, pronouns: form.pronouns === p ? "" : p })}
                  >
                    {p}
                  </button>
                ))}
              </div>
              <input
                type="text"
                placeholder="Custom pronouns"
                value={form.pronouns}
                onChange={(e) => setForm({ ...form, pronouns: e.target.value })}
                autoComplete="off"
              />
            </label>
            <label>
              <div>Organization</div>
              <input value={form.org} onChange={(e) => setForm({ ...form, org: e.target.value })} autoComplete="off" />
            </label>
            <label>
              <div>Title</div>
              <input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} autoComplete="off" />
            </label>
            <label>
              <div>Department</div>
              <input value={form.department} onChange={(e) => setForm({ ...form, department: e.target.value })} autoComplete="off" />
            </label>
            <label>
              <div>Birthday</div>
              <input type="date" value={form.birthday} onChange={(e) => setForm({ ...form, birthday: e.target.value })} />
            </label>

            <MultiValueField
              label="Emails"
              rows={form.emails}
              onChange={(emails) => setForm({ ...form, emails })}
              emptyRow={{ label: "", value: "" }}
              addLabel="+ Add email"
              renderRow={(row, update) => (
                <>
                  <select value={row.label ?? ""} onChange={(e) => update({ label: e.target.value })}>
                    <option value="">Other</option>
                    <option value="home">Home</option>
                    <option value="work">Work</option>
                  </select>
                  <input
                    type="email"
                    placeholder="email@example.com"
                    value={row.value}
                    onChange={(e) => update({ value: e.target.value })}
                    autoComplete="off"
                  />
                </>
              )}
            />

            <MultiValueField
              label="Phones"
              rows={form.phones}
              onChange={(phones) => setForm({ ...form, phones })}
              emptyRow={{ label: "", value: "" }}
              addLabel="+ Add phone"
              renderRow={(row, update) => (
                <>
                  <select value={row.label ?? ""} onChange={(e) => update({ label: e.target.value })}>
                    <option value="">Other</option>
                    <option value="home">Home</option>
                    <option value="work">Work</option>
                    <option value="mobile">Mobile</option>
                    <option value="fax">Fax</option>
                  </select>
                  <input
                    type="text"
                    placeholder="Phone number"
                    value={row.value}
                    onChange={(e) => update({ value: e.target.value })}
                    autoComplete="off"
                  />
                </>
              )}
            />

            <div className="contacts-multivalue">
              <div className="contacts-multivalue-label">Addresses</div>
              {form.addresses.map((addr, i) => (
                <div className="contacts-multivalue-row" key={i}>
                  <div className="contacts-address-row">
                    <input
                      type="text"
                      placeholder="Street"
                      value={addr.street ?? ""}
                      onChange={(e) => updateAddress(i, { street: e.target.value })}
                    />
                    <select value={addr.label ?? ""} onChange={(e) => updateAddress(i, { label: e.target.value })}>
                      <option value="">Other</option>
                      <option value="home">Home</option>
                      <option value="work">Work</option>
                    </select>
                    <input
                      type="text"
                      placeholder="City"
                      value={addr.city ?? ""}
                      onChange={(e) => updateAddress(i, { city: e.target.value })}
                    />
                    <input
                      type="text"
                      placeholder="Region/State"
                      value={addr.region ?? ""}
                      onChange={(e) => updateAddress(i, { region: e.target.value })}
                    />
                    <input
                      type="text"
                      placeholder="Postal code"
                      value={addr.postalCode ?? ""}
                      onChange={(e) => updateAddress(i, { postalCode: e.target.value })}
                    />
                    <input
                      type="text"
                      placeholder="Country"
                      value={addr.country ?? ""}
                      onChange={(e) => updateAddress(i, { country: e.target.value })}
                    />
                  </div>
                  <button
                    type="button"
                    className="contacts-multivalue-remove"
                    onClick={() => removeAddress(i)}
                    aria-label="Remove address"
                  >
                    &times;
                  </button>
                </div>
              ))}
              <button type="button" className="contacts-multivalue-add" onClick={addAddress}>
                + Add address
              </button>
            </div>

            <MultiValueField
              label="IM / Social"
              rows={form.ims}
              onChange={(ims) => setForm({ ...form, ims })}
              emptyRow={{ service: "whatsapp", label: "", value: "" }}
              addLabel="+ Add IM / social link"
              renderRow={(row, update) => (
                <>
                  <select value={row.service ?? ""} onChange={(e) => update({ service: e.target.value as IMService })}>
                    {IM_SERVICES.map((s) => (
                      <option key={s.value} value={s.value}>
                        {s.label}
                      </option>
                    ))}
                  </select>
                  {row.service === "" ? (
                    <input
                      type="text"
                      placeholder="Service name"
                      value={row.label ?? ""}
                      onChange={(e) => update({ label: e.target.value })}
                    />
                  ) : null}
                  <input
                    type="text"
                    placeholder="Handle / number / URL"
                    value={row.value}
                    onChange={(e) => update({ value: e.target.value })}
                    autoComplete="off"
                  />
                </>
              )}
            />

            <MultiValueField
              label="Websites"
              rows={form.websites}
              onChange={(websites) => setForm({ ...form, websites })}
              emptyRow={{ label: "", value: "" }}
              addLabel="+ Add website"
              renderRow={(row, update) => (
                <>
                  <input
                    type="text"
                    placeholder="Label (e.g. homepage)"
                    value={row.label ?? ""}
                    onChange={(e) => update({ label: e.target.value })}
                  />
                  <input
                    type="url"
                    placeholder="https://..."
                    value={row.value}
                    onChange={(e) => update({ value: e.target.value })}
                    autoComplete="off"
                  />
                </>
              )}
            />

            <MultiValueField
              label="Relations"
              rows={form.relations}
              onChange={(relations) => setForm({ ...form, relations })}
              emptyRow={{ label: "spouse", name: "" }}
              addLabel="+ Add relation"
              renderRow={(row, update) => (
                <>
                  <select value={row.label ?? ""} onChange={(e) => update({ label: e.target.value })}>
                    {RELATION_LABELS.map((l) => (
                      <option key={l} value={l}>
                        {l}
                      </option>
                    ))}
                  </select>
                  <input
                    type="text"
                    placeholder="Name"
                    value={row.name}
                    onChange={(e) => update({ name: e.target.value })}
                    autoComplete="off"
                  />
                </>
              )}
            />

            <MultiValueField
              label="Other dates"
              rows={form.events}
              onChange={(events) => setForm({ ...form, events })}
              emptyRow={{ label: "anniversary", date: "" }}
              addLabel="+ Add date"
              renderRow={(row, update) => (
                <>
                  <select value={row.label ?? ""} onChange={(e) => update({ label: e.target.value })}>
                    <option value="anniversary">Anniversary</option>
                    <option value="other">Other</option>
                  </select>
                  <input type="date" value={row.date} onChange={(e) => update({ date: e.target.value })} />
                </>
              )}
            />

            <MultiValueField
              label="Custom fields"
              rows={form.customFields}
              onChange={(customFields) => setForm({ ...form, customFields })}
              emptyRow={{ label: "", value: "" }}
              addLabel="+ Add custom field"
              renderRow={(row, update) => (
                <>
                  <input
                    type="text"
                    placeholder="Label"
                    value={row.label}
                    onChange={(e) => update({ label: e.target.value })}
                  />
                  <input
                    type="text"
                    placeholder="Value"
                    value={row.value}
                    onChange={(e) => update({ value: e.target.value })}
                  />
                </>
              )}
            />

            <div className="contacts-multivalue">
              <div className="contacts-multivalue-label">Groups</div>
              {groups.map((g) =>
                renamingGroupId === g.id ? (
                  <div key={g.id} className="contacts-group-row">
                    <input
                      type="text"
                      value={renameGroupName}
                      onChange={(e) => setRenameGroupName(e.target.value)}
                      autoComplete="off"
                    />
                    <button
                      type="button"
                      className="contacts-action"
                      onClick={() => void handleRenameGroup(g.id)}
                      disabled={groupBusyId === g.id || !renameGroupName.trim()}
                    >
                      Save
                    </button>
                    <button type="button" className="contacts-action" onClick={cancelRenameGroup} disabled={groupBusyId === g.id}>
                      Cancel
                    </button>
                  </div>
                ) : (
                  <div key={g.id} className="contacts-group-row">
                    <label className="contacts-group-checkbox">
                      <input
                        type="checkbox"
                        checked={form.groupIDs.includes(g.id)}
                        onChange={() =>
                          setForm({
                            ...form,
                            groupIDs: form.groupIDs.includes(g.id)
                              ? form.groupIDs.filter((id) => id !== g.id)
                              : [...form.groupIDs, g.id]
                          })
                        }
                      />
                      {g.name}
                    </label>
                    <button
                      type="button"
                      className="contacts-action"
                      onClick={() => beginRenameGroup(g)}
                      disabled={groupBusyId === g.id}
                    >
                      Rename
                    </button>
                    <button
                      type="button"
                      className="contacts-action-danger"
                      onClick={() => void handleDeleteGroup(g)}
                      disabled={groupBusyId === g.id}
                    >
                      Delete
                    </button>
                  </div>
                )
              )}
              <div className="contacts-multivalue-row">
                <input
                  type="text"
                  placeholder="New group name"
                  value={newGroupName}
                  onChange={(e) => setNewGroupName(e.target.value)}
                  autoComplete="off"
                />
                <button
                  type="button"
                  className="contacts-action"
                  onClick={() => void handleCreateGroup()}
                  disabled={creatingGroup || !newGroupName.trim()}
                >
                  + New group
                </button>
              </div>
            </div>

            <label>
              <div>PGP Public Key</div>
              <textarea
                value={form.pgpKey}
                onChange={(e) => setForm({ ...form, pgpKey: e.target.value })}
                rows={4}
                placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"
              />
            </label>
            <button
              type="button"
              className="contacts-action"
              onClick={() => void handleLookupPGPKeyserver()}
              disabled={pgpLookupBusy}
            >
              {pgpLookupBusy ? "Looking up…" : "Look up on keyserver"}
            </button>
            <PGPKeyInfo armoredKey={form.pgpKey} />

            <label>
              <div>Notes</div>
              <textarea value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} rows={3} />
            </label>

            <div className="contacts-form-actions">
              <button type="submit" className="contacts-create-submit" disabled={saving}>
                {saving ? "Saving..." : editingUid ? "Save Changes" : "Add Contact"}
              </button>
              <button type="button" className="contacts-action" onClick={closeForm} disabled={saving}>
                Cancel
              </button>
            </div>
          </form>
        </div>
      </dialog>

      <ContactDetailsDialog
        contactDialogRef={contactDialogRef}
        selectedContact={selectedContact}
        setSelectedContact={setSelectedContact}
        selectedContactPgpKey={selectedContactPgpKey}
        groupName={groupName}
        busyId={busyId}
        openEditForm={openEditForm}
        removeContact={removeContact}
        toggleSelfContact={toggleSelfContact}
        handleSuppressContactDiscovery={handleSuppressContactDiscovery}
      />
    </section>
  );
}
