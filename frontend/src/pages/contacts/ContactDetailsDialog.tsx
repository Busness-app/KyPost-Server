// The read-only contact card shown when a row is clicked.
//
// Split out of ContactsPage purely as markup: it holds no state of its own,
// so every binding it needs arrives as a prop and the page keeps ownership of
// the hooks. Adding state here would move hook order into a component that
// renders conditionally — do not.

import type { MutableRefObject } from "react";
import { contactPhotoUrl, IM_SERVICES, type Contact } from "../../api/contacts";
import type { Group } from "../../api/groups";
import { PGPKeyInfo } from "./PGPKeyInfo";
import { ContactAvatar } from "./ContactAvatar";
import { safeWebsiteHref } from "./formState";

type ContactDetailsDialogProps = {
  /** The dialog element ref the page opens/closes via useDialogOpen. */
  contactDialogRef: MutableRefObject<HTMLDialogElement | null>;
  selectedContact: Contact | null;
  setSelectedContact: (contact: Contact | null) => void;
  /** The account's own PGP key when the card is the user's self contact,
   *  otherwise the contact's own — resolved by the page, not here. */
  selectedContactPgpKey: string;
  /** Resolves a group id to its display name. */
  groupName: (id: string) => string;
  /** uid of the contact currently mid-write, used to disable its actions. */
  busyId: string;
  openEditForm: (contact: Contact) => void;
  removeContact: (contact: Contact) => void | Promise<void>;
  toggleSelfContact: (contact: Contact) => void | Promise<void>;
  handleSuppressContactDiscovery: (contact: Contact) => void | Promise<void>;
};

export function ContactDetailsDialog({
  contactDialogRef,
  selectedContact,
  setSelectedContact,
  selectedContactPgpKey,
  groupName,
  busyId,
  openEditForm,
  removeContact,
  toggleSelfContact,
  handleSuppressContactDiscovery
}: ContactDetailsDialogProps) {
  return (
        <dialog
          ref={contactDialogRef}
          className="contact-details-backdrop"
          onCancel={(event) => {
            event.preventDefault();
            setSelectedContact(null);
          }}
          onClick={(event) => {
            if (event.target === contactDialogRef.current) {
              setSelectedContact(null);
            }
          }}
        >
          {selectedContact ? (
            <div className="contact-details-window" onClick={(e) => e.stopPropagation()}>
              <div className="contact-details-head">
                <div className="contact-details-heading">
                  <ContactAvatar contact={selectedContact} className="contact-details-avatar-lg" />
                  <div>
                    <h3 style={{ margin: 0 }}>{selectedContact.fn}</h3>
                    {selectedContact.pronouns ? (
                      <p className="contacts-sub" style={{ margin: "2px 0 0" }}>
                        {selectedContact.pronouns}
                      </p>
                    ) : null}
                    {selectedContact.org || selectedContact.title ? (
                      <p className="contacts-sub" style={{ margin: "2px 0 0" }}>
                        {[selectedContact.title, selectedContact.org, selectedContact.department].filter(Boolean).join(" · ")}
                      </p>
                    ) : null}
                    {selectedContact.isSelf ? (
                      <p className="contacts-sub" style={{ margin: "2px 0 0" }}>
                        Your contact card — shared when someone scans your PGP QR code
                      </p>
                    ) : null}
                  </div>
                </div>
                <div className="contact-details-actions">
                  <button
                    type="button"
                    onClick={() => void toggleSelfContact(selectedContact)}
                    disabled={busyId === selectedContact.uid}
                  >
                    {selectedContact.isSelf ? "Remove as my card" : "Use as my card"}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedContact(null);
                      openEditForm(selectedContact);
                    }}
                  >
                    Edit
                  </button>
                  <button
                    type="button"
                    className="contacts-action-danger"
                    onClick={() => void removeContact(selectedContact)}
                  >
                    Delete
                  </button>
                  <button type="button" onClick={() => setSelectedContact(null)}>
                    Close
                  </button>
                </div>
              </div>

              <div className="contact-details-content">
                {[
                  selectedContact.prefix,
                  selectedContact.givenName,
                  selectedContact.middleName,
                  selectedContact.familyName,
                  selectedContact.suffix,
                  selectedContact.nickname,
                  selectedContact.phoneticGivenName,
                  selectedContact.phoneticFamilyName
                ].some(Boolean) ? (
                  <div className="contact-details-section">
                    <h4 className="contact-details-section-title">Name</h4>
                    {selectedContact.prefix ? (
                      <div className="contact-details-field">
                        <span>Prefix</span>
                        <span>{selectedContact.prefix}</span>
                      </div>
                    ) : null}
                    {selectedContact.givenName ? (
                      <div className="contact-details-field">
                        <span>Given Name</span>
                        <span>{selectedContact.givenName}</span>
                      </div>
                    ) : null}
                    {selectedContact.middleName ? (
                      <div className="contact-details-field">
                        <span>Middle Name</span>
                        <span>{selectedContact.middleName}</span>
                      </div>
                    ) : null}
                    {selectedContact.familyName ? (
                      <div className="contact-details-field">
                        <span>Family Name</span>
                        <span>{selectedContact.familyName}</span>
                      </div>
                    ) : null}
                    {selectedContact.suffix ? (
                      <div className="contact-details-field">
                        <span>Suffix</span>
                        <span>{selectedContact.suffix}</span>
                      </div>
                    ) : null}
                    {selectedContact.nickname ? (
                      <div className="contact-details-field">
                        <span>Nickname</span>
                        <span>{selectedContact.nickname}</span>
                      </div>
                    ) : null}
                    {selectedContact.phoneticGivenName || selectedContact.phoneticFamilyName ? (
                      <div className="contact-details-field">
                        <span>Phonetic</span>
                        <span>
                          {[selectedContact.phoneticGivenName, selectedContact.phoneticFamilyName].filter(Boolean).join(" ")}
                        </span>
                      </div>
                    ) : null}
                  </div>
                ) : null}

                {selectedContact.emails?.length ? (
                  <div className="contact-details-section">
                    <h4 className="contact-details-section-title">{selectedContact.emails.length > 1 ? "Emails" : "Email"}</h4>
                    {selectedContact.emails.map((e, i) => (
                      <div className="contact-details-field" key={i}>
                        <span>{e.label || "Email"}</span>
                        <a href={`mailto:${e.value}`}>{e.value}</a>
                      </div>
                    ))}
                  </div>
                ) : null}

                {selectedContact.phones?.length ? (
                  <div className="contact-details-section">
                    <h4 className="contact-details-section-title">{selectedContact.phones.length > 1 ? "Phones" : "Phone"}</h4>
                    {selectedContact.phones.map((p, i) => (
                      <div className="contact-details-field" key={i}>
                        <span>{p.label || "Phone"}</span>
                        <a href={`tel:${p.value}`}>{p.value}</a>
                      </div>
                    ))}
                  </div>
                ) : null}

                {selectedContact.addresses?.length ? (
                  <div className="contact-details-section">
                    <h4 className="contact-details-section-title">
                      {selectedContact.addresses.length > 1 ? "Addresses" : "Address"}
                    </h4>
                    {selectedContact.addresses.map((a, i) => (
                      <div className="contact-details-address" key={i}>
                        {a.label ? <span className="contact-details-address-label">{a.label}</span> : null}
                        {a.street ? <span>{a.street}</span> : null}
                        {a.city || a.region || a.postalCode ? (
                          <span>{[a.city, a.region, a.postalCode].filter(Boolean).join(", ")}</span>
                        ) : null}
                        {a.country ? <span>{a.country}</span> : null}
                      </div>
                    ))}
                  </div>
                ) : null}

                {selectedContact.ims?.length ? (
                  <div className="contact-details-section">
                    <h4 className="contact-details-section-title">IM / Social</h4>
                    {selectedContact.ims.map((im, i) => (
                      <div className="contact-details-field" key={i}>
                        <span>{im.service ? IM_SERVICES.find((s) => s.value === im.service)?.label ?? im.service : im.label || "Other"}</span>
                        <span>{im.value}</span>
                      </div>
                    ))}
                  </div>
                ) : null}

                {selectedContact.websites?.length ? (
                  <div className="contact-details-section">
                    <h4 className="contact-details-section-title">Websites</h4>
                    {selectedContact.websites.map((w, i) => {
                      const href = safeWebsiteHref(w.value);
                      return (
                        <div className="contact-details-field" key={i}>
                          <span>{w.label || "Website"}</span>
                          {href ? (
                            <a href={href} target="_blank" rel="noreferrer">
                              {w.value}
                            </a>
                          ) : (
                            <span>{w.value}</span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                ) : null}

                {selectedContact.relations?.length ? (
                  <div className="contact-details-section">
                    <h4 className="contact-details-section-title">Relations</h4>
                    {selectedContact.relations.map((r, i) => (
                      <div className="contact-details-field" key={i}>
                        <span>{r.label || "Relation"}</span>
                        <span>{r.name}</span>
                      </div>
                    ))}
                  </div>
                ) : null}

                {selectedContact.groupIDs?.length ? (
                  <div className="contact-details-field">
                    <span>Groups</span>
                    <span>{selectedContact.groupIDs.map(groupName).join(", ")}</span>
                  </div>
                ) : null}

                {selectedContact.birthday ? (
                  <div className="contact-details-field">
                    <span>Birthday</span>
                    <span>{selectedContact.birthday}</span>
                  </div>
                ) : null}

                {selectedContact.events?.length ? (
                  <div className="contact-details-section">
                    <h4 className="contact-details-section-title">Other dates</h4>
                    {selectedContact.events.map((ev, i) => (
                      <div className="contact-details-field" key={i}>
                        <span>{ev.label || "Date"}</span>
                        <span>{ev.date}</span>
                      </div>
                    ))}
                  </div>
                ) : null}

                {selectedContact.customFields?.length ? (
                  <div className="contact-details-section">
                    <h4 className="contact-details-section-title">Custom fields</h4>
                    {selectedContact.customFields.map((cf, i) => (
                      <div className="contact-details-field" key={i}>
                        <span>{cf.label}</span>
                        <span>{cf.value}</span>
                      </div>
                    ))}
                  </div>
                ) : null}

                {selectedContactPgpKey ? (
                  <div className="contact-details-section">
                    <h4 className="contact-details-section-title">PGP Public Key</h4>
                    <PGPKeyInfo armoredKey={selectedContactPgpKey} />
                    {selectedContact.discoveryCreated ? (
                      <p className="contacts-muted">
                        Added automatically by key discovery
                        {selectedContact.pgpKeySource ? ` (${selectedContact.pgpKeySource})` : ""}
                      </p>
                    ) : null}
                    {!selectedContact.isSelf &&
                    (selectedContact.pgpKeySource === "wkd" || selectedContact.pgpKeySource === "keyserver") ? (
                      <button
                        type="button"
                        onClick={() => {
                          if (!selectedContact) return;
                          void handleSuppressContactDiscovery(selectedContact);
                        }}
                      >
                        Remove key &amp; stop rediscovering
                      </button>
                    ) : null}
                    <details>
                      <summary className="contacts-muted">Show raw key</summary>
                      <pre className="contact-details-notes">{selectedContactPgpKey}</pre>
                    </details>
                  </div>
                ) : null}

                {selectedContact.notes ? (
                  <div className="contact-details-section">
                    <h4 className="contact-details-section-title">Notes</h4>
                    <p className="contact-details-notes">{selectedContact.notes}</p>
                  </div>
                ) : null}

                {!selectedContact.org &&
                !selectedContact.title &&
                !selectedContact.emails?.length &&
                !selectedContact.phones?.length &&
                !selectedContact.addresses?.length &&
                !selectedContact.birthday &&
                !selectedContact.notes &&
                !selectedContact.ims?.length &&
                !selectedContact.websites?.length &&
                !selectedContact.relations?.length &&
                !selectedContact.groupIDs?.length &&
                !selectedContactPgpKey &&
                ![
                  selectedContact.givenName,
                  selectedContact.familyName,
                  selectedContact.middleName,
                  selectedContact.prefix,
                  selectedContact.suffix,
                  selectedContact.nickname
                ].some(Boolean) ? (
                  <p className="contact-details-empty">No additional details on file.</p>
                ) : null}
              </div>
            </div>
          ) : null}
        </dialog>
  );
}
