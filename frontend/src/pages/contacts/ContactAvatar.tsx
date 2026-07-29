// A contact's photo, falling back to their initial.

import { contactPhotoUrl, type Contact } from "../../api/contacts";

export function ContactAvatar({ contact, className }: { contact: Contact; className?: string }) {
  const classes = ["contacts-avatar", className].filter(Boolean).join(" ");
  if (contact.photoRef) {
    return <img src={contactPhotoUrl(contact.uid)} alt="" className={classes} />;
  }
  return (
    <span className={classes} aria-hidden="true">
      {contact.fn.slice(0, 1).toUpperCase() || "?"}
    </span>
  );
}

