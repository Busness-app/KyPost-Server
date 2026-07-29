// The contact edit form's local shape and its conversions to and from the
// API's Contact/ContactInput. Pure — no React — so the round-trip is
// unit-testable without rendering the page.

import {
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
} from "../../api/contacts";

export type FormState = {
  fn: string;
  givenName: string;
  familyName: string;
  middleName: string;
  prefix: string;
  suffix: string;
  nickname: string;
  org: string;
  title: string;
  department: string;
  phoneticGivenName: string;
  phoneticFamilyName: string;
  birthday: string;
  notes: string;
  pronouns: string;
  pgpKey: string;
  photoRef?: string;
  groupIDs: string[];
  emails: ContactValue[];
  phones: ContactValue[];
  addresses: ContactAddress[];
  ims: ContactIM[];
  websites: ContactURL[];
  relations: ContactRelation[];
  events: ContactEvent[];
  customFields: ContactCustomField[];
};

export const emptyFormState: FormState = {
  fn: "",
  givenName: "",
  familyName: "",
  middleName: "",
  prefix: "",
  suffix: "",
  nickname: "",
  org: "",
  title: "",
  department: "",
  phoneticGivenName: "",
  phoneticFamilyName: "",
  birthday: "",
  notes: "",
  pronouns: "",
  pgpKey: "",
  photoRef: undefined,
  groupIDs: [],
  emails: [],
  phones: [],
  addresses: [],
  ims: [],
  websites: [],
  relations: [],
  events: [],
  customFields: []
};

export const CONTACTS_PER_PAGE = 20;

export const RELATION_LABELS = ["spouse", "child", "parent", "partner", "manager", "assistant", "friend", "relative", "other"];

export function contactToFormState(contact: Contact): FormState {
  return {
    fn: contact.fn,
    givenName: contact.givenName ?? "",
    familyName: contact.familyName ?? "",
    middleName: contact.middleName ?? "",
    prefix: contact.prefix ?? "",
    suffix: contact.suffix ?? "",
    nickname: contact.nickname ?? "",
    org: contact.org ?? "",
    title: contact.title ?? "",
    department: contact.department ?? "",
    phoneticGivenName: contact.phoneticGivenName ?? "",
    phoneticFamilyName: contact.phoneticFamilyName ?? "",
    birthday: contact.birthday ?? "",
    notes: contact.notes ?? "",
    pronouns: contact.pronouns ?? "",
    pgpKey: contact.pgpKey ?? "",
    photoRef: contact.photoRef,
    groupIDs: contact.groupIDs ?? [],
    emails: contact.emails ?? [],
    phones: contact.phones ?? [],
    addresses: contact.addresses ?? [],
    ims: contact.ims ?? [],
    websites: contact.websites ?? [],
    relations: contact.relations ?? [],
    events: contact.events ?? [],
    customFields: contact.customFields ?? []
  };
}

export function keepNonEmpty<T>(rows: T[], keep: (row: T) => boolean): T[] | undefined {
  const filtered = rows.filter(keep);
  return filtered.length ? filtered : undefined;
}

export function formStateToInput(form: FormState): ContactInput {
  return {
    fn: form.fn.trim(),
    givenName: form.givenName.trim() || undefined,
    familyName: form.familyName.trim() || undefined,
    middleName: form.middleName.trim() || undefined,
    prefix: form.prefix.trim() || undefined,
    suffix: form.suffix.trim() || undefined,
    nickname: form.nickname.trim() || undefined,
    org: form.org.trim() || undefined,
    title: form.title.trim() || undefined,
    department: form.department.trim() || undefined,
    phoneticGivenName: form.phoneticGivenName.trim() || undefined,
    phoneticFamilyName: form.phoneticFamilyName.trim() || undefined,
    birthday: form.birthday.trim() || undefined,
    notes: form.notes.trim() || undefined,
    pronouns: form.pronouns.trim() || undefined,
    pgpKey: form.pgpKey.trim() || undefined,
    photoRef: form.photoRef,
    groupIDs: form.groupIDs.length ? form.groupIDs : undefined,
    emails: keepNonEmpty(form.emails, (r) => r.value.trim() !== ""),
    phones: keepNonEmpty(form.phones, (r) => r.value.trim() !== ""),
    addresses: keepNonEmpty(form.addresses, (a) => Boolean(a.street || a.city || a.region || a.postalCode || a.country)),
    ims: keepNonEmpty(form.ims, (r) => r.value.trim() !== ""),
    websites: keepNonEmpty(form.websites, (r) => r.value.trim() !== ""),
    relations: keepNonEmpty(form.relations, (r) => r.name.trim() !== ""),
    events: keepNonEmpty(form.events, (r) => r.date.trim() !== ""),
    customFields: keepNonEmpty(form.customFields, (r) => r.label.trim() !== "" && r.value.trim() !== "")
  };
}

export function contactDisplayLine(contact: Contact): string {
  return contact.emails?.[0]?.value ?? contact.phones?.[0]?.value ?? "";
}

// Websites are freeform user input rendered as a clickable <a href>. Restrict
// to http/https so a value like "javascript:..." can't execute when clicked.
export function safeWebsiteHref(url: string): string | undefined {
  try {
    const parsed = new URL(url, window.location.origin);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.href : undefined;
  } catch {
    return undefined;
  }
}
