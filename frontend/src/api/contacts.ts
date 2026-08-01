import { getJSON, postJSON, putJSON, deleteJSON, postFormData } from "./client";

export type ContactValue = {
  label?: string;
  value: string;
};

export type ContactAddress = {
  label?: string;
  street?: string;
  city?: string;
  region?: string;
  postalCode?: string;
  country?: string;
};

// Fixed IM/social-media service catalog. "" (empty service) means "Other",
// with the user-supplied service name carried in label.
export type IMService = "whatsapp" | "signal" | "telegram" | "instagram" | "x" | "linkedin" | "facebook" | "mastodon" | "matrix" | "";

export const IM_SERVICES: { value: IMService; label: string }[] = [
  { value: "whatsapp", label: "WhatsApp" },
  { value: "signal", label: "Signal" },
  { value: "telegram", label: "Telegram" },
  { value: "instagram", label: "Instagram" },
  { value: "x", label: "X (Twitter)" },
  { value: "linkedin", label: "LinkedIn" },
  { value: "facebook", label: "Facebook" },
  { value: "mastodon", label: "Mastodon" },
  { value: "matrix", label: "Matrix" },
  { value: "", label: "Other" }
];

export type ContactIM = {
  service?: IMService;
  label?: string;
  value: string;
};

export type ContactURL = {
  label?: string;
  value: string;
};

export type ContactRelation = {
  label?: string;
  name: string;
};

export type ContactEvent = {
  label?: string;
  date: string;
};

export type ContactCustomField = {
  label: string;
  value: string;
};

type ContactExtendedFields = {
  photoRef?: string;
  groupIDs?: string[];
  pgpKey?: string;
  pgpKeySource?: string;
  pgpKeyFingerprint?: string;
  pgpKeyVerified?: boolean;
  discoveryCreated?: boolean;
  ims?: ContactIM[];
  websites?: ContactURL[];
  relations?: ContactRelation[];
  events?: ContactEvent[];
  phoneticGivenName?: string;
  phoneticFamilyName?: string;
  department?: string;
  customFields?: ContactCustomField[];
  pronouns?: string;
};

export type Contact = {
  uid: string;
  rev: number;
  deleted?: boolean;
  createdAt: string;
  updatedAt: string;
  fn: string;
  givenName?: string;
  familyName?: string;
  middleName?: string;
  prefix?: string;
  suffix?: string;
  nickname?: string;
  org?: string;
  title?: string;
  emails?: ContactValue[];
  phones?: ContactValue[];
  addresses?: ContactAddress[];
  notes?: string;
  birthday?: string;
  mergedUIDs?: string[];
  mergedInto?: string;
  isSelf?: boolean;
} & ContactExtendedFields;

export type ContactInput = {
  fn: string;
  givenName?: string;
  familyName?: string;
  middleName?: string;
  prefix?: string;
  suffix?: string;
  nickname?: string;
  org?: string;
  title?: string;
  emails?: ContactValue[];
  phones?: ContactValue[];
  addresses?: ContactAddress[];
  notes?: string;
  birthday?: string;
} & ContactExtendedFields;

type ContactsListResponse = {
  contacts: Contact[];
};

export async function listContacts(): Promise<Contact[]> {
  const res = await getJSON<ContactsListResponse>("/api/contacts");
  return res.contacts ?? [];
}

export function createContact(input: ContactInput): Promise<Contact> {
  return postJSON<Contact>("/api/contacts", input);
}

export function updateContact(uid: string, input: ContactInput): Promise<Contact> {
  return putJSON<Contact>(`/api/contacts/${encodeURIComponent(uid)}`, input);
}

export function deleteContact(uid: string): Promise<{ ok: boolean; removed: boolean }> {
  return deleteJSON<{ ok: boolean; removed: boolean }>(`/api/contacts/${encodeURIComponent(uid)}`);
}

export function setContactAsSelf(uid: string, self: boolean): Promise<Contact> {
  return postJSON<Contact>(`/api/contacts/${encodeURIComponent(uid)}/self`, { self });
}

export type DedupeMerge = {
  survivor: string;
  absorbed: string[];
};

export type DedupeReport = {
  mergedCount: number;
  groups: DedupeMerge[];
};

export function dedupeContacts(): Promise<DedupeReport> {
  return postJSON<DedupeReport>("/api/contacts/dedupe", {});
}

export type DAVPasswordStatus = {
  configured: boolean;
  createdAt?: string;
};

export function getDAVPasswordStatus(): Promise<DAVPasswordStatus> {
  return getJSON<DAVPasswordStatus>("/api/contacts/dav-password");
}

export type DAVPasswordGenerated = {
  password: string;
  createdAt: string;
};

export function generateDAVPassword(): Promise<DAVPasswordGenerated> {
  return postJSON<DAVPasswordGenerated>("/api/contacts/dav-password", {});
}

export function revokeDAVPassword(): Promise<{ ok: boolean }> {
  return deleteJSON<{ ok: boolean }>("/api/contacts/dav-password");
}

export type DiscoveredAddressBook = {
  path: string;
  name?: string;
  contactCount: number;
};

export type CardDAVClientConfig = {
  configured: boolean;
  serverUrl?: string;
  username?: string;
  addressBookPath?: string;
  updatedAt?: string;
  lastSyncedAt?: string;
  lastSyncError?: string;
  lastSyncImported?: number;
  lastSyncUpdated?: number;
  discoveredAddressBooks?: DiscoveredAddressBook[];
};

export type CardDAVClientInput = {
  serverUrl: string;
  username: string;
  password: string;
  addressBookPath?: string;
};

export function getCardDAVClientConfig(): Promise<CardDAVClientConfig> {
  return getJSON<CardDAVClientConfig>("/api/contacts/carddav-client/config");
}

export function saveCardDAVClientConfig(input: CardDAVClientInput): Promise<CardDAVClientConfig> {
  return postJSON<CardDAVClientConfig>("/api/contacts/carddav-client/config", input);
}

export function deleteCardDAVClientConfig(): Promise<{ ok: boolean }> {
  return deleteJSON<{ ok: boolean }>("/api/contacts/carddav-client/config");
}

export type CardDAVClientSyncResult = {
  ok: boolean;
  imported?: number;
  updated?: number;
  addressBookPath?: string;
  syncedAt?: string;
  error?: string;
  discoveredAddressBooks?: DiscoveredAddressBook[];
};

export function syncCardDAVClient(): Promise<CardDAVClientSyncResult> {
  return postJSON<CardDAVClientSyncResult>("/api/contacts/carddav-client/sync", {});
}

type BulkDeleteFailure = {
  id: string;
  error: string;
};

type BulkDeleteResult = {
  ok: boolean;
  processed: number;
  failed: BulkDeleteFailure[];
};

export function bulkDeleteContacts(ids: string[]): Promise<BulkDeleteResult> {
  return postJSON<BulkDeleteResult>("/api/contacts/bulk-delete", { ids });
}

export function exportContactsUrl(format: "vcard" | "csv"): string {
  return `/api/contacts/export?format=${encodeURIComponent(format)}`;
}

type ImportResult = {
  imported: number;
  skipped: number;
  errors: string[];
  // Total number of errors encountered, which may exceed errors.length: the
  // server caps how many error strings it returns but still reports the
  // true count here so truncation isn't silently dropped.
  errorCount: number;
};

export function importContacts(file: File): Promise<ImportResult> {
  const formData = new FormData();
  formData.append("file", file);
  return postFormData<ImportResult>("/api/contacts/import", formData);
}

export function contactPhotoUrl(uid: string): string {
  return `/api/contacts/${encodeURIComponent(uid)}/photo`;
}

export function uploadContactPhoto(uid: string, file: File): Promise<{ photoRef: string; photoUrl: string }> {
  const formData = new FormData();
  formData.append("photo", file);
  return postFormData<{ photoRef: string; photoUrl: string }>(`/api/contacts/${encodeURIComponent(uid)}/photo`, formData);
}

export function deleteContactPhoto(uid: string): Promise<{ ok: boolean }> {
  return deleteJSON<{ ok: boolean }>(`/api/contacts/${encodeURIComponent(uid)}/photo`);
}

export function searchContacts(q: string, limit = 5): Promise<{ contacts: Contact[] }> {
  return getJSON(`/api/contacts/search?q=${encodeURIComponent(q)}&limit=${limit}`);
}
