import { getJSON, postJSON, deleteJSON } from "./client";

export type SendAsAliasStatus = "pending" | "verified" | "failed";

// Mirrors backend/internal/sendas.Alias's JSON shape.
export type SendAsAlias = {
  id: string;
  userId: string;
  email: string;
  displayName?: string;
  verificationCode: string;
  status: SendAsAliasStatus;
  createdAt: string;
  expiresAt: string;
  verifiedAt?: string;
  failedAt?: string;
  // Set on the record the server creates for your own account address, which
  // has to pass this same check before your public key can be published for
  // it. You didn't ask for it, so the UI says why it's there.
  auto?: boolean;
};

type SendAsAliasesResponse = {
  aliases: SendAsAlias[];
};

export type CreateSendAsAliasResult = {
  ok: boolean;
  id: string;
  status: SendAsAliasStatus;
  expiresAt: string;
};

export async function listSendAsAliases(): Promise<SendAsAlias[]> {
  const result = await getJSON<SendAsAliasesResponse>("/api/mail/send-as");
  return result.aliases ?? [];
}

export async function createSendAsAlias(email: string, displayName: string): Promise<CreateSendAsAliasResult> {
  return postJSON<CreateSendAsAliasResult>("/api/mail/send-as", { email, displayName });
}

export async function deleteSendAsAlias(id: string): Promise<{ ok: boolean }> {
  return deleteJSON<{ ok: boolean }>(`/api/mail/send-as/${encodeURIComponent(id)}`);
}
