// Shared across SecurityPage and its section components — split out so pulling
// in the MFA status shape does not require importing SecurityPage itself.

import type { ApproverDevice } from "./deviceJoin";

export type MfaStatus = {
  totpEnabled: boolean;
  recoveryCodesRemaining: number;
  pushMfaEnabled: boolean;
  approverDevices: ApproverDevice[];
};

// The response from POST /api/mfa/totp/setup: a freshly minted secret the
// server will accept exactly once, for the enrollment that scans it. Shared
// with SecurityPage because it has to be lifted out of SignIn — see SignIn's
// props for why.
export type TotpSetup = {
  secret: string;
  otpauthUri: string;
};
