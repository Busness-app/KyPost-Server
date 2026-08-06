// Shared across SecurityPage and its section components — split out so pulling
// in the MFA status shape does not require importing SecurityPage itself.

import type { ApproverDevice } from "./deviceJoin";

export type MfaStatus = {
  totpEnabled: boolean;
  recoveryCodesRemaining: number;
  pushMfaEnabled: boolean;
  approverDevices: ApproverDevice[];
};
