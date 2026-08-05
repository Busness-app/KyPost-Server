import { deviceAppVersion, deviceTransport, formatDeviceTime, maskToken } from "./format";
import type { DeviceRow } from "./deviceJoin";

/**
 * One row per paired device, carrying its identity and what it may do.
 *
 * Presentational only — every binding arrives as a prop. The inventory and the
 * approver flags used to be two lists on two pages answering questions about the
 * same hardware; `deviceJoin.ts` reconciles them and this renders the result.
 */

export type DeviceListProps = {
  rows: DeviceRow[];
  /** True once the account has push approval switched on at all. */
  pushEnabled: boolean;
  /**
   * Whether `GET /api/mfa/status` has actually answered.
   *
   * Required, because "the status says this device cannot approve" and "the
   * status never loaded" produce identical-looking rows and must not produce
   * identical copy: telling someone to update an app and pair again, because a
   * fetch failed, sends them to redo work that was never broken.
   */
  approvalsKnown: boolean;
  busy: boolean;
  removingId: string;
  onToggleApprover: (deviceId: string, approver: boolean) => void;
  onRemove: (deviceId: string) => void;
};

export function DeviceList({
  rows,
  pushEnabled,
  approvalsKnown,
  busy,
  removingId,
  onToggleApprover,
  onRemove
}: DeviceListProps) {
  if (rows.length === 0) {
    return (
      <p className="sec-muted">
        No devices are paired to this account yet. Use <strong>Pair a new device</strong> above to add one.
      </p>
    );
  }

  return (
    <ul className="sec-devices sec-device-rows">
      {rows.map((row) => {
        const transport = row.device ? deviceTransport(row.device) : null;
        const version = row.device ? deviceAppVersion(row.device) : "";
        // A device the inventory does not know cannot be removed through the
        // inventory endpoint, and there is nothing honest to say about its
        // transport or last-seen time either.
        const removable = Boolean(row.device);
        return (
          <li key={row.deviceId} className="sec-device-row">
            <div className="sec-device-identity">
              <span className="sec-device-name-row">
                <span className="sec-device-name">{row.name}</span>
                {transport ? (
                  <span
                    className={`sec-transport-badge sec-transport-badge-${transport.key}`}
                    title="Current notification delivery method for this device"
                  >
                    {transport.label}
                  </span>
                ) : null}
              </span>
              {row.device ? (
                <>
                  {version ? <span className="sec-device-detail">{version}</span> : null}
                  <span className="sec-device-detail">
                    Updated: {formatDeviceTime(row.device.updatedAt || row.device.registeredAt)}
                  </span>
                  <span className="sec-device-detail">{maskToken(row.device.pushToken || "")}</span>
                  {row.device.userAgent?.trim() ? (
                    <span className="sec-device-detail">UA: {row.device.userAgent.trim()}</span>
                  ) : null}
                </>
              ) : null}
              {row.missingFromInventory ? (
                <p className="sec-verdict sec-verdict-risk">
                  This device can approve sign-ins but is no longer in your paired-device list. Turn its
                  approval off here.
                </p>
              ) : null}
            </div>

            <div className="sec-device-capabilities">
              <label className="sec-check">
                <input
                  type="checkbox"
                  checked={row.approver && row.canApprove}
                  disabled={
                    busy || !approvalsKnown || !pushEnabled || !row.canApprove || row.approvalUnavailable
                  }
                  onChange={(e) => onToggleApprover(row.deviceId, e.target.checked)}
                />
                <span>Can approve sign-ins</span>
              </label>
              {/* Nothing to say per row for the two account-wide cases: the
                  status not loading is reported once at the card level, and the
                  control that turns push approval on sits directly above this
                  list. Repeating either on every row is noise that buries the
                  per-device reasons that are actually specific. */}
              {!approvalsKnown || !pushEnabled ? null : row.approvalUnavailable ? (
                <p className="sec-muted">
                  This device has not offered itself as an approver. Update its app and pair again.
                </p>
              ) : !row.canApprove ? (
                <p className="sec-muted">
                  {row.cannotApproveReason ||
                    "This device's push delivery cannot carry sign-in approvals. Mail notifications still work."}
                </p>
              ) : null}
            </div>

            {removable ? (
              <div className="sec-device-actions">
                <button
                  type="button"
                  className="sec-action-danger"
                  onClick={() => onRemove(row.deviceId)}
                  disabled={busy || removingId === row.deviceId}
                >
                  {removingId === row.deviceId ? "Removing..." : "Remove"}
                </button>
              </div>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}
