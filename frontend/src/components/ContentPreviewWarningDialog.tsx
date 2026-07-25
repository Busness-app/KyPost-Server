import { useEffect, useRef, useState } from "react";
import { useDialogOpen } from "../hooks/useDialogOpen";

const CONFIRM_DELAY_SECONDS = 3;

type Props = {
  open: boolean;
  onConfirm: () => void;
  onCancel: () => void;
};

/**
 * Warns what turning on notification previews costs before it is turned on.
 *
 * "Understood" stays disabled for a few seconds so the warning is read rather
 * than clicked through — the choice leaks sender and subject to third parties
 * and cannot be un-leaked afterwards.
 */
export function ContentPreviewWarningDialog({ open, onConfirm, onCancel }: Props) {
  const dialogRef = useRef<HTMLDialogElement | null>(null);
  const [secondsLeft, setSecondsLeft] = useState(CONFIRM_DELAY_SECONDS);

  useDialogOpen(dialogRef, open);

  useEffect(() => {
    if (!open) {
      setSecondsLeft(CONFIRM_DELAY_SECONDS);
      return;
    }
    setSecondsLeft(CONFIRM_DELAY_SECONDS);
    const timer = window.setInterval(() => {
      setSecondsLeft((prev) => {
        if (prev <= 1) {
          window.clearInterval(timer);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => window.clearInterval(timer);
  }, [open]);

  const locked = secondsLeft > 0;

  return (
    <dialog
      ref={dialogRef}
      className="rules-help-backdrop"
      aria-label="Notification preview warning"
      onCancel={(event) => {
        event.preventDefault();
        onCancel();
      }}
      onClick={(event) => {
        if (event.target === dialogRef.current) {
          onCancel();
        }
      }}
    >
      <div className="rules-help-window" style={{ width: "min(560px, 94vw)" }} onClick={(event) => event.stopPropagation()}>
        <div className="rules-help-head">
          <h3>Read this before turning it on</h3>
        </div>
        <div className="rules-help-body">
          <p>
            Mobile push is not delivered by this server. It travels through the push relay and then Google
            (Android) or Apple (iOS), and the sender and subject are readable at every hop. Turning this on tells
            those companies who emails you and what about &mdash; which PGP encryption does not prevent, because the
            Subject header is not encrypted. Switch the mobile delivery mode to <strong>App Pull</strong> to get
            previews without involving them. Browser notifications are encrypted to your browser either way.
          </p>
          <div style={{ display: "flex", gap: 8, marginTop: 16, justifyContent: "flex-end" }}>
            <button type="button" className="contacts-action" onClick={onCancel}>
              Cancel
            </button>
            <button type="button" onClick={onConfirm} disabled={locked}>
              {locked ? `Understood (${secondsLeft})` : "Understood"}
            </button>
          </div>
        </div>
      </div>
    </dialog>
  );
}
