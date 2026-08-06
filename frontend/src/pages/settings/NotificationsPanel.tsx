import { NotificationPrefs } from "../../settings/sections/NotificationPrefs";

export function NotificationsPanel() {
  return (
    <section className="panel">
      <div className="config-header">
        <h2>Notifications</h2>
        <p>How and when this device tells you about new mail.</p>
      </div>
      <div id="notification-prefs"><NotificationPrefs /></div>
    </section>
  );
}
