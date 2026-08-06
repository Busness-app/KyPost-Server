self.addEventListener("pushsubscriptionchange", (event) => {
  event.waitUntil(
    (async () => {
      const keyResponse = await fetch("/api/notifications/vapid-public-key", { credentials: "include" });
      if (!keyResponse.ok) {
        throw new Error("failed to load vapid public key");
      }

      const keyData = await keyResponse.json();
      const publicKey = typeof keyData.publicKey === "string" ? keyData.publicKey : "";
      if (!publicKey) {
        throw new Error("missing vapid public key");
      }

      const normalized = publicKey.replace(/-/g, "+").replace(/_/g, "/");
      const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
      const raw = atob(padded);
      const applicationServerKey = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i += 1) {
        applicationServerKey[i] = raw.charCodeAt(i);
      }

      const subscription = await self.registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey
      });

      // A service worker cannot read document.cookie, so the double-submit
      // X-CSRF-Token header has to come from this dedicated endpoint instead
      // of the csrf_token cookie the page JS uses. Without it the POST below
      // is rejected (403) and push silently dies on subscription rotation.
      const csrfResponse = await fetch("/api/auth/csrf", { credentials: "include" });
      if (!csrfResponse.ok) {
        throw new Error("failed to load csrf token");
      }
      const csrfData = await csrfResponse.json();
      const csrfToken = typeof csrfData.csrfToken === "string" ? csrfData.csrfToken : "";
      if (!csrfToken) {
        throw new Error("missing csrf token");
      }

      const response = await fetch("/api/notifications/subscriptions", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify(subscription.toJSON())
      });

      if (!response.ok) {
        throw new Error(`subscription refresh failed with status ${response.status}`);
      }
    })()
  );
});

self.addEventListener("push", (event) => {
  let payload = {};
  if (event.data) {
    try {
      payload = event.data.json();
    } catch {
      payload = { body: event.data.text() };
    }
  }

  const title = typeof payload.title === "string" && payload.title.trim() ? payload.title : "KyPost";
  const body = typeof payload.body === "string" ? payload.body : "You have a new notification.";
  // Notification settings are a tab on Configuration. A push that names no url
  // is a push with nowhere better to go, so it lands there.
  const url = typeof payload.url === "string" && payload.url.trim() ? payload.url : "/config?tab=notifications";
  const tag = typeof payload.tag === "string" && payload.tag.trim() ? payload.tag : undefined;

  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      tag,
      data: { url },
      badge: "/pwa-icon.svg",
      icon: "/pwa-icon.svg"
    })
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = (event.notification && event.notification.data && event.notification.data.url) || "/config?tab=notifications";

  event.waitUntil(
    clients.matchAll({ type: "window", includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if ("focus" in client) {
          client.navigate(url);
          return client.focus();
        }
      }
      if (clients.openWindow) {
        return clients.openWindow(url);
      }
      return undefined;
    })
  );
});
