// Display formatting for the read view. Pure — no React, no I/O — so it is
// unit-testable without rendering the page.

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatTimestamp(value: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

export function formatInboxListTime(value: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;

  const now = new Date();
  const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const emailStart = new Date(date.getFullYear(), date.getMonth(), date.getDate());
  const diffDays = Math.floor((todayStart.getTime() - emailStart.getTime()) / 86_400_000);

  if (diffDays === 0) {
    return date.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  }
  if (diffDays === 1) {
    return "Yesterday";
  }
  if (diffDays > 1 && diffDays <= 6) {
    return date.toLocaleDateString([], { weekday: "long" });
  }
  return date.toLocaleDateString();
}

export function formatUpdatedLabel(lastLoadedAt: Date | null, now: number): string {
  if (!lastLoadedAt) return "Updated Never";
  const elapsedMs = now - lastLoadedAt.getTime();
  if (elapsedMs < 3 * 60 * 1000) {
    return "Updated Just Now";
  }
  return `Updated ${lastLoadedAt.toLocaleTimeString([], {
    hour: "numeric",
    minute: "2-digit"
  })}`;
}

