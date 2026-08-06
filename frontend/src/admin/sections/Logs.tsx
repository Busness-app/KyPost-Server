import { useEffect, useRef, useState, useCallback } from "react";
import { getJSON } from "../../api/client";

const LINE_OPTIONS = [50, 100, 200, 500, 1000];
const REFRESH_OPTIONS = [
  { label: "Off", value: 0 },
  { label: "5s", value: 5 },
  { label: "10s", value: 10 },
  { label: "30s", value: 30 },
];
const HIDDEN_LOG_FILES = ["classifier.log"];

// Files that should always appear first, in this order.
const PINNED_LOG_ORDER = ["app.log", "classifier.log", "classifier-error.log"];


function sortLogFiles(files: string[]): string[] {
  const pinned = PINNED_LOG_ORDER.filter((f) => files.includes(f));
  const rest = files.filter((f) => !PINNED_LOG_ORDER.includes(f)).sort();
  return [...pinned, ...rest];
}

function tabLabel(filename: string): string {
  if (filename === "classifier.log") return "Classifier";
  return filename.replace(/\.log$/, "").replace(/[._-]/g, " ");
}

function levelClass(line: string): string {
  const l = line.toLowerCase();
  if (l.includes(" error") || l.includes("[error]") || l.includes("level=error")) return "log-error";
  if (l.includes(" warn")  || l.includes("[warn]")  || l.includes("level=warn"))  return "log-warn";
  if (l.includes(" info")  || l.includes("[info]")  || l.includes("level=info"))  return "log-info";
  if (l.includes(" debug") || l.includes("[debug]") || l.includes("level=debug")) return "log-debug";
  return "";
}


function LogViewer({ filename }: { filename: string }) {
  const [lines, setLines]                     = useState<string[]>([]);
  const [lineCount, setLineCount]             = useState(200);
  const [refreshInterval, setRefreshInterval] = useState(10);
  const [filter, setFilter]                   = useState("");
  const [autoScroll, setAutoScroll]           = useState(true);
  const [loading, setLoading]                 = useState(false);
  const [lastFetched, setLastFetched]         = useState<Date | null>(null);
  const [error, setError]                     = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  const fetchLogs = useCallback(() => {
    setLoading(true);
    getJSON<{ lines: string[] }>(`/api/logs?file=${encodeURIComponent(filename)}&lines=${lineCount}`)
      .then((data) => { setLines(data.lines ?? []); setLastFetched(new Date()); setError(null); })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [filename, lineCount]);

  useEffect(() => { fetchLogs(); }, [fetchLogs]);

  useEffect(() => {
    if (refreshInterval === 0) return;
    const id = setInterval(fetchLogs, refreshInterval * 1000);
    return () => clearInterval(id);
  }, [fetchLogs, refreshInterval]);

  useEffect(() => {
    if (autoScroll && bottomRef.current) bottomRef.current.scrollIntoView({ behavior: "smooth" });
  }, [lines, autoScroll]);

  const filtered = filter.trim()
    ? lines.filter((l) => l.toLowerCase().includes(filter.toLowerCase()))
    : lines;

  return (
    <>
      <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", flexWrap: "wrap", marginBottom: "0.6rem" }}>
        <input type="text" placeholder="Filter..." value={filter} onChange={(e) => setFilter(e.target.value)}
          style={{ background: "var(--bg)", border: "1px solid var(--line)", borderRadius: 4, color: "var(--ink)", padding: "0.3rem 0.6rem", fontFamily: "var(--mono)", fontSize: "0.8rem", width: 180 }} />
        <label style={{ fontSize: "0.8rem", opacity: 0.7 }}>Lines:</label>
        <select value={lineCount} onChange={(e) => setLineCount(Number(e.target.value))}
          style={{ background: "var(--bg)", border: "1px solid var(--line)", borderRadius: 4, color: "var(--ink)", padding: "0.3rem 0.5rem", fontSize: "0.8rem" }}>
          {LINE_OPTIONS.map((n) => <option key={n} value={n}>{n}</option>)}
        </select>
        <label style={{ fontSize: "0.8rem", opacity: 0.7 }}>Refresh:</label>
        <select value={refreshInterval} onChange={(e) => setRefreshInterval(Number(e.target.value))}
          style={{ background: "var(--bg)", border: "1px solid var(--line)", borderRadius: 4, color: "var(--ink)", padding: "0.3rem 0.5rem", fontSize: "0.8rem" }}>
          {REFRESH_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        <button onClick={fetchLogs} disabled={loading}
          style={{ background: "var(--accent-soft)", border: "1px solid var(--accent)", borderRadius: 4, color: "var(--ink)", padding: "0.3rem 0.8rem", cursor: loading ? "wait" : "pointer", fontSize: "0.8rem" }}>
          {loading ? "..." : "Refresh"}
        </button>
        <label style={{ marginLeft: "auto", display: "flex", gap: "0.4rem", alignItems: "center", cursor: "pointer", fontSize: "0.8rem" }}>
          <input type="checkbox" checked={autoScroll} onChange={(e) => setAutoScroll(e.target.checked)} />
          Auto-scroll
        </label>
      </div>

      <div style={{ display: "flex", gap: "1rem", marginBottom: "0.4rem", fontSize: "0.72rem", opacity: 0.55 }}>
        <span>{filtered.length} line{filtered.length !== 1 ? "s" : ""}{filter ? " (filtered)" : ""}</span>
        {lastFetched && <span>Updated {lastFetched.toLocaleTimeString()}</span>}
        {refreshInterval > 0 && <span>Auto-refresh {refreshInterval}s</span>}
      </div>

      {error && (
        <div style={{ color: "var(--ink-strong)", background: "var(--error-soft)", border: "1px solid var(--line)", borderRadius: 4, padding: "0.5rem 0.75rem", marginBottom: "0.5rem", fontSize: "0.85rem" }}>
          {error}
        </div>
      )}

      <pre style={{ background: "var(--bg)", border: "1px solid var(--line)", borderRadius: 6, padding: "0.75rem 1rem", overflowY: "auto", maxHeight: "60vh", margin: 0, fontSize: "0.78rem", fontFamily: "var(--mono)", lineHeight: 1.6 }}>
        {filtered.length === 0
          ? <span style={{ opacity: 0.4 }}>{loading ? "Loading..." : filter ? "No lines match filter." : "No log output yet."}</span>
          : filtered.map((line, i) => (
              <div key={i} className={"log-line " + levelClass(line)} style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{line}</div>
            ))
        }
        <div ref={bottomRef} />
      </pre>
    </>
  );
}

export function Logs() {
  const [files, setFiles]   = useState<string[]>([]);
  const [active, setActive] = useState<string>("app.log");

  useEffect(() => {
    getJSON<{ files: string[] }>("/api/logs/list")
      .then((d) => {
        const list = sortLogFiles(
          (d.files ?? []).filter((name) => !HIDDEN_LOG_FILES.includes(name))
        );
        setFiles(list);
        if (list.length > 0 && !list.includes(active)) setActive(list[0]);
      })
      .catch(() => {});
  }, []);

  return (
    <>

      <div style={{ display: "flex", gap: 0, flexWrap: "wrap", borderBottom: "1px solid var(--line)", marginBottom: "1rem" }}>
        {files.map((f) => (
          <button key={f} onClick={() => setActive(f)}
            style={{
              background: active === f ? "var(--panel)" : "transparent",
              border: "1px solid var(--line)",
              borderBottom: active === f ? "1px solid var(--panel)" : "1px solid var(--line)",
              borderRadius: "4px 4px 0 0",
              marginBottom: active === f ? -1 : 0,
              color: active === f ? "var(--accent)" : "var(--ink)",
              padding: "0.35rem 0.9rem",
              cursor: "pointer",
              fontSize: "0.8rem",
              fontFamily: "var(--mono)",
              textTransform: "capitalize",
              whiteSpace: "nowrap",
            }}>
            {tabLabel(f)}
          </button>
        ))}
        {files.length === 0 && <span style={{ padding: "0.35rem 0.5rem", fontSize: "0.8rem", opacity: 0.4 }}>Loading...</span>}
      </div>

      {active && <LogViewer key={active} filename={active} />}
    </>
  );
}
