import { useEffect, useState } from "react";
import { getJSON } from "../../api/client";
import { usePagination } from "../../hooks/usePagination";
import { PageTabs } from "../../components/PageTabs";

type Decision = {
  messageId: string;
  sender: string;
  sentTo?: string;
  subject: string;
  label: string;
  status: string;
  detail: string;
  atUtc: string;
};

/**
 * The account's own classification audit log.
 *
 * Per-user, like the tuning that produced it. This is where "labels are a hint,
 * not a security boundary" is checkable: every decision the model made is
 * recorded, so a user can see what actually happened to their mail.
 *
 * Loads on mount rather than on a tab click — the panel only mounts this
 * component while its tab is the active one.
 */
export function Decisions() {
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [decisionsLoaded, setDecisionsLoaded] = useState(false);
  const [decisionsError, setDecisionsError] = useState("");

  useEffect(() => {
    getJSON<Decision[]>("/api/decisions?limit=500")
      .then((data) => {
        setDecisions(data ?? []);
        setDecisionsLoaded(true);
        setDecisionsError("");
      })
      .catch(() => {
        setDecisionsError("Failed to load decisions.");
        setDecisionsLoaded(true);
      });
  }, []);

  const { currentPage, setCurrentPage, totalPages, pageItems: pageDecisions } = usePagination(decisions, 20);

  return (
    <div>
      <h3>Classification Decisions</h3>
      <p>Audit log of AI classification decisions for message labeling.</p>

      {decisionsError ? (
        <p className="notice notice-error">{decisionsError}</p>
      ) : decisionsLoaded ? (
        <>
          {decisions.length === 0 ? (
            <p className="config-muted">No classification decisions recorded yet.</p>
          ) : (
            <>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid var(--border-color)" }}>
                      <th style={{ textAlign: "left", padding: "8px" }}>Time</th>
                      <th style={{ textAlign: "left", padding: "8px" }}>Sender</th>
                      <th style={{ textAlign: "left", padding: "8px" }}>Subject</th>
                      <th style={{ textAlign: "left", padding: "8px" }}>Label</th>
                      <th style={{ textAlign: "left", padding: "8px" }}>Status</th>
                      <th style={{ textAlign: "left", padding: "8px" }}>Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pageDecisions.map((decision) => (
                      <tr key={`${decision.messageId}-${decision.atUtc}`} style={{ borderBottom: "1px solid var(--border-color)" }}>
                        <td style={{ padding: "8px", fontSize: "0.9em" }}>{new Date(decision.atUtc).toLocaleString()}</td>
                        <td style={{ padding: "8px", fontSize: "0.9em" }}>{decision.sender}</td>
                        <td style={{ padding: "8px", fontSize: "0.9em" }}>{decision.subject}</td>
                        <td style={{ padding: "8px", fontSize: "0.9em" }}>{decision.label}</td>
                        <td style={{ padding: "8px", fontSize: "0.9em" }}>{decision.status}</td>
                        <td style={{ padding: "8px", fontSize: "0.85em" }}>{decision.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <PageTabs
                totalPages={totalPages}
                currentPage={currentPage}
                onSelect={setCurrentPage}
                classPrefix="tuning"
                ariaLabel="Decision pages"
              />
            </>
          )}
        </>
      ) : (
        <p className="config-muted">Loading decisions...</p>
      )}
    </div>
  );
}
