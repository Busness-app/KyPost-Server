import { useEffect, useState } from "react";
import { toErrorMessage } from "../../api/client";
import {
  listWKDDomains,
  claimWKDDomain,
  verifyWKDDomain,
  deleteWKDDomain,
  wkdDomainRecord,
  type WKDDomainClaim
} from "../../api/pgp";

export function WkdDomains() {
  const [wkdDomains, setWkdDomains] = useState<WKDDomainClaim[]>([]);
  const [wkdLoading, setWkdLoading] = useState(true);
  const [wkdBusy, setWkdBusy] = useState(false);
  const [wkdStatus, setWkdStatus] = useState("");
  const [wkdNewDomain, setWkdNewDomain] = useState("");

  async function refreshWKDDomains() {
    try {
      const res = await listWKDDomains();
      setWkdDomains(res.domains);
    } catch (e) {
      setWkdStatus(`Failed to load domains: ${toErrorMessage(e, "unknown error")}`);
    } finally {
      setWkdLoading(false);
    }
  }

  useEffect(() => {
    void refreshWKDDomains();
  }, []);

  function copyWKDText(text: string) {
    void navigator.clipboard?.writeText(text);
  }

  async function addWKDDomain() {
    const domain = wkdNewDomain.trim().toLowerCase();
    if (!domain) return;
    // Re-claiming an already-listed domain mints a fresh token and resets
    // Verified to false server-side (wkdpublish.Store.Create), instantly
    // unpublishing every user currently served under it until it's
    // re-verified — the same blast radius Remove already warns about, so
    // Add needs the same confirmation for the same case.
    if (
      wkdDomains.some((d) => d.domain === domain) &&
      !window.confirm(
        `${domain} is already claimed. Re-adding it mints a new verification token and immediately unpublishes every user's key at this domain until it's re-verified. Continue?`
      )
    ) {
      return;
    }
    setWkdBusy(true);
    setWkdStatus("");
    try {
      await claimWKDDomain(domain);
      setWkdNewDomain("");
      await refreshWKDDomains();
    } catch (error: unknown) {
      setWkdStatus(`Failed to add domain: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setWkdBusy(false);
    }
  }

  async function runWKDDomainVerify(domain: string) {
    setWkdBusy(true);
    setWkdStatus("");
    try {
      const result = await verifyWKDDomain(domain);
      await refreshWKDDomains();
      setWkdStatus(
        result.verified
          ? `${domain} verified. Also point openpgpkey.${domain} at this server (DNS or a tunnel) so key lookups can actually resolve.`
          : `${domain} is not verified yet — make sure the DNS TXT record is in place and has propagated, then try again.`
      );
    } catch (error: unknown) {
      setWkdStatus(`Failed to verify domain: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setWkdBusy(false);
    }
  }

  async function removeWKDDomain(domain: string) {
    if (!window.confirm(`Stop publishing keys for ${domain}? Users will no longer be discoverable via WKD at this domain.`)) {
      return;
    }
    setWkdBusy(true);
    setWkdStatus("");
    try {
      await deleteWKDDomain(domain);
      await refreshWKDDomains();
    } catch (error: unknown) {
      setWkdStatus(`Failed to remove domain: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setWkdBusy(false);
    }
  }

  return (
    <div className="config-card" role="tabpanel">
      <h3>WKD key publishing (domains)</h3>
      <p className="config-muted">
        Web Key Directory (WKD) lets other mail clients look up a user's PGP key automatically, without it
        being shared directly. Verifying a domain here proves this instance controls its DNS, and lets any
        user on that domain publish their key there (each user opts in individually on their Security page).
      </p>

      {wkdLoading ? (
        <p className="config-muted">Loading...</p>
      ) : wkdDomains.length > 0 ? (
        <div className="config-status-card">
          {wkdDomains.map((d) => {
            const record = wkdDomainRecord(d);
            return (
              <div key={d.domain} style={{ padding: "10px 0" }}>
                <div className="security-card-head">
                  <span>{d.domain}</span>
                  <span className={`security-badge ${d.verified ? "security-badge-on" : "security-badge-off"}`}>
                    <span className="security-dot" aria-hidden="true" />
                    {d.verified ? "verified" : "unverified"}
                  </span>
                </div>
                {d.verified ? (
                  <p className="config-muted">
                    Also make sure <code>openpgpkey.{d.domain}</code> points at this server (DNS or a
                    tunnel) so key lookups actually resolve.
                  </p>
                ) : (
                  <>
                    <p className="config-muted">Add this DNS TXT record to prove control of {d.domain}:</p>
                    <p className="config-muted">
                      Name: <code>{record.name}</code>{" "}
                      <button type="button" onClick={() => copyWKDText(record.name)}>
                        Copy
                      </button>
                    </p>
                    <p className="config-muted">
                      Value: <code>{record.value}</code>{" "}
                      <button type="button" onClick={() => copyWKDText(record.value)}>
                        Copy
                      </button>
                    </p>
                  </>
                )}
                <div className="security-actions">
                  {!d.verified ? (
                    <button type="button" disabled={wkdBusy} onClick={() => void runWKDDomainVerify(d.domain)}>
                      Verify
                    </button>
                  ) : null}
                  <button
                    type="button"
                    className="security-action-danger"
                    disabled={wkdBusy}
                    onClick={() => void removeWKDDomain(d.domain)}
                  >
                    Remove
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <p className="config-muted">No domains published yet.</p>
      )}

      <div className="config-grid config-grid-two">
        <label>
          <div>Domain to publish keys for</div>
          <input
            value={wkdNewDomain}
            onChange={(event) => setWkdNewDomain(event.target.value)}
            placeholder="example.com"
          />
        </label>
      </div>
      <div className="config-actions">
        <button type="button" onClick={() => void addWKDDomain()} disabled={wkdBusy || wkdNewDomain.trim() === ""}>
          {wkdBusy ? "Working..." : "Add domain"}
        </button>
      </div>
      {wkdStatus ? <p className="config-muted">{wkdStatus}</p> : null}
    </div>
  );
}
