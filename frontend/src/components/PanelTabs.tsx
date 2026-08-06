import { type ReactNode } from "react";
import { useSearchParams } from "react-router";

export type PanelTab = {
  /** Stable id, used as the `?tab=` value — retired routes redirect straight to one. */
  id: string;
  label: string;
  body: ReactNode;
};

/** Falls back to the first tab for anything unrecognised, so a bad link still renders. */
export function resolvePanelTab(raw: string | null, tabs: ReadonlyArray<{ id: string }>): string {
  const value = (raw ?? "").trim();
  return tabs.some((tab) => tab.id === value) ? value : (tabs[0]?.id ?? "");
}

/**
 * The tab strip a panel uses once it holds more sections than fit one scroll.
 *
 * The active tab lives in the URL, matching Security: prose elsewhere can link
 * to a specific section, a reload keeps you where you were, and the retired
 * routes have somewhere exact to point.
 */
export function PanelTabs({ tabs, ariaLabel }: { tabs: ReadonlyArray<PanelTab>; ariaLabel: string }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const active = resolvePanelTab(searchParams.get("tab"), tabs);

  function select(id: string) {
    const next = new URLSearchParams(searchParams);
    next.set("tab", id);
    // Replace, not push: switching tabs is not navigation, and pushing would
    // mean Back walks every tab visited instead of leaving the panel.
    setSearchParams(next, { replace: true });
  }

  return (
    <>
      <div className="config-tabs" role="tablist" aria-label={ariaLabel}>
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={active === tab.id}
            className={`config-tab${active === tab.id ? " active" : ""}`}
            onClick={() => select(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>
      {tabs.map((tab) =>
        active === tab.id ? (
          <div key={tab.id} id={tab.id} role="tabpanel">
            {tab.body}
          </div>
        ) : null
      )}
    </>
  );
}
