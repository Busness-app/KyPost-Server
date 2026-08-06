import { Appearance } from "../../settings/sections/Appearance";

export function AppearancePanel() {
  return (
    <section className="panel">
      <div className="config-header">
        <h2>Appearance</h2>
        <p>Theme is stored in this browser only.</p>
      </div>
      <div id="theme"><Appearance /></div>
    </section>
  );
}
