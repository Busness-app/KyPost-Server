import { Appearance } from "../../settings/sections/Appearance";

export function AppearancePanel() {
  return (
    <section className="panel">
      <div className="config-header">
        <h2>Appearance</h2>
        <p>Pick a theme. It applies straight away and is remembered by this browser only.</p>
      </div>
      <div id="theme"><Appearance /></div>
    </section>
  );
}
