import { useState } from "react";
import { applyTheme, getStoredTheme, THEME_OPTIONS, type ThemeName } from "../../theme";

type AppearanceProps = {
  // The only genuine coupling to a caller: ConfigPage mirrors this into its
  // page-level status banner. Optional so a caller with no such banner can
  // still render this with zero props.
  onStatus?: (status: string) => void;
};

export function Appearance({ onStatus }: AppearanceProps = {}) {
  const [selectedTheme, setSelectedTheme] = useState<ThemeName>(getStoredTheme());

  function saveTheme() {
    applyTheme(selectedTheme);
    onStatus?.(`Theme set to ${selectedTheme}.`);
  }

  return (
    <div className="config-card">
      <h3>Appearance</h3>
      <p className="config-muted">Theme is stored in this browser only.</p>
      <div className="config-grid config-grid-two">
        <label>
          <div>Theme</div>
          <select value={selectedTheme} onChange={(event) => setSelectedTheme(event.target.value as ThemeName)}>
            {THEME_OPTIONS.map((theme) => (
              <option key={theme} value={theme}>
                {theme}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="config-actions">
        <button type="button" onClick={saveTheme}>Apply Theme</button>
      </div>
    </div>
  );
}
