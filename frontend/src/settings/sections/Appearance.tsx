import { THEME_OPTIONS, type ThemeName } from "../../theme";

type AppearanceProps = {
  // selectedTheme and saveTheme are also used by the (admin-only) Application
  // tab's embedded theme selector, so both stay owned by ConfigPage rather
  // than being duplicated here.
  selectedTheme: ThemeName;
  setSelectedTheme: (theme: ThemeName) => void;
  saveTheme: () => void;
};

export function Appearance({ selectedTheme, setSelectedTheme, saveTheme }: AppearanceProps) {
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
