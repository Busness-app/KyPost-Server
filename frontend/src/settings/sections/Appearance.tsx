import { useState } from "react";
import { applyTheme, getStoredTheme, THEME_OPTIONS, themes, type ThemeName } from "../../theme";

/**
 * One swatch per theme, painted in that theme's own colours, applied on
 * click. A dropdown named fifteen themes and showed none of them.
 */
export function Appearance() {
  const [selectedTheme, setSelectedTheme] = useState<ThemeName>(getStoredTheme());

  function choose(theme: ThemeName) {
    setSelectedTheme(theme);
    applyTheme(theme);
  }

  return (
    <div className="theme-grid">
      {THEME_OPTIONS.map((theme) => {
        const c = themes[theme];
        return (
          <button
            key={theme}
            type="button"
            aria-pressed={theme === selectedTheme}
            className="theme-swatch"
            onClick={() => choose(theme)}
          >
            <span
              className="theme-swatch-preview"
              style={{ background: `linear-gradient(90deg, ${c.sidebarStart} 30%, ${c.bg} 30%)` }}
            >
              <i style={{ background: c.accent }} />
              <i style={{ background: c.inkStrong, opacity: 0.55 }} />
            </span>
            <span className="theme-swatch-name">{theme}</span>
          </button>
        );
      })}
    </div>
  );
}
