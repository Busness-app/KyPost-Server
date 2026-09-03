// Toolbar glyphs. Inline SVG so they render the same on every OS; emoji did
// not, and clashed with the typeface. All 16px, stroke follows text colour.

const icon = (d: string) => () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d={d} />
  </svg>
);

export const TrashIcon = icon("M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14M10 11v6M14 11v6");
export const ArchiveIcon = icon("M3 4h18v5H3zM5 9v11h14V9M10 13h4");
export const WarningIcon = icon("M12 3 2 21h20L12 3zM12 10v5M12 18h.01");
export const CheckIcon = icon("M4 12l5 5L20 6");
export const PrintIcon = icon("M6 9V3h12v6M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2M6 14h12v7H6z");
