# GovernX Frontend — Weeks 1 & 2

React + TypeScript dashboard starter for the GovernX NIST CSF 2.0 compliance project.

## Included

### Week 1
- `Dashboard.tsx`: dashboard overview and six NIST functions
- `NistPillar.tsx`: reusable NIST function cards
- `ComplianceCard.tsx`: category maturity and gap cards
- `Header.tsx`, `Footer.tsx`, `Sidebar.tsx`: shared UI components
- `nist.css`: responsive styling, function colors, and print styles

### Week 2
- `MaturityScore.tsx`: function maturity gauge charts
- `RiskVisualization.tsx`: financial risk bar chart
- `GapAnalysis.tsx`: prioritized sample gaps
- `Reports.tsx`: report summary with CSV export and print action
- `charts/`: reserved for splitting chart types into dedicated components; the current starter composes its charts in reusable visualization components.

## Run locally

Requires Node.js 18 or newer.

```bash
npm install
npm run dev
```

Open the local URL shown by Vite.

## Build

```bash
npm run build
```

## Notes

- This project uses illustrative mock data in `src/data/mockDashboard.ts`.
- No live backend API is connected yet. `src/types/dashboard.ts` contains the frontend data types.
- The report page exports CSV and uses the browser print dialog. PDF generation and live API integration are not implemented.
- The PDF workplan specifies the component deliverables, but does not prescribe exact filenames for separate chart components, API services, or data types.
