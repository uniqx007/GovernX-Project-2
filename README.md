# GovernX Frontend — Person 4 (Weeks 3 & 4)

This folder contains an implementation-ready React + TypeScript frontend for Person 4's Week 3 and Week 4 work.

## Included deliverables

### Week 3
- `ExecutiveDashboard.tsx` — executive overview, financial risk, compliance summary and NIST function maturity.
- `GovernFunctionView.tsx` — Govern categories, policy/supply-chain governance view and related findings.
- `ReportGenerator.tsx` — downloadable executive PDF report.
- `RiskPortfolioView.tsx` — portfolio exposure trend, severity distribution and risk register.

### Week 4
- `UI_Polish.tsx` — shared visual-polish wrapper.
- `Accessibility.tsx` — semantic landmark wrapper.
- `ResponsiveDesign.tsx` — responsive layout wrapper; breakpoints are in `src/styles/nist.css`.
- `Performance_Optimization.tsx` — performance wrapper; route-level lazy loading can be added as the app grows.
- `UserGuide.md` — end-user guide.
- Shared styling, responsive breakpoints, reduced-motion support and print styles.

## Run locally

Requires Node.js 20 or later.

```bash
npm install
cp .env.example .env
npm run dev
```

Open the local URL printed by Vite (normally http://localhost:5173).

Create a production build:

```bash
npm run build
npm run preview
```

## Backend integration contract

Set `VITE_API_BASE_URL` in `.env` to the backend API base URL. The frontend requests:

`GET {VITE_API_BASE_URL}/dashboard/data`

The expected response shape is represented by `src/types.ts` and `src/data/mockData.ts`. Until the backend endpoint is available, the UI automatically falls back to illustrative mock data.

Example top-level response fields:
- `organization`
- `overallMaturity`
- `riskExposure`
- `complianceRate`
- `openGaps`
- `functions`
- `risks`
- `trend`

Coordinate the final API response schema with Persons 1, 2 and 3 before integration.

## Important data note

The included figures and findings are sample data for frontend development only. They are not real audit results, verified ALE calculations, or compliance assertions. Replace them with backend responses and validate all figures before board use.

## Suggested Git workflow

```bash
git checkout -b feature/person4-week3-week4-frontend
git add frontend/
git commit -m "Add Person 4 frontend deliverables for weeks 3 and 4"
git push -u origin feature/person4-week3-week4-frontend
```
