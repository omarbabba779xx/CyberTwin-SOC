# Frontend — Lighthouse CI Report

**Tool**: [Lighthouse CI](https://github.com/GoogleChrome/lighthouse-ci) v0.14.x
**Workflow step**: `frontend-build › Lighthouse CI` in `.github/workflows/ci.yml`
**Config**: [`frontend/.lighthouserc.json`](../../frontend/.lighthouserc.json)
**Commit**: `0ca70b7`

## Why Lighthouse?

Lighthouse audits four pillars on the production-built frontend:

| Pillar | What it measures | Why it matters for a SOC UI |
|---|---|---|
| Performance | LCP, FCP, TTI, TBT, CLS | analysts wait for the dashboard ~50× a day |
| Accessibility | ARIA, contrast, focus order | required for compliance with WCAG 2.1 AA |
| Best Practices | HTTPS, console errors, deprecated APIs | catches CSP / cookie / TLS regressions |
| SEO | meta, robots | not critical, but flags missing meta tags |

## Reproduction

```bash
cd frontend
npm ci
npm run build
npm install --no-save @lhci/cli@0.14.x
npx lhci autorun --config=.lighthouserc.json
```

The `frontend-build` CI job runs the same command on every push. The
job uploads the `.lighthouseci/` folder as a 14-day artefact named
`lighthouse-${SHA}`.

## Reference run (commit `0ca70b7`)

| Pillar | Score |
|---|---:|
| Performance | 0.82 |
| Accessibility | 0.95 |
| Best Practices | 0.96 |
| SEO | 0.91 |

Per-metric (Performance):

| Metric | Value | Budget |
|---|---:|---:|
| First Contentful Paint | 1.4 s | < 1.8 s ✅ |
| Largest Contentful Paint | 2.1 s | < 2.5 s ✅ |
| Total Blocking Time | 122 ms | < 200 ms ✅ |
| Cumulative Layout Shift | 0.04 | < 0.1 ✅ |
| Speed Index | 2.0 s | < 3.4 s ✅ |
| Time to Interactive | 2.4 s | < 3.8 s ✅ |

## Soft-fail today

The CI job currently sets `continue-on-error: true` on the Lighthouse
step. This is intentional: we run the audit on every push to detect
trends, but we do NOT fail the build on a single regression. The
`v3.3` plan turns Lighthouse into a hard gate after the perf budget
is locked (target: Performance ≥ 0.85, Accessibility ≥ 0.95).

## Known regressions to address

| Issue | Impact | Plan |
|---|---|---|
| `html2pdf.js` is ~982 KB gzipped | -8 pts on Performance | lazy-load on the Reports route only (planned `v3.3-perf`) |
| Recharts SVG re-renders on every websocket message | TBT spike | introduce a `useDeferredValue` debounce |
| No image preconnect for Mermaid renderer | LCP +200 ms | add `<link rel="preconnect">` for the chart fonts |

## Limitations

- Lighthouse runs against the bundled `dist/` served by `npx serve`,
  not the production nginx-unprivileged container. The container
  adds gzip + `Cache-Control` headers that improve real-user metrics
  by ~10 % vs the audit number.
- LH is a synthetic, single-machine audit; the real-user perf is
  tracked by an OTel `web-vitals` instrumentation in `App.jsx`
  (planned for `v3.3`).

## Next steps

- Pin Performance budget to ≥ 0.85 and remove `continue-on-error`.
- Add a Playwright performance trace alongside Lighthouse for visual
  diffs (e.g. dashboard mount time histograms).
