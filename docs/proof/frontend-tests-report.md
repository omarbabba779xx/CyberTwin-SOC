# Frontend Tests Report

**Commit**: `097cc9c`
**Date**: 2026-04-28
**Test runner**: Vitest 1.x + @testing-library/react 14.x
**Test files**: `frontend/src/__tests__/*.test.jsx`

## Scope

Documents the frontend automated test footprint introduced in v3.2:

- 4 page-level smoke tests (Login, Dashboard, Alerts, App router)
- Vitest configuration with jsdom environment
- React Testing Library + jest-dom assertions
- CI integration via `npm run test`

## Test files

| File | Coverage |
|---|---|
| `frontend/src/__tests__/App.test.jsx` | Top-level router + lazy boundaries |
| `frontend/src/__tests__/Login.test.jsx` | Login form rendering + interaction |
| `frontend/src/__tests__/Dashboard.test.jsx` | Dashboard component rendering |
| `frontend/src/__tests__/Alerts.test.jsx` | Alerts page rendering |
| `frontend/src/test-setup.js` | jest-dom matchers wiring |

## How to run locally

```bash
cd frontend
npm ci
npm run test          # one-shot (CI mode)
npm run test:watch    # watch mode
```

## Vitest configuration

```js
// frontend/vitest.config.js
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.js'],
  },
})
```

## CI integration

The "Frontend Build" job in `.github/workflows/ci.yml` runs:

```yaml
- run: cd frontend && npm ci
- run: cd frontend && npm run build
- run: cd frontend && npm run test -- --run
```

`npm run test` exits non-zero on any failed assertion, blocking the build.

## Smoke test methodology

Each page-level test:

1. Mounts the React component with `render(<Component />)`.
2. Asserts critical landmarks are present (form fields, headings, buttons).
3. Where applicable, simulates user interaction with `userEvent` and
   verifies the resulting DOM mutation.

Example (`Login.test.jsx`):

```jsx
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import Login from '../pages/Login'

test('renders username and password fields', () => {
  render(<Login />)
  expect(screen.getByLabelText(/username/i)).toBeInTheDocument()
  expect(screen.getByLabelText(/password/i)).toBeInTheDocument()
})

test('submit button is initially disabled when empty', () => {
  render(<Login />)
  const button = screen.getByRole('button', { name: /sign in/i })
  expect(button).toBeDisabled()
})
```

## Coverage scope (current)

| Page | Smoke test |
|---|---|
| `/login` | ✅ |
| `/dashboard` | ✅ |
| `/alerts` | ✅ |
| `/cases` | ❌ (planned) |
| `/coverage` | ❌ (planned) |
| `/admin/users` | ❌ (planned) |
| `/admin/connectors` | ❌ (planned) |
| `/executive` | ❌ (planned) |
| `/playbooks` | ❌ (planned) |

## Roadmap (v3.3+)

- **Playwright E2E**: full login → dashboard → alert triage flow against
  a running stack (`docker compose up -d` + `npx playwright test`).
- **Lighthouse CI**: performance / accessibility / SEO budgets per page,
  results uploaded as a CI artefact.
- **Bundle analyzer**: visualisation + size budgets per chunk
  (target < 300 KB gzipped per route).
- **Visual regression**: Percy / Chromatic snapshot per page.

## Limits

- The current smoke tests verify rendering, not data fetching.
  Integration tests against a mocked backend (msw) are on the roadmap.
- Coverage is < 100% of pages by design — the goal of v3.2 was to
  introduce the framework + cover the highest-traffic pages.
  Subsequent PRs will fill gaps page-by-page.
