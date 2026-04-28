import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../i18n', () => ({
  createI18n: () => ({ t: (k) => k, lang: 'en' }),
  LANGUAGES: [{ code: 'en', label: 'English', flag: '🇬🇧' }],
  default: {},
}));

vi.mock('../utils/api', () => ({
  apiUrl: (path) => `http://localhost${path}`,
  authHeaders: () => ({}),
  API_BASE: '',
}));

vi.mock('../components/Sidebar', () => ({
  default: () => <nav data-testid="sidebar">Sidebar</nav>,
}));

vi.mock('../components/LiveSimulation', () => ({
  default: () => null,
}));

vi.mock('../components/SearchModal', () => ({
  default: () => null,
}));

vi.mock('../components/ShortcutsHelp', () => ({
  default: () => null,
}));

vi.mock('../hooks/useKeyboardShortcuts', () => ({
  default: () => {},
}));

vi.mock('../pages/Dashboard', () => ({
  default: () => <div data-testid="dashboard">Dashboard</div>,
}));

vi.mock('../pages/Login', () => ({
  default: ({ onLogin }) => (
    <div data-testid="login">
      <button onClick={onLogin}>Login</button>
    </div>
  ),
}));

import App from '../App';

describe('App', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({ json: () => Promise.resolve([]) })));
  });

  it('renders the login page when not authenticated', () => {
    render(<App />);
    expect(screen.getByTestId('login')).toBeInTheDocument();
  });

  it('renders the main layout when authenticated', () => {
    localStorage.setItem('cybertwin_token', 'test-token');
    render(<App />);
    expect(screen.getByTestId('sidebar')).toBeInTheDocument();
  });
});
