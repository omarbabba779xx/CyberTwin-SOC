import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import Login from '../pages/Login';

vi.mock('../i18n', () => ({
  LANGUAGES: [
    { code: 'en', label: 'English', flag: '🇬🇧' },
  ],
}));

vi.mock('../utils/api', () => ({
  apiUrl: (path) => `http://localhost${path}`,
}));

const i18n = { t: (k) => k, lang: 'en' };

describe('Login', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  it('renders the login page', () => {
    render(<Login onLogin={vi.fn()} i18n={i18n} onLangChange={vi.fn()} />);
    expect(screen.getByText('CyberTwin')).toBeInTheDocument();
    expect(screen.getByText('SOC')).toBeInTheDocument();
  });

  it('has a username input field', () => {
    render(<Login onLogin={vi.fn()} i18n={i18n} onLangChange={vi.fn()} />);
    const input = screen.getByPlaceholderText('admin');
    expect(input).toBeInTheDocument();
    expect(input).toHaveAttribute('type', 'text');
  });

  it('has a password input field', () => {
    render(<Login onLogin={vi.fn()} i18n={i18n} onLangChange={vi.fn()} />);
    const input = screen.getByPlaceholderText('cybertwin2024');
    expect(input).toBeInTheDocument();
    expect(input).toHaveAttribute('type', 'password');
  });

  it('has a submit button', () => {
    render(<Login onLogin={vi.fn()} i18n={i18n} onLangChange={vi.fn()} />);
    const btn = screen.getByRole('button', { name: 'login.submit' });
    expect(btn).toBeInTheDocument();
    expect(btn).toHaveAttribute('type', 'submit');
  });
});
