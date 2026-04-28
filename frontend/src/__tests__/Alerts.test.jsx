import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';

vi.mock('../components/Skeleton', () => ({
  AlertsSkeleton: () => <div data-testid="skeleton">Loading...</div>,
}));

vi.mock('../components/PlaybookViewer', () => ({
  default: () => null,
}));

vi.mock('../utils/export', () => ({
  exportToCSV: vi.fn(),
  exportToJSON: vi.fn(),
}));

import Alerts from '../pages/Alerts';

describe('Alerts', () => {
  it('renders the empty state when no alerts provided', async () => {
    render(<Alerts alerts={[]} incidents={[]} />);
    await vi.waitFor(() => {
      expect(screen.getByText('Aucune alerte')).toBeInTheDocument();
    });
  });

  it('renders alerts when data is provided', async () => {
    const alerts = [
      {
        alert_id: 'a1',
        severity: 'critical',
        rule_name: 'Suspicious PowerShell',
        tactic: 'Execution',
        technique_id: 'T1059.001',
        technique_name: 'PowerShell',
        affected_host: 'WS01',
        timestamp: '2026-04-28T14:00:00Z',
        description: 'Test alert',
      },
    ];
    render(<Alerts alerts={alerts} incidents={[]} />);
    await vi.waitFor(() => {
      expect(screen.getByText('Security Alerts')).toBeInTheDocument();
      expect(screen.getByText('Suspicious PowerShell')).toBeInTheDocument();
    });
  });
});
