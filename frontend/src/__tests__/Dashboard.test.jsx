import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';

vi.mock('recharts', () => ({
  ResponsiveContainer: ({ children }) => <div>{children}</div>,
  BarChart: ({ children }) => <div>{children}</div>,
  Bar: () => null,
  XAxis: () => null,
  YAxis: () => null,
  Tooltip: () => null,
  PieChart: ({ children }) => <div>{children}</div>,
  Pie: () => null,
  Cell: () => null,
}));

vi.mock('../components/Skeleton', () => ({
  DashboardSkeleton: () => <div data-testid="skeleton">Loading...</div>,
}));

import Dashboard from '../pages/Dashboard';

const i18n = { t: (k) => k, lang: 'en' };

describe('Dashboard', () => {
  it('renders the empty state when no result is provided', async () => {
    render(<Dashboard result={null} environment={null} i18n={i18n} />);
    await vi.waitFor(() => {
      expect(screen.getByText('dashboard.empty.title')).toBeInTheDocument();
    });
  });

  it('renders without crashing when result is provided', async () => {
    const mockResult = {
      scores: {
        overall_score: 75,
        detection_score: 80,
        coverage_score: 60,
        visibility_score: 70,
        response_score: 65,
        risk_level: 'Medium',
        maturity_level: 'Level 3',
      },
      alerts: [
        { severity: 'high', rule_name: 'Test Rule', tactic: 'Execution', technique_id: 'T1059', affected_host: 'DC01' },
      ],
      incidents: [],
      logs_statistics: { by_severity: { high: 3 }, by_type: { sysmon: 5 } },
      scenario: { name: 'APT29', threat_actor: { name: 'APT29', origin: 'Russia' }, phases: [] },
    };
    render(<Dashboard result={mockResult} environment={null} i18n={i18n} />);
    await vi.waitFor(() => {
      expect(screen.getByText('dashboard.title')).toBeInTheDocument();
    });
  });
});
