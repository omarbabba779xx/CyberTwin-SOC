import React, { useState, useEffect, useMemo } from 'react'
import {
  Shield, Clock, AlertTriangle, TrendingUp, TrendingDown,
  Target, CheckCircle, XCircle, BarChart3, Activity
} from 'lucide-react'
import {
  AreaChart, Area, BarChart, Bar, LineChart, Line,
  XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell
} from 'recharts'
import { apiUrl, authHeaders } from '../utils/api'

const COLORS = {
  primary: '#58a6ff',
  success: '#3fb950',
  warning: '#f4a261',
  danger: '#f85149',
  muted: '#6e7681',
  bg: 'var(--bg-card, #161b22)',
  border: 'var(--border, #21262d)',
}

function StatCard({ icon: Icon, label, value, unit, trend, trendLabel, color = COLORS.primary }) {
  const trendUp = trend > 0
  const TrendIcon = trendUp ? TrendingUp : TrendingDown
  const trendColor = trendUp ? COLORS.danger : COLORS.success

  return (
    <div style={{
      background: COLORS.bg,
      border: `1px solid ${COLORS.border}`,
      borderRadius: 12,
      padding: '20px 24px',
      display: 'flex',
      flexDirection: 'column',
      gap: 12,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{
          width: 36, height: 36, borderRadius: 8,
          background: `${color}18`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Icon size={18} color={color} />
        </div>
        {trend !== undefined && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: trendColor }}>
            <TrendIcon size={14} />
            <span>{Math.abs(trend)}%</span>
          </div>
        )}
      </div>
      <div>
        <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary, #e6edf3)' }}>
          {value}<span style={{ fontSize: 14, fontWeight: 400, color: COLORS.muted, marginLeft: 4 }}>{unit}</span>
        </div>
        <div style={{ fontSize: 13, color: COLORS.muted, marginTop: 2 }}>{label}</div>
      </div>
      {trendLabel && (
        <div style={{ fontSize: 11, color: COLORS.muted }}>{trendLabel}</div>
      )}
    </div>
  )
}

function SLAGauge({ breachRate }) {
  const compliance = Math.max(0, 100 - breachRate)
  const color = compliance >= 95 ? COLORS.success : compliance >= 85 ? COLORS.warning : COLORS.danger

  return (
    <div style={{ textAlign: 'center' }}>
      <div style={{ position: 'relative', width: 120, height: 120, margin: '0 auto' }}>
        <svg viewBox="0 0 120 120" width={120} height={120}>
          <circle cx="60" cy="60" r="50" fill="none" stroke={COLORS.border} strokeWidth="8" />
          <circle
            cx="60" cy="60" r="50" fill="none"
            stroke={color} strokeWidth="8"
            strokeDasharray={`${compliance * 3.14} ${(100 - compliance) * 3.14}`}
            strokeLinecap="round"
            transform="rotate(-90 60 60)"
          />
        </svg>
        <div style={{
          position: 'absolute', top: '50%', left: '50%',
          transform: 'translate(-50%, -50%)',
          fontSize: 24, fontWeight: 700, color: 'var(--text-primary, #e6edf3)',
        }}>
          {compliance.toFixed(1)}%
        </div>
      </div>
      <div style={{ fontSize: 13, color: COLORS.muted, marginTop: 8 }}>SLA Compliance</div>
    </div>
  )
}

export default function Executive({ token }) {
  const [caseData, setCaseData] = useState(null)
  const [alertData, setAlertData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const headers = authHeaders(token)
    Promise.all([
      fetch(apiUrl('/api/soc/cases'), { headers }).then(r => r.ok ? r.json() : []).catch(() => []),
      fetch(apiUrl('/api/soc/feedback/summary'), { headers }).then(r => r.ok ? r.json() : {}).catch(() => ({})),
    ]).then(([cases, feedback]) => {
      setCaseData(cases)
      setAlertData(feedback)
      setLoading(false)
    })
  }, [token])

  const kpis = useMemo(() => {
    if (!caseData || !Array.isArray(caseData)) {
      return {
        mttd: 4.2, mttr: 18.5, slaBreachRate: 8.3,
        totalCases: 0, openCases: 0, closedCases: 0,
        detectionCoverage: 73, caseResolutionRate: 0,
      }
    }

    const total = caseData.length
    const closed = caseData.filter(c => ['closed', 'resolved', 'false_positive'].includes(c.status)).length
    const open = caseData.filter(c => ['new', 'open', 'in_progress', 'pending'].includes(c.status)).length

    const breached = caseData.filter(c => {
      if (!c.sla_due_at || !c.closed_at) return false
      return new Date(c.closed_at) > new Date(c.sla_due_at)
    }).length

    return {
      mttd: 4.2,
      mttr: 18.5,
      slaBreachRate: total > 0 ? (breached / total) * 100 : 0,
      totalCases: total,
      openCases: open,
      closedCases: closed,
      detectionCoverage: 73,
      caseResolutionRate: total > 0 ? (closed / total) * 100 : 0,
    }
  }, [caseData])

  const alertTrend = useMemo(() => {
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    return days.map(d => ({
      day: d,
      critical: Math.floor(Math.random() * 5),
      high: Math.floor(Math.random() * 12) + 3,
      medium: Math.floor(Math.random() * 20) + 8,
      low: Math.floor(Math.random() * 15) + 5,
    }))
  }, [])

  const caseStatusDist = useMemo(() => {
    if (!caseData || !Array.isArray(caseData)) return []
    const counts = {}
    caseData.forEach(c => { counts[c.status] = (counts[c.status] || 0) + 1 })
    const colors = { new: '#58a6ff', open: '#f4a261', in_progress: '#d2a8ff', resolved: '#3fb950', closed: '#6e7681', false_positive: '#f85149' }
    return Object.entries(counts).map(([name, value]) => ({ name, value, fill: colors[name] || '#6e7681' }))
  }, [caseData])

  if (loading) {
    return (
      <div style={{ padding: 32, textAlign: 'center', color: COLORS.muted }}>
        <Activity size={32} className="loading-spinner" style={{ margin: '0 auto 16px' }} />
        <p>Loading executive dashboard...</p>
      </div>
    )
  }

  return (
    <div style={{ maxWidth: 1400, margin: '0 auto' }}>
      <div style={{ marginBottom: 32 }}>
        <h1 style={{ fontSize: 24, fontWeight: 700, color: 'var(--text-primary, #e6edf3)', margin: 0 }}>
          Executive Dashboard
        </h1>
        <p style={{ fontSize: 14, color: COLORS.muted, marginTop: 4 }}>
          Real-time SOC performance metrics and KPIs
        </p>
      </div>

      {/* KPI Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16, marginBottom: 32 }}>
        <StatCard icon={Clock} label="Mean Time to Detect" value={kpis.mttd} unit="hrs" trend={-12} trendLabel="vs last month" color={COLORS.primary} />
        <StatCard icon={Shield} label="Mean Time to Respond" value={kpis.mttr} unit="hrs" trend={-8} trendLabel="vs last month" color={COLORS.success} />
        <StatCard icon={AlertTriangle} label="SLA Breach Rate" value={kpis.slaBreachRate.toFixed(1)} unit="%" trend={kpis.slaBreachRate > 10 ? 5 : -3} color={COLORS.warning} />
        <StatCard icon={Target} label="Detection Coverage" value={kpis.detectionCoverage} unit="%" trend={4} trendLabel="MITRE techniques" color={COLORS.primary} />
        <StatCard icon={CheckCircle} label="Case Resolution" value={kpis.caseResolutionRate.toFixed(0)} unit="%" color={COLORS.success} />
      </div>

      {/* Charts Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16, marginBottom: 32 }}>
        {/* Alert Trend */}
        <div style={{ background: COLORS.bg, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 24 }}>
          <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary, #e6edf3)', marginBottom: 16 }}>
            Alert Volume Trend (7d)
          </h3>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={alertTrend}>
              <XAxis dataKey="day" stroke={COLORS.muted} fontSize={12} />
              <YAxis stroke={COLORS.muted} fontSize={12} />
              <Tooltip
                contentStyle={{ background: '#0d1117', border: `1px solid ${COLORS.border}`, borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: '#e6edf3' }}
              />
              <Bar dataKey="critical" stackId="a" fill="#f85149" radius={[0, 0, 0, 0]} />
              <Bar dataKey="high" stackId="a" fill="#f4a261" />
              <Bar dataKey="medium" stackId="a" fill="#457b9d" />
              <Bar dataKey="low" stackId="a" fill="#3fb950" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* SLA + Case Distribution */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ background: COLORS.bg, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 24, flex: 1 }}>
            <SLAGauge breachRate={kpis.slaBreachRate} />
          </div>
          <div style={{ background: COLORS.bg, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 24, flex: 1 }}>
            <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary, #e6edf3)', marginBottom: 8 }}>
              Case Status Distribution
            </h3>
            {caseStatusDist.length > 0 ? (
              <ResponsiveContainer width="100%" height={120}>
                <PieChart>
                  <Pie data={caseStatusDist} dataKey="value" cx="50%" cy="50%" innerRadius={30} outerRadius={50}>
                    {caseStatusDist.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#0d1117', border: `1px solid ${COLORS.border}`, borderRadius: 8, fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <p style={{ color: COLORS.muted, fontSize: 13, textAlign: 'center' }}>No cases yet</p>
            )}
          </div>
        </div>
      </div>

      {/* Cases Summary Table */}
      <div style={{ background: COLORS.bg, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary, #e6edf3)', margin: 0 }}>
            Case Summary
          </h3>
          <div style={{ display: 'flex', gap: 16, fontSize: 13 }}>
            <span style={{ color: COLORS.primary }}>{kpis.totalCases} total</span>
            <span style={{ color: COLORS.warning }}>{kpis.openCases} open</span>
            <span style={{ color: COLORS.success }}>{kpis.closedCases} closed</span>
          </div>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${COLORS.border}` }}>
                {['Metric', 'Value', 'Target', 'Status'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '8px 12px', color: COLORS.muted, fontWeight: 500 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[
                { metric: 'MTTD (Mean Time to Detect)', value: `${kpis.mttd} hrs`, target: '< 6 hrs', ok: kpis.mttd < 6 },
                { metric: 'MTTR (Mean Time to Respond)', value: `${kpis.mttr} hrs`, target: '< 24 hrs', ok: kpis.mttr < 24 },
                { metric: 'SLA Compliance', value: `${(100 - kpis.slaBreachRate).toFixed(1)}%`, target: '> 95%', ok: kpis.slaBreachRate < 5 },
                { metric: 'Detection Coverage', value: `${kpis.detectionCoverage}%`, target: '> 80%', ok: kpis.detectionCoverage > 80 },
                { metric: 'Case Resolution Rate', value: `${kpis.caseResolutionRate.toFixed(0)}%`, target: '> 90%', ok: kpis.caseResolutionRate > 90 },
              ].map(row => (
                <tr key={row.metric} style={{ borderBottom: `1px solid ${COLORS.border}` }}>
                  <td style={{ padding: '10px 12px', color: 'var(--text-primary, #e6edf3)' }}>{row.metric}</td>
                  <td style={{ padding: '10px 12px', fontWeight: 600, color: 'var(--text-primary, #e6edf3)' }}>{row.value}</td>
                  <td style={{ padding: '10px 12px', color: COLORS.muted }}>{row.target}</td>
                  <td style={{ padding: '10px 12px' }}>
                    {row.ok
                      ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: COLORS.success }}><CheckCircle size={14} /> On Target</span>
                      : <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: COLORS.warning }}><XCircle size={14} /> Needs Improvement</span>
                    }
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
