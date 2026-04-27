import React, { useState, useEffect, useMemo } from 'react'
import { BarChart3, TrendingUp, Award, Target, Activity, ArrowUpRight, ArrowDownRight } from 'lucide-react'
import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from 'recharts'
import { apiUrl, authHeaders } from '../utils/api'

const SCORE_COLORS = {
  overall: '#e63946',
  detection: '#f4a261',
  coverage: '#457b9d',
  visibility: '#2a9d8f',
}

function formatDate(ts) {
  if (!ts) return ''
  const d = new Date(ts)
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + ' ' + d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
}

function getRiskColor(level) {
  if (!level) return '#6e7681'
  const l = level.toLowerCase()
  if (l === 'critical' || l === 'high') return '#e63946'
  if (l === 'medium') return '#f4a261'
  return '#2a9d8f'
}

export default function Analytics({ token }) {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [sortField, setSortField] = useState('timestamp')
  const [sortDir, setSortDir] = useState('desc')

  useEffect(() => {
    fetch(apiUrl('/api/history?limit=50'), { headers: authHeaders(token) })
      .then(r => r.json())
      .then(data => {
        setHistory(Array.isArray(data) ? data : [])
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [token])

  // Trend data (chronological order)
  const trendData = useMemo(() => {
    return [...history].reverse().map(run => ({
      date: formatDate(run.timestamp),
      overall: Math.round(run.overall_score ?? 0),
      detection: Math.round(run.detection_score ?? 0),
      coverage: Math.round(run.coverage_score ?? 0),
      visibility: Math.round(run.visibility_score ?? 0),
    }))
  }, [history])

  // Scenario comparison data
  const scenarioData = useMemo(() => {
    const byScenario = {}
    history.forEach(run => {
      const name = run.scenario_name || run.scenario_id || 'Unknown'
      if (!byScenario[name]) {
        byScenario[name] = { runs: 0, overall: 0, detection: 0, coverage: 0, visibility: 0 }
      }
      byScenario[name].runs += 1
      byScenario[name].overall += (run.overall_score ?? 0)
      byScenario[name].detection += (run.detection_score ?? 0)
      byScenario[name].coverage += (run.coverage_score ?? 0)
      byScenario[name].visibility += (run.visibility_score ?? 0)
    })
    return Object.entries(byScenario).map(([name, data]) => ({
      name: name.length > 20 ? name.slice(0, 18) + '...' : name,
      overall: Math.round(data.overall / data.runs),
      detection: Math.round(data.detection / data.runs),
      coverage: Math.round(data.coverage / data.runs),
      visibility: Math.round(data.visibility / data.runs),
    }))
  }, [history])

  // Stats
  const stats = useMemo(() => {
    if (!history.length) return null
    const scores = history.map(r => r.overall_score ?? 0)
    const best = Math.max(...scores)
    const scenarioCounts = {}
    history.forEach(r => {
      const n = r.scenario_name || r.scenario_id || 'Unknown'
      scenarioCounts[n] = (scenarioCounts[n] || 0) + 1
    })
    const mostTested = Object.entries(scenarioCounts).sort((a, b) => b[1] - a[1])[0]

    // Average improvement: compare last vs first score
    let improvement = 0
    if (history.length >= 2) {
      const reversed = [...history].reverse()
      const first = reversed[0].overall_score ?? 0
      const last = reversed[reversed.length - 1].overall_score ?? 0
      improvement = first > 0 ? Math.round(((last - first) / first) * 100) : 0
    }

    return {
      total: history.length,
      best: Math.round(best),
      mostTested: mostTested ? mostTested[0] : 'N/A',
      mostTestedCount: mostTested ? mostTested[1] : 0,
      improvement,
    }
  }, [history])

  // Sortable history
  const sortedHistory = useMemo(() => {
    return [...history].sort((a, b) => {
      let valA, valB
      if (sortField === 'timestamp') {
        valA = a.timestamp || ''
        valB = b.timestamp || ''
      } else if (sortField === 'overall_score') {
        valA = a.overall_score ?? 0
        valB = b.overall_score ?? 0
      } else {
        valA = a[sortField] ?? ''
        valB = b[sortField] ?? ''
      }
      if (valA < valB) return sortDir === 'asc' ? -1 : 1
      if (valA > valB) return sortDir === 'asc' ? 1 : -1
      return 0
    })
  }, [history, sortField, sortDir])

  const toggleSort = (field) => {
    if (sortField === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortDir('desc')
    }
  }

  const sortIndicator = (field) => {
    if (sortField !== field) return ''
    return sortDir === 'asc' ? ' \u25B2' : ' \u25BC'
  }

  const tooltipStyle = {
    backgroundColor: '#161b22',
    border: '1px solid #21262d',
    borderRadius: 8,
    color: '#e6edf3',
  }

  if (loading) {
    return (
      <div>
        <div className="flex items-center gap-3 mb-6">
          <BarChart3 className="w-7 h-7" style={{ color: '#e63946' }} />
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary, #e6edf3)' }}>Security Analytics</h1>
        </div>
        <div className="card" style={{ textAlign: 'center', padding: 60 }}>
          <p style={{ color: 'var(--text-muted, #6e7681)' }}>Loading analytics...</p>
        </div>
      </div>
    )
  }

  if (!history.length) {
    return (
      <div>
        <div className="flex items-center gap-3 mb-6">
          <BarChart3 className="w-7 h-7" style={{ color: '#e63946' }} />
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary, #e6edf3)' }}>Security Analytics</h1>
            <p style={{ color: 'var(--text-muted, #6e7681)', fontSize: 14 }}>Trends and insights across simulation runs</p>
          </div>
        </div>
        <div className="card" style={{ textAlign: 'center', padding: 60 }}>
          <BarChart3 className="w-16 h-16 mx-auto mb-4" style={{ color: '#21262d' }} />
          <h2 className="text-xl font-semibold mb-2" style={{ color: 'var(--text-primary, #e6edf3)' }}>No Analytics Available</h2>
          <p style={{ color: 'var(--text-muted, #6e7681)' }}>Run multiple simulations to see analytics and trends.</p>
        </div>
      </div>
    )
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <BarChart3 className="w-7 h-7" style={{ color: '#e63946' }} />
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary, #e6edf3)' }}>Security Analytics</h1>
          <p style={{ color: 'var(--text-muted, #6e7681)', fontSize: 14 }}>Trends and insights across simulation runs</p>
        </div>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <div className="card" style={{ padding: 20 }}>
            <div className="flex items-center gap-2 mb-2">
              <Activity className="w-4 h-4" style={{ color: '#457b9d' }} />
              <span style={{ color: 'var(--text-muted, #6e7681)', fontSize: 12, fontWeight: 600, textTransform: 'uppercase' }}>Total Simulations</span>
            </div>
            <div className="stat-value" style={{ color: '#457b9d', fontSize: 28 }}>{stats.total}</div>
          </div>

          <div className="card" style={{ padding: 20 }}>
            <div className="flex items-center gap-2 mb-2">
              <Award className="w-4 h-4" style={{ color: '#2a9d8f' }} />
              <span style={{ color: 'var(--text-muted, #6e7681)', fontSize: 12, fontWeight: 600, textTransform: 'uppercase' }}>Best Score</span>
            </div>
            <div className="stat-value" style={{ color: '#2a9d8f', fontSize: 28 }}>{stats.best}%</div>
          </div>

          <div className="card" style={{ padding: 20 }}>
            <div className="flex items-center gap-2 mb-2">
              <Target className="w-4 h-4" style={{ color: '#f4a261' }} />
              <span style={{ color: 'var(--text-muted, #6e7681)', fontSize: 12, fontWeight: 600, textTransform: 'uppercase' }}>Most Tested</span>
            </div>
            <div className="stat-value" style={{ color: '#f4a261', fontSize: 16 }}>{stats.mostTested.length > 22 ? stats.mostTested.slice(0, 20) + '...' : stats.mostTested}</div>
            <div style={{ color: 'var(--text-muted, #6e7681)', fontSize: 12 }}>{stats.mostTestedCount} runs</div>
          </div>

          <div className="card" style={{ padding: 20 }}>
            <div className="flex items-center gap-2 mb-2">
              <TrendingUp className="w-4 h-4" style={{ color: stats.improvement >= 0 ? '#2a9d8f' : '#e63946' }} />
              <span style={{ color: 'var(--text-muted, #6e7681)', fontSize: 12, fontWeight: 600, textTransform: 'uppercase' }}>Avg Improvement</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="stat-value" style={{ color: stats.improvement >= 0 ? '#2a9d8f' : '#e63946', fontSize: 28 }}>{stats.improvement >= 0 ? '+' : ''}{stats.improvement}%</span>
              {stats.improvement >= 0
                ? <ArrowUpRight className="w-5 h-5" style={{ color: '#2a9d8f' }} />
                : <ArrowDownRight className="w-5 h-5" style={{ color: '#e63946' }} />
              }
            </div>
          </div>
        </div>
      )}

      {/* Score Trend Line Chart */}
      <div className="card" style={{ padding: 24, marginBottom: 24 }}>
        <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary, #e6edf3)' }}>Score Trends Over Time</h2>
        <ResponsiveContainer width="100%" height={340}>
          <LineChart data={trendData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
            <XAxis dataKey="date" tick={{ fill: '#6e7681', fontSize: 11 }} angle={-30} textAnchor="end" height={60} />
            <YAxis domain={[0, 100]} tick={{ fill: '#6e7681', fontSize: 12 }} />
            <Tooltip contentStyle={tooltipStyle} labelStyle={{ color: '#e6edf3' }} />
            <Legend wrapperStyle={{ color: '#8b949e', fontSize: 12 }} />
            <Line type="monotone" dataKey="overall" name="Overall" stroke={SCORE_COLORS.overall} strokeWidth={2} dot={{ r: 4 }} />
            <Line type="monotone" dataKey="detection" name="Detection" stroke={SCORE_COLORS.detection} strokeWidth={2} dot={{ r: 3 }} />
            <Line type="monotone" dataKey="coverage" name="Coverage" stroke={SCORE_COLORS.coverage} strokeWidth={2} dot={{ r: 3 }} />
            <Line type="monotone" dataKey="visibility" name="Visibility" stroke={SCORE_COLORS.visibility} strokeWidth={2} dot={{ r: 3 }} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Scenario Comparison Bar Chart */}
      {scenarioData.length > 0 && (
        <div className="card" style={{ padding: 24, marginBottom: 24 }}>
          <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary, #e6edf3)' }}>Scenario Comparison (Avg Scores)</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={scenarioData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
              <XAxis dataKey="name" tick={{ fill: '#6e7681', fontSize: 11 }} />
              <YAxis domain={[0, 100]} tick={{ fill: '#6e7681', fontSize: 12 }} />
              <Tooltip contentStyle={tooltipStyle} labelStyle={{ color: '#e6edf3' }} />
              <Legend wrapperStyle={{ color: '#8b949e', fontSize: 12 }} />
              <Bar dataKey="overall" name="Overall" fill={SCORE_COLORS.overall} radius={[4, 4, 0, 0]} />
              <Bar dataKey="detection" name="Detection" fill={SCORE_COLORS.detection} radius={[4, 4, 0, 0]} />
              <Bar dataKey="coverage" name="Coverage" fill={SCORE_COLORS.coverage} radius={[4, 4, 0, 0]} />
              <Bar dataKey="visibility" name="Visibility" fill={SCORE_COLORS.visibility} radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Run History Table */}
      <div className="card" style={{ padding: 24 }}>
        <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary, #e6edf3)' }}>Run History</h2>
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table" style={{ width: '100%' }}>
            <thead>
              <tr>
                <th style={{ cursor: 'pointer' }} onClick={() => toggleSort('timestamp')}>Date{sortIndicator('timestamp')}</th>
                <th>Scenario</th>
                <th style={{ cursor: 'pointer' }} onClick={() => toggleSort('overall_score')}>Score{sortIndicator('overall_score')}</th>
                <th>Risk Level</th>
                <th>Events</th>
                <th>Alerts</th>
              </tr>
            </thead>
            <tbody>
              {sortedHistory.map((run, i) => (
                <tr key={run.id || i}>
                  <td style={{ whiteSpace: 'nowrap' }}>{formatDate(run.timestamp)}</td>
                  <td>{run.scenario_name || run.scenario_id}</td>
                  <td>
                    <span style={{ color: run.overall_score >= 75 ? '#2a9d8f' : run.overall_score >= 50 ? '#f4a261' : '#e63946', fontWeight: 600 }}>
                      {Math.round(run.overall_score ?? 0)}%
                    </span>
                  </td>
                  <td>
                    <span style={{
                      fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 9999,
                      backgroundColor: `${getRiskColor(run.risk_level)}15`,
                      color: getRiskColor(run.risk_level),
                      border: `1px solid ${getRiskColor(run.risk_level)}30`,
                    }}>
                      {run.risk_level || 'N/A'}
                    </span>
                  </td>
                  <td>{run.total_events ?? 0}</td>
                  <td>{run.total_alerts ?? 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
