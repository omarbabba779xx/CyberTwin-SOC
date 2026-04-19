import React, { useMemo } from 'react'
import { GitCompareArrows, TrendingUp, TrendingDown, Minus, BarChart3 } from 'lucide-react'
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Legend, Cell } from 'recharts'

const Delta = ({ value, suffix = '%' }) => {
  const v = parseFloat(value) || 0
  const color = v > 0 ? 'text-green-400' : v < 0 ? 'text-red-400' : 'text-gray-500'
  const Icon = v > 0 ? TrendingUp : v < 0 ? TrendingDown : Minus
  return (
    <span className={`flex items-center gap-1 text-sm font-bold ${color}`}>
      <Icon size={14} />
      {v > 0 ? '+' : ''}{v.toFixed(1)}{suffix}
    </span>
  )
}

export default function Comparison({ history }) {
  if (!history || history.length < 2) {
    return (
      <div className="flex flex-col items-center justify-center h-96 text-gray-500">
        <GitCompareArrows className="w-12 h-12 mb-3 text-gray-700" />
        <h2 className="text-xl font-semibold text-gray-400 mb-2">Comparison Dashboard</h2>
        <p>Run at least 2 simulations to compare results.</p>
        <p className="text-xs text-gray-600 mt-1">Each simulation is automatically saved for comparison.</p>
      </div>
    )
  }

  const baseline = history[0]
  const latest = history[history.length - 1]
  const bScores = baseline.scores || {}
  const lScores = latest.scores || {}

  // Radar data
  const radarData = [
    { dim: 'Detection', baseline: bScores.detection_score || 0, latest: lScores.detection_score || 0 },
    { dim: 'Coverage', baseline: bScores.coverage_score || 0, latest: lScores.coverage_score || 0 },
    { dim: 'Response', baseline: bScores.response_score || 0, latest: lScores.response_score || 0 },
    { dim: 'Visibility', baseline: bScores.visibility_score || 0, latest: lScores.visibility_score || 0 },
  ]

  // Comparison metrics
  const metrics = [
    { label: 'Overall Score', b: bScores.overall_score, l: lScores.overall_score },
    { label: 'Detection', b: bScores.detection_score, l: lScores.detection_score },
    { label: 'Coverage', b: bScores.coverage_score, l: lScores.coverage_score },
    { label: 'Response', b: bScores.response_score, l: lScores.response_score },
    { label: 'Visibility', b: bScores.visibility_score, l: lScores.visibility_score },
  ]

  // Bar chart data
  const barData = [
    { name: 'Events', baseline: baseline.total_events || 0, latest: latest.total_events || 0 },
    { name: 'Alerts', baseline: (baseline.alerts || []).length, latest: (latest.alerts || []).length },
    { name: 'Incidents', baseline: (baseline.incidents || []).length, latest: (latest.incidents || []).length },
  ]

  const overallDelta = (lScores.overall_score || 0) - (bScores.overall_score || 0)

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center gap-4">
        <div className="p-3 bg-[#457b9d]/20 rounded-xl">
          <GitCompareArrows className="w-8 h-8 text-[#457b9d]" />
        </div>
        <div>
          <h1 className="text-2xl font-bold">Simulation Comparison</h1>
          <p className="text-gray-400 text-sm">{history.length} simulations recorded</p>
        </div>
      </div>

      {/* Overall improvement */}
      <div className={`p-6 rounded-xl border ${overallDelta >= 0 ? 'bg-green-600/10 border-green-600/30' : 'bg-red-600/10 border-red-600/30'}`}>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-gray-400">Overall Security Improvement</p>
            <p className={`text-4xl font-bold ${overallDelta >= 0 ? 'text-green-400' : 'text-red-400'}`}>
              {overallDelta >= 0 ? '+' : ''}{overallDelta.toFixed(1)}%
            </p>
          </div>
          <div className="text-right text-sm">
            <p className="text-gray-500">Baseline: <span className="text-gray-300 font-bold">{bScores.overall_score?.toFixed(1)}%</span></p>
            <p className="text-gray-500">Latest: <span className="text-[#e63946] font-bold">{lScores.overall_score?.toFixed(1)}%</span></p>
          </div>
        </div>
      </div>

      {/* Side-by-side cards */}
      <div className="grid grid-cols-2 gap-6">
        {/* Baseline */}
        <div className="card p-6">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-3 h-3 bg-gray-500 rounded-full" />
            <h3 className="font-semibold text-gray-400">Baseline (First Run)</h3>
          </div>
          <p className="text-xs text-gray-600 mb-3">{baseline.scenario?.name || baseline.scores?.scenario_name}</p>
          <div className="space-y-2">
            {metrics.map(m => (
              <div key={m.label} className="flex justify-between items-center">
                <span className="text-sm text-gray-500">{m.label}</span>
                <span className="text-sm font-bold text-gray-400">{(m.b || 0).toFixed(1)}%</span>
              </div>
            ))}
          </div>
          <div className="mt-3 pt-3 border-t border-[#21262d]">
            <span className={`text-xs font-bold px-2 py-1 rounded ${
              bScores.risk_level === 'Critical' ? 'bg-red-600/20 text-red-400' :
              bScores.risk_level === 'High' ? 'bg-orange-600/20 text-orange-400' :
              'bg-yellow-600/20 text-yellow-400'
            }`}>{bScores.risk_level}</span>
          </div>
        </div>

        {/* Latest */}
        <div className="card border-[#e63946]/30 p-6">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-3 h-3 bg-[#e63946] rounded-full animate-pulse" />
            <h3 className="font-semibold text-[#e63946]">Latest Run</h3>
          </div>
          <p className="text-xs text-gray-600 mb-3">{latest.scenario?.name || latest.scores?.scenario_name}</p>
          <div className="space-y-2">
            {metrics.map(m => (
              <div key={m.label} className="flex justify-between items-center">
                <span className="text-sm text-gray-500">{m.label}</span>
                <div className="flex items-center gap-3">
                  <span className="text-sm font-bold text-[#e63946]">{(m.l || 0).toFixed(1)}%</span>
                  <Delta value={(m.l || 0) - (m.b || 0)} />
                </div>
              </div>
            ))}
          </div>
          <div className="mt-3 pt-3 border-t border-[#21262d]">
            <span className={`text-xs font-bold px-2 py-1 rounded ${
              lScores.risk_level === 'Critical' ? 'bg-red-600/20 text-red-400' :
              lScores.risk_level === 'High' ? 'bg-orange-600/20 text-orange-400' :
              'bg-yellow-600/20 text-yellow-400'
            }`}>{lScores.risk_level}</span>
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Radar Chart */}
        <div className="card p-6">
          <h3 className="text-lg font-semibold mb-4">Security Dimensions</h3>
          <ResponsiveContainer width="100%" height={300}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="#334155" />
              <PolarAngleAxis dataKey="dim" tick={{ fill: '#94a3b8', fontSize: 12 }} />
              <PolarRadiusAxis angle={90} domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 10 }} />
              <Radar name="Baseline" dataKey="baseline" stroke="#64748b" fill="#64748b" fillOpacity={0.2} strokeWidth={2} />
              <Radar name="Latest" dataKey="latest" stroke="#e63946" fill="#e63946" fillOpacity={0.3} strokeWidth={2} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        {/* Bar Chart */}
        <div className="card p-6">
          <h3 className="text-lg font-semibold mb-4">Detection Metrics</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={barData}>
              <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
              <YAxis stroke="#64748b" fontSize={12} />
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Bar dataKey="baseline" name="Baseline" fill="#64748b" radius={[4, 4, 0, 0]} />
              <Bar dataKey="latest" name="Latest" fill="#e63946" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Run History */}
      <div className="card p-6">
        <h3 className="text-lg font-semibold mb-4">Simulation History</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-400 border-b border-[#21262d]">
                <th className="text-left py-2 px-3">#</th>
                <th className="text-left py-2 px-3">Scenario</th>
                <th className="text-left py-2 px-3">Overall</th>
                <th className="text-left py-2 px-3">Detection</th>
                <th className="text-left py-2 px-3">Coverage</th>
                <th className="text-left py-2 px-3">Risk</th>
                <th className="text-left py-2 px-3">Alerts</th>
              </tr>
            </thead>
            <tbody>
              {history.map((run, i) => (
                <tr key={i} className="border-b border-[#21262d]/50 hover:bg-gray-800/30">
                  <td className="py-2 px-3 text-gray-500">{i + 1}</td>
                  <td className="py-2 px-3 text-gray-300">{run.scenario?.name || run.scores?.scenario_name || 'N/A'}</td>
                  <td className="py-2 px-3 font-bold" style={{
                    color: (run.scores?.overall_score || 0) >= 70 ? '#22c55e' : (run.scores?.overall_score || 0) >= 40 ? '#f59e0b' : '#ef4444'
                  }}>{(run.scores?.overall_score || 0).toFixed(1)}%</td>
                  <td className="py-2 px-3 text-[#e63946]">{(run.scores?.detection_score || 0).toFixed(1)}%</td>
                  <td className="py-2 px-3 text-[#457b9d]">{(run.scores?.coverage_score || 0).toFixed(1)}%</td>
                  <td className="py-2 px-3">
                    <span className={`text-xs px-2 py-0.5 rounded font-bold ${
                      run.scores?.risk_level === 'Critical' ? 'bg-red-600/20 text-red-400' :
                      run.scores?.risk_level === 'High' ? 'bg-orange-600/20 text-orange-400' :
                      'bg-green-600/20 text-green-400'
                    }`}>{run.scores?.risk_level}</span>
                  </td>
                  <td className="py-2 px-3 text-gray-400">{(run.alerts || []).length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
