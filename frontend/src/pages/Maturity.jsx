import React from 'react'
import { Shield, Eye, ShieldCheck, Search, MessageSquare, RefreshCw, Landmark, TrendingUp, AlertTriangle } from 'lucide-react'
import {
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, ResponsiveContainer, Legend, Tooltip
} from 'recharts'

const NIST_FUNCTIONS = [
  { name: 'Identify', key: 'visibility', description: 'Asset management, risk assessment', icon: Eye },
  { name: 'Protect', key: 'coverage', description: 'Access control, awareness training', icon: ShieldCheck },
  { name: 'Detect', key: 'detection', description: 'Anomalies, continuous monitoring', icon: Search },
  { name: 'Respond', key: 'response', description: 'Response planning, communications', icon: MessageSquare },
  { name: 'Recover', key: 'recovery', description: 'Recovery planning, improvements', icon: RefreshCw },
  { name: 'Govern', key: 'governance', description: 'Policy, oversight, supply chain', icon: Landmark },
]

const MATURITY_LEVELS = [
  { level: 1, name: 'Initial / Ad Hoc', range: '0–20', description: 'Security practices are reactive and unstructured. No formal processes in place.', next: 'Establish basic security policies and assign responsibilities.' },
  { level: 2, name: 'Developing', range: '21–40', description: 'Some security practices exist but are inconsistently applied.', next: 'Formalize and document security procedures across the organization.' },
  { level: 3, name: 'Defined', range: '41–60', description: 'Security processes are documented and standardized across the organization.', next: 'Implement metrics and continuous monitoring for all security controls.' },
  { level: 4, name: 'Managed', range: '61–80', description: 'Security is measured and controlled. Quantitative objectives are established.', next: 'Pursue continuous improvement and automation of security processes.' },
  { level: 5, name: 'Optimized', range: '81–100', description: 'Continuous improvement with advanced automation and proactive threat management.', next: 'Maintain excellence and adapt to emerging threats proactively.' },
]

function getMaturityLevel(score) {
  if (score <= 20) return MATURITY_LEVELS[0]
  if (score <= 40) return MATURITY_LEVELS[1]
  if (score <= 60) return MATURITY_LEVELS[2]
  if (score <= 80) return MATURITY_LEVELS[3]
  return MATURITY_LEVELS[4]
}

function getScoreColor(score) {
  if (score < 50) return '#e63946'
  if (score <= 75) return '#f4a261'
  return '#2a9d8f'
}

function mapScores(scores) {
  if (!scores) return null
  const detection = scores.detection_score ?? 0
  const coverage = scores.coverage_score ?? 0
  const response = scores.response_score ?? 0
  const visibility = scores.visibility_score ?? 0
  const recovery = Math.min(response, visibility)
  const governance = Math.round((detection + coverage + response + visibility) / 4)

  return {
    visibility,
    coverage,
    detection,
    response,
    recovery,
    governance,
  }
}

export default function Maturity({ result, scores }) {
  const mapped = mapScores(scores || result?.scores)

  if (!mapped) {
    return (
      <div>
        <div className="flex items-center gap-3 mb-6">
          <Shield className="w-7 h-7" style={{ color: '#e63946' }} />
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary, #e6edf3)' }}>SOC Maturity Assessment</h1>
            <p style={{ color: 'var(--text-muted, #6e7681)', fontSize: 14 }}>Based on NIST Cybersecurity Framework</p>
          </div>
        </div>
        <div className="card" style={{ textAlign: 'center', padding: 60 }}>
          <Shield className="w-16 h-16 mx-auto mb-4" style={{ color: '#21262d' }} />
          <h2 className="text-xl font-semibold mb-2" style={{ color: 'var(--text-primary, #e6edf3)' }}>No Assessment Available</h2>
          <p style={{ color: 'var(--text-muted, #6e7681)' }}>Run a simulation first to generate a SOC maturity assessment based on the NIST Cybersecurity Framework.</p>
        </div>
      </div>
    )
  }

  const radarData = NIST_FUNCTIONS.map(fn => ({
    name: fn.name,
    score: mapped[fn.key] ?? 0,
    target: 80,
    fullMark: 100,
  }))

  const allScores = NIST_FUNCTIONS.map(fn => mapped[fn.key] ?? 0)
  const overallAvg = Math.round(allScores.reduce((a, b) => a + b, 0) / allScores.length)
  const maturity = getMaturityLevel(overallAvg)

  return (
    <div>
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <Shield className="w-7 h-7" style={{ color: '#e63946' }} />
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary, #e6edf3)' }}>SOC Maturity Assessment</h1>
          <p style={{ color: 'var(--text-muted, #6e7681)', fontSize: 14 }}>Based on NIST Cybersecurity Framework</p>
        </div>
      </div>

      {/* Radar Chart */}
      <div className="card" style={{ padding: 24, marginBottom: 24 }}>
        <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary, #e6edf3)' }}>NIST CSF Radar</h2>
        <ResponsiveContainer width="100%" height={420}>
          <RadarChart cx="50%" cy="50%" outerRadius="80%" data={radarData}>
            <PolarGrid stroke="#21262d" />
            <PolarAngleAxis dataKey="name" tick={{ fill: '#8b949e', fontSize: 13 }} />
            <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: '#6e7681' }} />
            <Radar name="Current Score" dataKey="score" stroke="#e63946" fill="#e63946" fillOpacity={0.2} />
            <Radar name="Target" dataKey="target" stroke="#2a9d8f" fill="#2a9d8f" fillOpacity={0.1} strokeDasharray="5 5" />
            <Legend wrapperStyle={{ color: '#8b949e', fontSize: 12 }} />
            <Tooltip
              contentStyle={{ backgroundColor: '#161b22', border: '1px solid #21262d', borderRadius: 8, color: '#e6edf3' }}
              labelStyle={{ color: '#e6edf3' }}
            />
          </RadarChart>
        </ResponsiveContainer>
      </div>

      {/* Function Cards - 3x2 grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
        {NIST_FUNCTIONS.map(fn => {
          const score = Math.round(mapped[fn.key] ?? 0)
          const gap = Math.max(0, 80 - score)
          const color = getScoreColor(score)
          const Icon = fn.icon

          return (
            <div key={fn.key} className="card" style={{ padding: 20 }}>
              <div className="flex items-center gap-2 mb-3">
                <Icon className="w-5 h-5" style={{ color }} />
                <span className="font-semibold" style={{ color: 'var(--text-primary, #e6edf3)', fontSize: 15 }}>{fn.name}</span>
              </div>

              <div className="stat-value" style={{ color, fontSize: 32, marginBottom: 8 }}>{score}%</div>

              <div className="progress-bar" style={{ marginBottom: 10 }}>
                <div className="progress-fill" style={{ width: `${score}%`, backgroundColor: color }} />
              </div>

              <p style={{ color: 'var(--text-muted, #6e7681)', fontSize: 12, marginBottom: 8 }}>{fn.description}</p>

              <div style={{ fontSize: 12, color: 'var(--text-secondary, #8b949e)', backgroundColor: 'rgba(13, 17, 23, 0.5)', padding: '8px 10px', borderRadius: 6, border: '1px solid var(--border, #21262d)' }}>
                <span>Current: <strong style={{ color }}>{score}%</strong></span>
                <span style={{ margin: '0 6px', color: '#21262d' }}>&rarr;</span>
                <span>Target: <strong style={{ color: '#2a9d8f' }}>80%</strong></span>
                <span style={{ margin: '0 6px', color: '#21262d' }}>&rarr;</span>
                <span>Gap: <strong style={{ color: gap > 0 ? '#f4a261' : '#2a9d8f' }}>{gap}%</strong></span>
              </div>
            </div>
          )
        })}
      </div>

      {/* Maturity Level Card */}
      <div className="card" style={{ padding: 24 }}>
        <div className="flex items-center gap-3 mb-4">
          <TrendingUp className="w-6 h-6" style={{ color: getScoreColor(overallAvg) }} />
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary, #e6edf3)' }}>Overall Maturity Level</h2>
        </div>

        <div className="flex items-center gap-6 mb-4">
          <div
            className="flex items-center justify-center"
            style={{
              width: 80, height: 80, borderRadius: '50%',
              backgroundColor: `${getScoreColor(overallAvg)}15`,
              border: `2px solid ${getScoreColor(overallAvg)}40`,
            }}
          >
            <span style={{ fontSize: 32, fontWeight: 700, color: getScoreColor(overallAvg) }}>{maturity.level}</span>
          </div>
          <div>
            <div className="text-xl font-bold" style={{ color: 'var(--text-primary, #e6edf3)' }}>Level {maturity.level}: {maturity.name}</div>
            <div style={{ color: 'var(--text-secondary, #8b949e)', fontSize: 14, marginTop: 4 }}>Overall Score: {overallAvg}% (Range: {maturity.range})</div>
          </div>
        </div>

        <p style={{ color: 'var(--text-secondary, #8b949e)', fontSize: 14, marginBottom: 16 }}>{maturity.description}</p>

        {maturity.level < 5 && (
          <div style={{ padding: '12px 16px', borderRadius: 8, backgroundColor: 'rgba(244, 162, 97, 0.08)', border: '1px solid rgba(244, 162, 97, 0.2)' }}>
            <div className="flex items-center gap-2 mb-1">
              <AlertTriangle className="w-4 h-4" style={{ color: '#f4a261' }} />
              <span style={{ color: '#f4a261', fontSize: 13, fontWeight: 600 }}>Path to Level {maturity.level + 1}</span>
            </div>
            <p style={{ color: 'var(--text-secondary, #8b949e)', fontSize: 13 }}>{maturity.next}</p>
          </div>
        )}
      </div>
    </div>
  )
}
