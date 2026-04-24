import React, { useState, useEffect } from 'react'
import { BookOpen, Shield, CheckCircle, AlertTriangle, XCircle, RefreshCw } from 'lucide-react'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

function ScoreBar({ score, max = 100 }) {
  const pct = Math.min(100, Math.round((score / max) * 100))
  const color = pct >= 75 ? '#3fb950' : pct >= 50 ? '#e3b341' : '#f85149'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <div style={{ flex: 1, height: 6, borderRadius: 3, backgroundColor: 'rgba(255,255,255,0.08)' }}>
        <div style={{ width: pct + '%', height: '100%', borderRadius: 3, backgroundColor: color, transition: 'width 0.6s ease' }} />
      </div>
      <span style={{ fontSize: 12, fontWeight: 600, color, minWidth: 34, textAlign: 'right' }}>{Math.round(score)}</span>
    </div>
  )
}

function TierBadge({ tier }) {
  const color = tier?.includes('4') ? '#3fb950'
    : tier?.includes('3') ? '#a5d8ff'
    : tier?.includes('2') ? '#e3b341'
    : '#f85149'
  return (
    <span style={{
      fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 99,
      backgroundColor: color + '22', color, border: `1px solid ${color}44`,
    }}>
      {tier || '—'}
    </span>
  )
}

export default function Benchmark({ scenarioId, token }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const load = () => {
    if (!scenarioId) return
    setLoading(true)
    setError(null)
    fetch(`${API}/api/results/${scenarioId}/benchmark`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => r.ok ? r.json() : Promise.reject(r.statusText))
      .then(setData)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [scenarioId])

  if (!scenarioId) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60vh', color: '#6e7681' }}>
      <div style={{ textAlign: 'center' }}>
        <BookOpen style={{ width: 48, height: 48, marginBottom: 12, opacity: 0.3, margin: '0 auto 12px' }} />
        <p>Run a simulation first to see benchmark ratings.</p>
      </div>
    </div>
  )

  return (
    <div style={{ padding: '24px 28px', maxWidth: 960, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 28 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary, #e6edf3)', margin: 0 }}>
            Security Benchmark
          </h1>
          <p style={{ fontSize: 13, color: '#6e7681', marginTop: 4 }}>
            NIST Cybersecurity Framework v1.1 &amp; CIS Controls v8
          </p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '7px 14px', borderRadius: 6, fontSize: 13, fontWeight: 500,
            backgroundColor: 'rgba(99,110,123,0.15)', border: '1px solid rgba(99,110,123,0.3)',
            color: '#8b949e', cursor: 'pointer',
          }}
        >
          <RefreshCw style={{ width: 14, height: 14 }} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {error && (
        <div style={{ padding: 14, borderRadius: 8, backgroundColor: 'rgba(248,81,73,0.1)', border: '1px solid rgba(248,81,73,0.25)', color: '#f85149', marginBottom: 20 }}>
          {error}
        </div>
      )}

      {loading && (
        <div style={{ textAlign: 'center', padding: 60, color: '#6e7681' }}>Loading benchmark data…</div>
      )}

      {data && !loading && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>

          {/* NIST CSF Card */}
          <div style={{ gridColumn: '1 / -1', padding: 20, borderRadius: 10, backgroundColor: 'var(--bg-card, #161b22)', border: '1px solid var(--border, #21262d)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
              <div>
                <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary, #e6edf3)', margin: 0 }}>
                  NIST Cybersecurity Framework
                </h2>
                <p style={{ fontSize: 12, color: '#6e7681', marginTop: 2 }}>Version 1.1 — Five Core Functions</p>
              </div>
              <TierBadge tier={data.nist_csf?.overall_tier} />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
              {Object.entries(data.nist_csf?.functions || {}).map(([fn, val]) => {
                const colors = { IDENTIFY: '#a5d8ff', PROTECT: '#3fb950', DETECT: '#e3b341', RESPOND: '#ffa657', RECOVER: '#bc8cff' }
                const col = colors[fn] || '#8b949e'
                return (
                  <div key={fn} style={{ padding: 14, borderRadius: 8, backgroundColor: col + '11', border: `1px solid ${col}33`, textAlign: 'center' }}>
                    <p style={{ fontSize: 10, fontWeight: 700, color: col, marginBottom: 8, letterSpacing: '0.1em' }}>{fn}</p>
                    <p style={{ fontSize: 26, fontWeight: 800, color: col, margin: '0 0 6px' }}>{Math.round(val.score)}</p>
                    <TierBadge tier={val.tier?.split(' — ')[0]} />
                  </div>
                )
              })}
            </div>
          </div>

          {/* CIS Controls Card */}
          <div style={{ gridColumn: '1 / -1', padding: 20, borderRadius: 10, backgroundColor: 'var(--bg-card, #161b22)', border: '1px solid var(--border, #21262d)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
              <div>
                <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary, #e6edf3)', margin: 0 }}>
                  CIS Controls v8
                </h2>
                <p style={{ fontSize: 12, color: '#6e7681', marginTop: 2 }}>Implementation Groups &amp; Control Scores</p>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ fontSize: 13, color: '#8b949e' }}>Avg: <strong style={{ color: '#e6edf3' }}>{data.cis_controls?.avg_score}</strong></span>
                <TierBadge tier={data.cis_controls?.implementation_group} />
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {(data.cis_controls?.controls || []).map((ctrl) => (
                <div key={ctrl.id} style={{ display: 'grid', gridTemplateColumns: '90px 1fr 80px', alignItems: 'center', gap: 14 }}>
                  <span style={{ fontSize: 11, fontWeight: 700, color: '#6e7681', fontFamily: 'monospace' }}>{ctrl.id}</span>
                  <div>
                    <p style={{ fontSize: 12, color: 'var(--text-secondary, #8b949e)', margin: 0 }}>{ctrl.name}</p>
                    <ScoreBar score={ctrl.score} />
                  </div>
                  <span style={{
                    fontSize: 12, fontWeight: 700, textAlign: 'right',
                    color: ctrl.score >= 75 ? '#3fb950' : ctrl.score >= 50 ? '#e3b341' : '#f85149',
                  }}>
                    {Math.round(ctrl.score)}/100
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Interpretation guide */}
          <div style={{ gridColumn: '1 / -1', padding: 16, borderRadius: 8, backgroundColor: 'rgba(99,110,123,0.08)', border: '1px solid rgba(99,110,123,0.2)' }}>
            <p style={{ fontSize: 11, fontWeight: 600, color: '#8b949e', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Score Interpretation</p>
            <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
              {[['≥ 75', '#3fb950', 'Strong'], ['50-74', '#e3b341', 'Adequate'], ['< 50', '#f85149', 'Needs Improvement']].map(([range, color, label]) => (
                <div key={range} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: color }} />
                  <span style={{ fontSize: 12, color: '#8b949e' }}><strong style={{ color }}>{range}</strong> — {label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
