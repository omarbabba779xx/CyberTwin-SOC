import React, { useState, useEffect } from 'react'
import { Cpu, RefreshCw, AlertTriangle, User, Clock, Activity } from 'lucide-react'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const SEV_COLOR = { critical: '#f85149', high: '#ffa657', medium: '#e3b341', low: '#3fb950' }
const SEV_BG = { critical: 'rgba(248,81,73,0.1)', high: 'rgba(255,166,87,0.1)', medium: 'rgba(227,179,65,0.1)', low: 'rgba(63,185,80,0.1)' }

function AnomalyCard({ anomaly }) {
  const sev = anomaly.severity || 'medium'
  const color = SEV_COLOR[sev] || '#8b949e'
  const bg = SEV_BG[sev] || 'rgba(99,110,123,0.08)'

  return (
    <div style={{
      padding: '14px 16px', borderRadius: 8,
      backgroundColor: 'var(--bg-card, #161b22)',
      border: `1px solid ${color}33`,
      borderLeft: `3px solid ${color}`,
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <span style={{
              fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 99,
              backgroundColor: bg, color, border: `1px solid ${color}44`,
              textTransform: 'uppercase',
            }}>
              {sev}
            </span>
            <span style={{ fontSize: 11, color: '#6e7681', fontFamily: 'monospace' }}>
              {anomaly.anomaly_type?.replace('_', ' ') || 'anomaly'}
            </span>
          </div>
          <p style={{ fontSize: 13, color: 'var(--text-primary, #e6edf3)', margin: '0 0 8px', fontWeight: 500 }}>
            {anomaly.description || anomaly.reason || 'Anomalous activity detected'}
          </p>
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
            {anomaly.user && (
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: '#8b949e' }}>
                <User style={{ width: 11, height: 11 }} /> {anomaly.user}
              </span>
            )}
            {anomaly.src_host && (
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: '#8b949e' }}>
                <Activity style={{ width: 11, height: 11 }} /> {anomaly.src_host}
              </span>
            )}
            {anomaly.timestamp && (
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: '#8b949e' }}>
                <Clock style={{ width: 11, height: 11 }} /> {anomaly.timestamp?.slice(0, 19).replace('T', ' ')}
              </span>
            )}
          </div>
        </div>
        {anomaly.anomaly_score != null && (
          <div style={{ textAlign: 'center', minWidth: 52 }}>
            <p style={{ fontSize: 10, color: '#6e7681', margin: '0 0 2px' }}>Score</p>
            <p style={{ fontSize: 20, fontWeight: 800, color, margin: 0 }}>
              {Math.round(Math.abs(anomaly.anomaly_score) * 100)}
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

export default function Anomaly({ scenarioId, token }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('all')

  const load = () => {
    if (!scenarioId) return
    setLoading(true)
    setError(null)
    fetch(`${API}/api/results/${scenarioId}/anomalies`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => r.ok ? r.json() : Promise.reject(r.statusText))
      .then(setData)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [scenarioId])

  const anomalies = data?.anomalies || []
  const filtered = filter === 'all'
    ? anomalies
    : anomalies.filter((a) => a.severity === filter)

  const counts = anomalies.reduce((acc, a) => {
    acc[a.severity || 'medium'] = (acc[a.severity || 'medium'] || 0) + 1
    return acc
  }, {})

  if (!scenarioId) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60vh', color: '#6e7681' }}>
      <div style={{ textAlign: 'center' }}>
        <Cpu style={{ width: 48, height: 48, opacity: 0.3, margin: '0 auto 12px', display: 'block' }} />
        <p>Run a simulation to detect anomalies.</p>
      </div>
    </div>
  )

  return (
    <div style={{ padding: '24px 28px', maxWidth: 900 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary, #e6edf3)', margin: 0 }}>
            ML Anomaly Detection
          </h1>
          <p style={{ fontSize: 13, color: '#6e7681', marginTop: 4 }}>
            IsolationForest + UEBA behavioral analysis
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

      {/* Stats row */}
      {data && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12, marginBottom: 24 }}>
          {[
            { label: 'Total', value: data.total, color: '#8b949e' },
            { label: 'Critical', value: counts.critical || 0, color: '#f85149' },
            { label: 'High', value: counts.high || 0, color: '#ffa657' },
            { label: 'Medium', value: counts.medium || 0, color: '#e3b341' },
            { label: 'Low', value: counts.low || 0, color: '#3fb950' },
          ].map(({ label, value, color }) => (
            <div key={label} style={{
              padding: '14px 16px', borderRadius: 8, textAlign: 'center',
              backgroundColor: 'var(--bg-card, #161b22)', border: '1px solid var(--border, #21262d)',
            }}>
              <p style={{ fontSize: 22, fontWeight: 800, color, margin: '0 0 4px' }}>{value}</p>
              <p style={{ fontSize: 11, color: '#6e7681', margin: 0 }}>{label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Filter tabs */}
      {data && (
        <div style={{ display: 'flex', gap: 6, marginBottom: 18, flexWrap: 'wrap' }}>
          {['all', 'critical', 'high', 'medium', 'low'].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              style={{
                padding: '5px 12px', borderRadius: 6, fontSize: 12, fontWeight: 600,
                cursor: 'pointer', border: '1px solid',
                backgroundColor: filter === f
                  ? (SEV_COLOR[f] || 'rgba(99,110,123,0.3)') + '22'
                  : 'transparent',
                borderColor: filter === f
                  ? (SEV_COLOR[f] || '#6e7681') + '55'
                  : 'rgba(99,110,123,0.25)',
                color: filter === f ? (SEV_COLOR[f] || '#e6edf3') : '#6e7681',
              }}
            >
              {f === 'all' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1)}
              {f !== 'all' && counts[f] ? ` (${counts[f]})` : ''}
            </button>
          ))}
        </div>
      )}

      {error && (
        <div style={{ padding: 14, borderRadius: 8, backgroundColor: 'rgba(248,81,73,0.1)', border: '1px solid rgba(248,81,73,0.25)', color: '#f85149', marginBottom: 20 }}>
          {error}
        </div>
      )}

      {loading && (
        <div style={{ textAlign: 'center', padding: 60, color: '#6e7681' }}>Analyzing logs…</div>
      )}

      {data && !loading && filtered.length === 0 && (
        <div style={{ textAlign: 'center', padding: 48, color: '#6e7681' }}>
          <Cpu style={{ width: 36, height: 36, opacity: 0.3, margin: '0 auto 10px', display: 'block' }} />
          No anomalies for the selected filter.
        </div>
      )}

      {data && !loading && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {filtered.map((a, i) => (
            <AnomalyCard key={i} anomaly={a} />
          ))}
        </div>
      )}
    </div>
  )
}
