import React, { useState, useEffect, useMemo, useCallback } from 'react'
import {
  AlertTriangle, ChevronDown, ChevronRight, Shield, Zap, Activity,
  Users, Server, Download, BookOpen, CheckCircle, Clock, XCircle,
  Filter, UserCheck, MessageSquare, TrendingDown, Eye
} from 'lucide-react'
import { AlertsSkeleton } from '../components/Skeleton'
import PlaybookViewer from '../components/PlaybookViewer'
import { exportToCSV, exportToJSON } from '../utils/export'

// ─── Severity Badge ───────────────────────────────────────────────────────────
const SeverityBadge = ({ severity }) => {
  const cls = {
    critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium',
    low: 'badge-low', info: 'bg-gray-600/20 text-gray-400 border border-gray-600/30',
  }
  return (
    <span className={`px-2.5 py-1 rounded text-[11px] font-bold uppercase tracking-wider ${cls[severity] || cls.info}`}>
      {severity}
    </span>
  )
}

// ─── Workflow Status Badge ────────────────────────────────────────────────────
const STATUS_CONFIG = {
  new:          { label: 'New',          color: '#e63946', bg: 'rgba(230,57,70,0.12)',  icon: <AlertTriangle className="w-3 h-3" /> },
  investigating:{ label: 'Investigating',color: '#f4a261', bg: 'rgba(244,162,97,0.12)', icon: <Eye className="w-3 h-3" /> },
  resolved:     { label: 'Resolved',     color: '#3fb950', bg: 'rgba(63,185,80,0.12)',  icon: <CheckCircle className="w-3 h-3" /> },
  fp:           { label: 'False Positive',color:'#8b949e', bg: 'rgba(139,148,158,0.12)',icon: <XCircle className="w-3 h-3" /> },
}

const StatusBadge = ({ status }) => {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.new
  return (
    <span style={{ color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.color}40`,
      display:'inline-flex', alignItems:'center', gap:4, padding:'2px 8px', borderRadius:6,
      fontSize:11, fontWeight:600 }}>
      {cfg.icon} {cfg.label}
    </span>
  )
}

// ─── Analysts list ────────────────────────────────────────────────────────────
const ANALYSTS = ['Unassigned', 'Omar B.', 'Analyst 1', 'Analyst 2', 'Analyst 3']

// ─── Status Filter Tabs ───────────────────────────────────────────────────────
const STATUS_FILTERS = [
  { key: 'all',           label: 'All' },
  { key: 'new',           label: 'New' },
  { key: 'investigating', label: 'Investigating' },
  { key: 'resolved',      label: 'Resolved' },
  { key: 'fp',            label: 'False Positive' },
]

// ─── SLA Metrics ─────────────────────────────────────────────────────────────
function SLAMetrics({ alerts, workflow }) {
  const fpCount  = Object.values(workflow).filter(w => w.status === 'fp').length
  const fpRate   = alerts.length ? Math.round((fpCount / alerts.length) * 100) : 0
  const resolved = Object.values(workflow).filter(w => w.status === 'resolved').length
  const MTTI = '4.2 min'
  const MTTR = '23.5 min'

  return (
    <div className="card p-4" style={{ borderTop: '2px solid #457b9d' }}>
      <div className="flex items-center gap-2 mb-3">
        <TrendingDown className="w-4 h-4" style={{ color: '#457b9d' }} />
        <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: '#457b9d' }}>
          SLA Metrics
        </span>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'MTTI', value: MTTI, sub: 'Mean Time to Identify', color: '#f4a261' },
          { label: 'MTTR', value: MTTR, sub: 'Mean Time to Respond', color: '#e63946' },
          { label: 'FP Rate', value: `${fpRate}%`, sub: `${fpCount} false positives`, color: '#8b949e' },
          { label: 'Resolved', value: resolved, sub: `of ${alerts.length} alerts`, color: '#3fb950' },
        ].map(m => (
          <div key={m.label}>
            <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: '#6e7681' }}>{m.label}</p>
            <p className="text-xl font-bold font-mono" style={{ color: m.color }}>{m.value}</p>
            <p className="text-[10px]" style={{ color: '#6e7681' }}>{m.sub}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function Alerts({ alerts = [], incidents = [] }) {
  const [expandedAlert, setExpandedAlert]   = useState(null)
  const [loading, setLoading]               = useState(true)
  const [statusFilter, setStatusFilter]     = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [playbookOpen, setPlaybookOpen]     = useState(false)
  const [playbookTechnique, setPlaybookTechnique] = useState(null)

  // Workflow state: alertId → { status, assignee, note, updatedAt }
  const [workflow, setWorkflow] = useState(() => {
    try { return JSON.parse(localStorage.getItem('ct_alert_workflow') || '{}') }
    catch { return {} }
  })

  // Persist workflow
  useEffect(() => {
    localStorage.setItem('ct_alert_workflow', JSON.stringify(workflow))
  }, [workflow])

  useEffect(() => {
    const t = setTimeout(() => setLoading(false), 400)
    return () => clearTimeout(t)
  }, [])

  // Init workflow for new alerts
  useEffect(() => {
    if (!alerts.length) return
    setWorkflow(prev => {
      const updated = { ...prev }
      alerts.forEach(a => {
        if (!updated[a.alert_id]) {
          updated[a.alert_id] = { status: 'new', assignee: 'Unassigned', note: '', updatedAt: null }
        }
      })
      return updated
    })
  }, [alerts])

  const updateWorkflow = useCallback((alertId, field, value) => {
    setWorkflow(prev => ({
      ...prev,
      [alertId]: { ...prev[alertId], [field]: value, updatedAt: new Date().toISOString() }
    }))
  }, [])

  // Filtered alerts
  const filteredAlerts = useMemo(() => {
    return alerts.filter(a => {
      const wf = workflow[a.alert_id] || { status: 'new' }
      const statusOk = statusFilter === 'all' || wf.status === statusFilter
      const sevOk    = severityFilter === 'all' || a.severity === severityFilter
      return statusOk && sevOk
    })
  }, [alerts, workflow, statusFilter, severityFilter])

  // Counts per status
  const statusCounts = useMemo(() => {
    const counts = { all: alerts.length, new: 0, investigating: 0, resolved: 0, fp: 0 }
    alerts.forEach(a => {
      const s = (workflow[a.alert_id] || {}).status || 'new'
      if (counts[s] !== undefined) counts[s]++
    })
    return counts
  }, [alerts, workflow])

  if (loading) return <AlertsSkeleton />

  if (!alerts.length) {
    return (
      <div className="flex flex-col items-center justify-center h-96 animate-fade-in-up">
        <div className="card p-12 text-center max-w-md">
          <AlertTriangle className="w-16 h-16 mb-4 text-gray-600 mx-auto" />
          <h3 className="text-lg font-semibold text-gray-400 mb-2">Aucune alerte</h3>
          <p className="text-gray-500 text-sm">Lancez une simulation pour générer des alertes de sécurité.</p>
        </div>
      </div>
    )
  }

  const criticalCount = alerts.filter(a => a.severity === 'critical').length
  const highCount     = alerts.filter(a => a.severity === 'high').length
  const mediumCount   = alerts.filter(a => a.severity === 'medium').length

  return (
    <div className="space-y-6 animate-fade-in-up">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl shadow-lg" style={{ background: 'linear-gradient(135deg,#e63946,#c1121f)', boxShadow:'0 4px 15px rgba(230,57,70,0.3)' }}>
            <AlertTriangle className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Security Alerts</h1>
            <p className="text-sm" style={{ color:'#8b949e' }}>
              {alerts.length} alertes · {incidents.length} incidents corrélés
            </p>
          </div>
        </div>

        {/* Export Buttons */}
        <div className="flex gap-2">
          <button
            onClick={() => exportToCSV(filteredAlerts, `alerts_${Date.now()}.csv`)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold transition-colors"
            style={{ background:'#21262d', color:'#8b949e', border:'1px solid #30363d' }}
            onMouseOver={e => e.currentTarget.style.color='#e6edf3'}
            onMouseOut={e => e.currentTarget.style.color='#8b949e'}
          >
            <Download className="w-3.5 h-3.5" /> CSV
          </button>
          <button
            onClick={() => exportToJSON(filteredAlerts, `alerts_${Date.now()}.json`)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold transition-colors"
            style={{ background:'#21262d', color:'#8b949e', border:'1px solid #30363d' }}
            onMouseOver={e => e.currentTarget.style.color='#e6edf3'}
            onMouseOut={e => e.currentTarget.style.color='#8b949e'}
          >
            <Download className="w-3.5 h-3.5" /> JSON
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 stagger-children">
        {[
          { label: 'Total Alerts', value: alerts.length,    color: '#e6edf3', accent: 'transparent' },
          { label: 'Critical',     value: criticalCount,    color: '#f85149', accent: '#f85149' },
          { label: 'High',         value: highCount,        color: '#f4a261', accent: '#f4a261' },
          { label: 'Medium',       value: mediumCount,      color: '#e3b341', accent: '#e3b341' },
          { label: 'Incidents',    value: incidents.length, color: '#457b9d', accent: '#457b9d' },
        ].map(kpi => (
          <div key={kpi.label} className="card p-4" style={{ borderLeft: `2px solid ${kpi.accent}` }}>
            <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color:'#6e7681' }}>{kpi.label}</p>
            <span className="text-2xl font-bold font-mono" style={{ color: kpi.color }}>{kpi.value}</span>
          </div>
        ))}
      </div>

      {/* SLA Metrics */}
      <SLAMetrics alerts={alerts} workflow={workflow} />

      {/* Status Filter Tabs + Severity Filter */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex gap-1 p-1 rounded-lg" style={{ background:'#161b22', border:'1px solid #21262d' }}>
          {STATUS_FILTERS.map(f => {
            const active = statusFilter === f.key
            const cfg = STATUS_CONFIG[f.key]
            return (
              <button
                key={f.key}
                onClick={() => setStatusFilter(f.key)}
                className="px-3 py-1.5 rounded-md text-xs font-semibold transition-all"
                style={{
                  background: active ? (cfg?.bg || 'rgba(230,57,70,0.12)') : 'transparent',
                  color: active ? (cfg?.color || '#e63946') : '#6e7681',
                  border: active ? `1px solid ${cfg?.color || '#e63946'}40` : '1px solid transparent',
                }}
              >
                {f.label}
                <span className="ml-1.5 opacity-60">({statusCounts[f.key] ?? 0})</span>
              </button>
            )
          })}
        </div>

        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5" style={{ color:'#6e7681' }} />
          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            className="text-xs px-3 py-1.5 rounded-lg"
            style={{ background:'#161b22', border:'1px solid #21262d', color:'#e6edf3' }}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="card overflow-hidden">
        <div className="p-4 flex items-center gap-2" style={{ borderBottom:'1px solid #21262d' }}>
          <Zap className="w-4 h-4" style={{ color:'#e63946' }} />
          <h2 className="text-lg font-semibold">Détail des alertes</h2>
          <span className="text-xs font-mono ml-auto" style={{ color:'#6e7681' }}>
            {filteredAlerts.length} / {alerts.length}
          </span>
        </div>

        <table className="data-table">
          <thead>
            <tr>
              <th className="w-8"></th>
              <th>Severity</th>
              <th>Status</th>
              <th>Time</th>
              <th>Rule</th>
              <th>Technique</th>
              <th>Host</th>
              <th>Assignee</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredAlerts.map((a, i) => {
              const wf = workflow[a.alert_id] || { status: 'new', assignee: 'Unassigned', note: '' }
              const isExpanded = expandedAlert === a.alert_id
              return (
                <React.Fragment key={a.alert_id || i}>
                  <tr
                    className="cursor-pointer transition-colors"
                    style={{ background: isExpanded ? '#161b22' : 'transparent' }}
                    onMouseOver={e => !isExpanded && (e.currentTarget.style.background = '#0d1117')}
                    onMouseOut={e => !isExpanded && (e.currentTarget.style.background = 'transparent')}
                    onClick={() => setExpandedAlert(isExpanded ? null : a.alert_id)}
                  >
                    <td className="text-center">
                      {isExpanded
                        ? <ChevronDown className="w-4 h-4 inline" style={{ color:'#6e7681' }} />
                        : <ChevronRight className="w-4 h-4 inline" style={{ color:'#6e7681' }} />}
                    </td>
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td><StatusBadge status={wf.status} /></td>
                    <td className="font-mono text-xs whitespace-nowrap" style={{ color:'#8b949e' }}>
                      {a.timestamp?.split('T')[1]?.slice(0,8) || '--:--:--'}
                    </td>
                    <td className="text-sm font-medium" style={{ color:'#e6edf3' }}>{a.rule_name}</td>
                    <td className="font-mono text-xs" style={{ color:'#e63946' }}>{a.technique_id}</td>
                    <td className="text-xs" style={{ color:'#8b949e' }}>{a.affected_host}</td>
                    <td>
                      <span className="text-xs flex items-center gap-1" style={{ color:'#8b949e' }}>
                        <UserCheck className="w-3 h-3" />
                        {wf.assignee === 'Unassigned' ? <span style={{ color:'#6e7681' }}>—</span> : wf.assignee}
                      </span>
                    </td>
                    <td onClick={e => e.stopPropagation()}>
                      <button
                        title="Playbook"
                        onClick={() => { setPlaybookTechnique(a.technique_id); setPlaybookOpen(true) }}
                        className="p-1.5 rounded-md transition-colors"
                        style={{ background:'#21262d', color:'#457b9d' }}
                        onMouseOver={e => e.currentTarget.style.color='#e6edf3'}
                        onMouseOut={e => e.currentTarget.style.color='#457b9d'}
                      >
                        <BookOpen className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>

                  {/* Expanded Row */}
                  {isExpanded && (
                    <tr>
                      <td colSpan={9} style={{ padding:0 }}>
                        <div style={{ background:'rgba(13,17,23,0.7)', borderTop:'1px solid rgba(230,57,70,0.1)', borderBottom:'1px solid rgba(230,57,70,0.1)', padding:'1.25rem 2rem' }} className="space-y-4">

                          {/* Detail Grid */}
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                            {[
                              { label:'Tactic',    value: a.tactic },
                              { label:'Technique', value: a.technique_name, mono: true, color:'#e63946' },
                              { label:'Hosts',     value: a.affected_hosts?.join(', ') || a.affected_host },
                              { label:'Users',     value: a.affected_users?.join(', ') || '—' },
                            ].map(d => (
                              <div key={d.label} className="card p-3">
                                <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color:'#6e7681' }}>{d.label}</p>
                                <p className={`text-sm ${d.mono ? 'font-mono' : ''}`} style={{ color: d.color || '#e6edf3' }}>{d.value}</p>
                              </div>
                            ))}
                          </div>

                          {/* Workflow Controls */}
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            {/* Status */}
                            <div>
                              <label className="text-[10px] uppercase tracking-wider block mb-1.5" style={{ color:'#6e7681' }}>Status</label>
                              <select
                                value={wf.status}
                                onChange={e => updateWorkflow(a.alert_id, 'status', e.target.value)}
                                className="w-full text-xs px-3 py-2 rounded-lg"
                                style={{ background:'#0d1117', border:'1px solid #30363d', color:'#e6edf3' }}
                                onClick={e => e.stopPropagation()}
                              >
                                {Object.entries(STATUS_CONFIG).map(([k, v]) => (
                                  <option key={k} value={k}>{v.label}</option>
                                ))}
                              </select>
                            </div>
                            {/* Assignee */}
                            <div>
                              <label className="text-[10px] uppercase tracking-wider block mb-1.5" style={{ color:'#6e7681' }}>Assign To</label>
                              <select
                                value={wf.assignee}
                                onChange={e => updateWorkflow(a.alert_id, 'assignee', e.target.value)}
                                className="w-full text-xs px-3 py-2 rounded-lg"
                                style={{ background:'#0d1117', border:'1px solid #30363d', color:'#e6edf3' }}
                                onClick={e => e.stopPropagation()}
                              >
                                {ANALYSTS.map(a => <option key={a}>{a}</option>)}
                              </select>
                            </div>
                            {/* Note */}
                            <div>
                              <label className="text-[10px] uppercase tracking-wider block mb-1.5" style={{ color:'#6e7681' }}>
                                <MessageSquare className="w-3 h-3 inline mr-1" />Note
                              </label>
                              <input
                                type="text"
                                value={wf.note}
                                onChange={e => updateWorkflow(a.alert_id, 'note', e.target.value)}
                                placeholder="Analyst note..."
                                className="w-full text-xs px-3 py-2 rounded-lg"
                                style={{ background:'#0d1117', border:'1px solid #30363d', color:'#e6edf3' }}
                                onClick={e => e.stopPropagation()}
                              />
                            </div>
                          </div>

                          {/* Description + Events */}
                          <div>
                            <p className="text-xs uppercase tracking-wider mb-1" style={{ color:'#6e7681' }}>Description</p>
                            <p className="text-sm" style={{ color:'#c9d1d9' }}>{a.description}</p>
                          </div>

                          {a.matched_events?.length > 0 && (
                            <div>
                              <p className="text-xs uppercase tracking-wider mb-2" style={{ color:'#6e7681' }}>
                                Matched Events ({a.matched_events.length})
                              </p>
                              <div className="space-y-1 max-h-48 overflow-y-auto pr-1">
                                {a.matched_events.slice(0,8).map((e, j) => (
                                  <div key={j} className="card text-xs px-3 py-2 font-mono">
                                    <span style={{ color:'rgba(69,123,157,0.7)' }}>{e.timestamp}</span>
                                    <span className="mx-2" style={{ color:'#30363d' }}>|</span>
                                    <span style={{ color:'#c9d1d9' }}>{e.description}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Playbook Button */}
                          <div>
                            <button
                              onClick={e => { e.stopPropagation(); setPlaybookTechnique(a.technique_id); setPlaybookOpen(true) }}
                              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-colors"
                              style={{ background:'rgba(69,123,157,0.15)', color:'#457b9d', border:'1px solid rgba(69,123,157,0.3)' }}
                              onMouseOver={e => e.currentTarget.style.background='rgba(69,123,157,0.25)'}
                              onMouseOut={e => e.currentTarget.style.background='rgba(69,123,157,0.15)'}
                            >
                              <BookOpen className="w-4 h-4" />
                              Open Response Playbook — {a.technique_id}
                            </button>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Correlated Incidents */}
      {incidents.length > 0 && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5" style={{ color:'#457b9d' }} />
            <h2 className="text-lg font-semibold">Incidents corrélés</h2>
            <span className="text-xs font-mono ml-2 px-2.5 py-0.5 rounded-full" style={{ background:'rgba(69,123,157,0.15)', color:'#457b9d' }}>
              {incidents.length}
            </span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 stagger-children">
            {incidents.map((inc, i) => (
              <div key={i} className="card p-5 transition-colors" style={{ borderLeft:'2px solid rgba(69,123,157,0.4)' }}>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <SeverityBadge severity={inc.severity} />
                    <span className="font-semibold" style={{ color:'#e6edf3' }}>{inc.name}</span>
                  </div>
                  <span className="text-xs font-mono px-2 py-1 rounded" style={{ background:'rgba(139,148,158,0.1)', color:'#8b949e' }}>
                    Confiance: {inc.confidence_score}%
                  </span>
                </div>

                <div className="grid grid-cols-3 gap-3 mt-3">
                  <div className="flex items-center gap-2">
                    <Activity className="w-3.5 h-3.5" style={{ color:'#6e7681' }} />
                    <span className="text-xs" style={{ color:'#8b949e' }}>
                      <strong style={{ color:'#e6edf3' }}>{inc.alert_count}</strong> alertes
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Server className="w-3.5 h-3.5" style={{ color:'#6e7681' }} />
                    <span className="text-xs" style={{ color:'#8b949e' }}>{inc.affected_hosts?.length || 0} hôtes</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Zap className="w-3.5 h-3.5" style={{ color:'#6e7681' }} />
                    <span className="text-xs" style={{ color:'#8b949e' }}>{inc.techniques?.length || 0} techniques</span>
                  </div>
                </div>

                <div className="flex flex-wrap gap-1.5 mt-3">
                  {inc.affected_hosts?.map((host, j) => (
                    <span key={j} className="text-[10px] font-mono px-2 py-0.5 rounded-full" style={{ background:'rgba(139,148,158,0.1)', color:'#c9d1d9', border:'1px solid rgba(139,148,158,0.2)' }}>
                      {host}
                    </span>
                  ))}
                </div>

                <div className="flex flex-wrap gap-1.5 mt-2">
                  {inc.techniques?.map((tech, j) => (
                    <span key={j} className="text-[10px] font-mono px-2 py-0.5 rounded-full" style={{ background:'rgba(230,57,70,0.1)', color:'#e63946', border:'1px solid rgba(230,57,70,0.2)' }}>
                      {tech}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Playbook Viewer Modal */}
      <PlaybookViewer
        isOpen={playbookOpen}
        onClose={() => setPlaybookOpen(false)}
        techniqueId={playbookTechnique}
      />
    </div>
  )
}
