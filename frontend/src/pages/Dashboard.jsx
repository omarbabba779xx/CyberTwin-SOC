import React, { useState, useEffect } from 'react'
import {
  Shield, AlertTriangle, Activity, Clock, Target, User, Globe,
  Zap, FileText, Search, Brain, Grid3X3, ArrowRight, Eye, Gauge,
  TrendingUp, ChevronDown, ChevronUp
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell
} from 'recharts'
import { DashboardSkeleton } from '../components/Skeleton'

// ─── Severity Colors (new palette) ───
const SEV_COLORS = {
  critical: '#f85149',
  high: '#f4a261',
  medium: '#457b9d',
  low: '#3fb950',
  info: '#6e7681',
}

// ─── Threat Actor Metadata ───
const THREAT_ACTOR_META = {
  'APT29': { flag: '\u{1F1F7}\u{1F1FA}', brief: 'Russian state-sponsored espionage group linked to SVR, known for SolarWinds and phishing campaigns.' },
  'APT28': { flag: '\u{1F1F7}\u{1F1FA}', brief: 'Russian military intelligence (GRU) group known for sophisticated lateral movement and credential theft.' },
  'Lazarus': { flag: '\u{1F1F0}\u{1F1F5}', brief: 'North Korean state-sponsored group known for financial theft and destructive attacks.' },
  'APT41': { flag: '\u{1F1E8}\u{1F1F3}', brief: 'Chinese dual espionage and cybercrime group targeting healthcare, telecom, and tech sectors.' },
}

function getActorMeta(name) {
  if (!name) return null
  for (const [key, meta] of Object.entries(THREAT_ACTOR_META)) {
    if (name.includes(key)) return { key, ...meta }
  }
  return { key: name, flag: '\u{1F3F4}', brief: 'Threat actor profile unavailable.' }
}

// ─── Animated Counter ───
function AnimatedNumber({ value, duration = 1000 }) {
  const [current, setCurrent] = useState(0)
  useEffect(() => {
    if (!value) return
    let start = 0
    const step = value / (duration / 16)
    const timer = setInterval(() => {
      start += step
      if (start >= value) { setCurrent(value); clearInterval(timer) }
      else setCurrent(Math.round(start))
    }, 16)
    return () => clearInterval(timer)
  }, [value])
  return current
}

// ─── Risk badge class ───
function riskBadgeClass(level) {
  switch (level) {
    case 'Low': return 'badge-low'
    case 'Medium': return 'badge-medium'
    case 'High': return 'badge-high'
    case 'Critical': return 'badge-critical'
    default: return 'badge-low'
  }
}

// ─── Custom Pie Label ───
function renderCustomLabel({ cx, cy, midAngle, outerRadius, name, value, percent }) {
  const RADIAN = Math.PI / 180
  const radius = outerRadius + 25
  const x = cx + radius * Math.cos(-midAngle * RADIAN)
  const y = cy + radius * Math.sin(-midAngle * RADIAN)
  if (percent < 0.05) return null
  return (
    <text x={x} y={y} fill="#94a3b8" textAnchor={x > cx ? 'start' : 'end'} dominantBaseline="central" fontSize={11}>
      {name} ({value})
    </text>
  )
}

// ─── Custom Tooltip ───
function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="card px-3 py-2 text-xs shadow-xl">
      <p className="text-secondary font-medium">{label || payload[0].name}</p>
      <p style={{ color: '#e63946' }} className="font-bold">{payload[0].value}</p>
    </div>
  )
}

// ─── KPI Card ───
function KPICard({ title, value, suffix = '', accentClass, progress, delay = 0 }) {
  return (
    <div className={`card ${accentClass} p-5 relative overflow-hidden`} style={{ animationDelay: `${delay}ms` }}>
      <p className="text-secondary text-xs uppercase tracking-wider font-medium mb-3">{title}</p>
      <p className="stat-value text-2xl font-bold text-white">
        <AnimatedNumber value={value} />{suffix}
      </p>
      {progress !== undefined && (
        <div className="progress-bar mt-3">
          <div className="progress-bar-fill" style={{ width: `${Math.min(progress, 100)}%` }} />
        </div>
      )}
    </div>
  )
}

// ─── Empty State (No Simulation) ───
function EmptyState({ t }) {
  const features = [
    { title: '4 Scenarios', desc: 'APT29, APT28, Lazarus, APT41', accent: 'card-accent-red' },
    { title: '34 Detection Rules', desc: 'Sigma-based detection engine', accent: 'card-accent-amber' },
    { title: 'AI Analysis', desc: 'Automated threat assessment', accent: 'card-accent-steel' },
    { title: 'MITRE ATT&CK', desc: 'Full framework mapping', accent: 'card-accent-teal' },
  ]

  return (
    <div className="flex flex-col items-center justify-center h-full animate-fade-in-up">
      {/* Hero */}
      <div className="text-center mb-12">
        <div className="relative inline-block mb-6">
          <Shield className="w-16 h-16" style={{ color: '#e63946' }} />
        </div>
        <h2 className="text-3xl font-bold text-white mb-3">
          {t('dashboard.empty.title')}
        </h2>
        <p className="text-gray-400 text-base mb-2">{t('dashboard.empty.subtitle')}</p>
        <p className="text-gray-500 text-sm flex items-center justify-center gap-2">
          Launch from the Scenarios page
          <ArrowRight className="w-4 h-4" style={{ color: '#e63946' }} />
        </p>
      </div>

      {/* Feature Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 max-w-4xl w-full stagger">
        {features.map((f, i) => (
          <div key={i} className={`card ${f.accent} p-5 text-center`}>
            <h3 className="text-sm font-semibold text-white mb-1">{f.title}</h3>
            <p className="text-xs text-secondary">{f.desc}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Main Dashboard ───
export default function Dashboard({ result, environment, i18n }) {
  const t = i18n?.t || ((k) => k)
  const [expandedAlert, setExpandedAlert] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const timer = setTimeout(() => setLoading(false), 600)
    return () => clearTimeout(timer)
  }, [])

  if (loading) return <DashboardSkeleton />
  if (!result) return <EmptyState t={t} />

  const { scores, alerts, incidents, logs_statistics, scenario } = result
  const stats = logs_statistics || {}
  const actor = scenario?.threat_actor

  // Chart data
  const severityData = Object.entries(stats.by_severity || {}).map(([k, v]) => ({
    name: k.charAt(0).toUpperCase() + k.slice(1),
    value: v,
    fill: SEV_COLORS[k] || '#6e7681'
  }))

  const sourceData = Object.entries(stats.by_type || {}).map(([k, v]) => ({ name: k, value: v }))

  // Accent class for risk level KPI
  const riskAccent = scores.risk_level === 'Critical' || scores.risk_level === 'High'
    ? 'card-accent-red' : 'card-accent-amber'

  return (
    <div className="space-y-6 animate-fade-in-up">
      {/* ── Header ── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">{t('dashboard.title')}</h1>
          <div className="flex items-center gap-3 mt-1.5">
            <p className="text-gray-400 text-sm">
              Scenario: <span style={{ color: '#e63946' }} className="font-medium">{scenario?.name}</span>
            </p>
            {actor && (
              <span className="text-xs px-2 py-0.5 rounded-full font-semibold" style={{ background: 'rgba(230,57,70,0.1)', color: '#e63946', border: '1px solid rgba(230,57,70,0.2)' }}>
                {getActorMeta(actor.name)?.flag} {actor.name}
              </span>
            )}
          </div>
        </div>
        <span className={`px-4 py-2 rounded-xl text-sm font-bold ${riskBadgeClass(scores.risk_level)}`}>
          Risk: {scores.risk_level}
        </span>
      </div>

      {/* ── KPI Cards (3x2) ── */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-4 stagger">
        <KPICard
          title={t('dashboard.overallScore')}
          value={scores.overall_score}
          suffix="%"
          accentClass="card-accent-red"
          progress={scores.overall_score}
          delay={0}
        />
        <KPICard
          title={t('dashboard.detectionRate')}
          value={scores.detection_score}
          suffix="%"
          accentClass="card-accent-amber"
          progress={scores.detection_score}
          delay={50}
        />
        <KPICard
          title={t('dashboard.coverage')}
          value={scores.coverage_score}
          suffix="%"
          accentClass="card-accent-steel"
          progress={scores.coverage_score}
          delay={100}
        />
        <KPICard
          title={t('dashboard.visibility')}
          value={scores.visibility_score}
          suffix="%"
          accentClass="card-accent-teal"
          progress={scores.visibility_score}
          delay={150}
        />
        <KPICard
          title={t('dashboard.responseTime')}
          value={scores.response_score}
          suffix="%"
          accentClass="card-accent-teal"
          progress={scores.response_score}
          delay={200}
        />
        <div className={`card ${riskAccent} p-5 relative overflow-hidden`} style={{ animationDelay: '250ms' }}>
          <p className="text-secondary text-xs uppercase tracking-wider font-medium mb-3">{t('dashboard.riskLevel')}</p>
          <div className="mt-1">
            <span className={`text-lg font-bold px-3 py-1 rounded-lg ${riskBadgeClass(scores.risk_level)}`}>
              {scores.risk_level}
            </span>
          </div>
          <p className="text-secondary text-xs mt-2">Maturity: {scores.maturity_level}</p>
        </div>
      </div>

      {/* ── SLA Metrics Strip ── */}
      <div className="card p-4" style={{ borderLeft:'3px solid #457b9d' }}>
        <div className="flex flex-wrap items-center justify-between gap-4">
          <span className="text-xs font-semibold uppercase tracking-wider" style={{ color:'#457b9d' }}>
            SOC Operational Metrics
          </span>
          <div className="flex flex-wrap gap-6">
            {[
              { label:'MTTI', value:'4.2 min', icon:'⚡', color:'#f4a261' },
              { label:'MTTR', value:'23.5 min', icon:'🔧', color:'#e63946' },
              { label:'Alerts/hr', value: Math.max(1, Math.round(alerts.length / 1.5)), icon:'🔔', color:'#3fb950' },
              { label:'FP Rate', value:'8%', icon:'❌', color:'#8b949e' },
              { label:'Incidents', value: incidents.length, icon:'🚨', color:'#e63946' },
            ].map(m => (
              <div key={m.label} className="text-center">
                <p className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color:'#6e7681' }}>
                  {m.icon} {m.label}
                </p>
                <p className="text-base font-bold font-mono" style={{ color: m.color }}>{m.value}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Charts Row ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 stagger">
        {/* Severity Distribution */}
        <div className="card p-6">
          <h3 className="text-sm font-semibold mb-4 text-gray-300 uppercase tracking-wider flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" style={{ color: '#f4a261' }} />
            {t('dashboard.severityDistribution')}
          </h3>
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={90}
                dataKey="value"
                nameKey="name"
                label={renderCustomLabel}
                stroke="rgba(0,0,0,0.3)"
                strokeWidth={2}
              >
                {severityData.map((entry, i) => (
                  <Cell key={i} fill={entry.fill} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Log Sources */}
        <div className="card p-6">
          <h3 className="text-sm font-semibold mb-4 text-gray-300 uppercase tracking-wider flex items-center gap-2">
            <Activity className="w-4 h-4" style={{ color: '#e63946' }} />
            {t('dashboard.logSources')}
          </h3>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={sourceData} layout="vertical">
              <XAxis type="number" stroke="#374151" fontSize={11} tickLine={false} axisLine={false} />
              <YAxis type="category" dataKey="name" stroke="#6b7280" fontSize={11} width={100} tickLine={false} axisLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="value" fill="#e63946" radius={[0, 6, 6, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ── Threat Actor + Executive Summary ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 stagger">
        {/* Threat Actor Card */}
        {scenario?.threat_actor && (() => {
          const meta = getActorMeta(actor.name)
          return (
            <div className="card card-accent-red p-6">
              <h3 className="text-sm font-semibold mb-4 flex items-center gap-2 text-gray-300 uppercase tracking-wider">
                <User className="w-4 h-4" style={{ color: '#e63946' }} />
                {t('dashboard.threatActor')}
              </h3>
              <div className="flex items-center gap-3 mb-3">
                <span className="text-3xl">{meta.flag}</span>
                <div>
                  <h4 className="text-xl font-bold text-white">{actor.name}</h4>
                  {actor.aliases && (
                    <p className="text-xs text-secondary">
                      aka {actor.aliases.slice(0, 3).join(', ')}
                    </p>
                  )}
                </div>
              </div>
              <div className="flex flex-wrap gap-2 text-xs mb-3">
                <span className="px-2.5 py-1 rounded-lg text-gray-300 flex items-center gap-1.5" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <Globe className="w-3 h-3" style={{ color: '#457b9d' }} /> {actor.origin || 'Unknown'}
                </span>
              </div>
              <p className="text-sm text-gray-400 leading-relaxed">{meta.brief}</p>
            </div>
          )
        })()}

        {/* Executive Summary */}
        {(() => {
          const phases = scenario?.phases || []
          const totalPhases = phases.length
          const detectedAlerts = alerts?.length || 0
          const tactics = (alerts || []).map(a => a.tactic).filter(Boolean)
          const topTactic = tactics.length > 0
            ? Object.entries(tactics.reduce((acc, t) => { acc[t] = (acc[t] || 0) + 1; return acc }, {}))
                .sort((a, b) => b[1] - a[1])[0][0]
            : 'N/A'

          const riskExplanations = {
            'Low': 'Defenses effectively contained the simulated threat with minimal gaps.',
            'Medium': 'Some attack phases went undetected. Review detection rules for coverage gaps.',
            'High': 'Significant detection gaps identified. Immediate remediation recommended.',
            'Critical': 'Most attack phases bypassed defenses. Critical posture improvements required.',
          }

          const summaryItems = [
            { label: 'Attack Phase Coverage', value: `${detectedAlerts > 0 ? Math.min(detectedAlerts, totalPhases) : 0} / ${totalPhases} phases` },
            { label: 'Primary Attack Vector', value: topTactic },
            { label: 'Detection Score', value: `${scores.detection_score}%` },
            { label: 'Risk Assessment', value: scores.risk_level, sub: riskExplanations[scores.risk_level] },
          ]

          return (
            <div className="card card-accent-amber p-6">
              <h3 className="text-sm font-semibold mb-4 flex items-center gap-2 text-gray-300 uppercase tracking-wider">
                <FileText className="w-4 h-4" style={{ color: '#f4a261' }} />
                {t('dashboard.executiveSummary')}
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {summaryItems.map((item, i) => (
                  <div key={i} className="p-3 rounded-lg" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.04)' }}>
                    <p className="text-secondary text-xs uppercase tracking-wider mb-1.5 font-medium">{item.label}</p>
                    <p className="text-base font-bold text-white">{item.value}</p>
                    {item.sub && <p className="text-secondary text-xs mt-1">{item.sub}</p>}
                  </div>
                ))}
              </div>
            </div>
          )
        })()}
      </div>

      {/* ── Recent Alerts Table ── */}
      <div className="card p-6">
        <h3 className="text-sm font-semibold mb-4 text-gray-300 uppercase tracking-wider flex items-center gap-2">
          <Zap className="w-4 h-4" style={{ color: '#f4a261' }} />
          {t('dashboard.recentAlerts')}
          <span className="ml-auto text-xs text-secondary font-normal normal-case tracking-normal">
            {(alerts || []).length} total
          </span>
        </h3>
        <div className="overflow-x-auto">
          <table className="data-table w-full text-sm">
            <thead>
              <tr>
                <th className="text-left py-3 px-4 text-xs uppercase tracking-wider font-semibold text-secondary">Severity</th>
                <th className="text-left py-3 px-4 text-xs uppercase tracking-wider font-semibold text-secondary">Rule</th>
                <th className="text-left py-3 px-4 text-xs uppercase tracking-wider font-semibold text-secondary">Tactic</th>
                <th className="text-left py-3 px-4 text-xs uppercase tracking-wider font-semibold text-secondary">Technique</th>
                <th className="text-left py-3 px-4 text-xs uppercase tracking-wider font-semibold text-secondary">Host</th>
                <th className="text-left py-3 px-4 text-xs uppercase tracking-wider font-semibold text-secondary"></th>
              </tr>
            </thead>
            <tbody>
              {(alerts || []).slice(0, 10).map((a, i) => (
                <React.Fragment key={i}>
                  <tr
                    className="border-b hover:bg-white/[0.02] cursor-pointer transition-colors"
                    style={{ borderColor: '#21262d' }}
                    onClick={() => setExpandedAlert(expandedAlert === i ? null : i)}
                  >
                    <td className="py-2.5 px-4">
                      <span className={`px-2 py-0.5 rounded-md text-xs font-bold uppercase ${
                        a.severity === 'critical' ? 'badge-critical' :
                        a.severity === 'high' ? 'badge-high' :
                        a.severity === 'medium' ? 'badge-medium' :
                        'badge-low'
                      }`}>{a.severity}</span>
                    </td>
                    <td className="py-2.5 px-4 text-gray-300 text-sm">{a.rule_name}</td>
                    <td className="py-2.5 px-4 text-gray-400 text-sm">{a.tactic}</td>
                    <td className="py-2.5 px-4">
                      <span className="font-mono text-xs px-1.5 py-0.5 rounded" style={{ color: '#e63946', background: 'rgba(230,57,70,0.06)', border: '1px solid rgba(230,57,70,0.1)' }}>
                        {a.technique_id}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-gray-400 text-sm">{a.affected_host}</td>
                    <td className="py-2.5 px-4">
                      {expandedAlert === i
                        ? <ChevronUp className="w-3.5 h-3.5 text-gray-500" />
                        : <ChevronDown className="w-3.5 h-3.5 text-gray-500" />
                      }
                    </td>
                  </tr>
                  {expandedAlert === i && (
                    <tr>
                      <td colSpan={6} className="px-4 py-3" style={{ background: 'rgba(255,255,255,0.02)' }}>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                          {a.description && (
                            <div className="col-span-2">
                              <span className="text-secondary">Description: </span>
                              <span className="text-gray-300">{a.description}</span>
                            </div>
                          )}
                          {a.source_ip && (
                            <div>
                              <span className="text-secondary">Source IP: </span>
                              <span className="text-gray-300 font-mono">{a.source_ip}</span>
                            </div>
                          )}
                          {a.dest_ip && (
                            <div>
                              <span className="text-secondary">Dest IP: </span>
                              <span className="text-gray-300 font-mono">{a.dest_ip}</span>
                            </div>
                          )}
                          {a.timestamp && (
                            <div>
                              <span className="text-secondary">Timestamp: </span>
                              <span className="text-gray-300">{a.timestamp}</span>
                            </div>
                          )}
                          {a.phase && (
                            <div>
                              <span className="text-secondary">Phase: </span>
                              <span className="text-gray-300">{a.phase}</span>
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
