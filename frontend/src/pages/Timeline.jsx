import React, { useState, useMemo, useRef } from 'react'
import { Clock, Search, Eye, EyeOff, ChevronDown, ChevronRight, Activity, Zap, Shield, Download } from 'lucide-react'
import { exportToCSV, exportToJSON } from '../utils/export'

const tacticColors = {
  'initial-access': '#e63946', 'execution': '#ef4444', 'persistence': '#457b9d',
  'privilege-escalation': '#f97316', 'defense-evasion': '#457b9d', 'credential-access': '#ec4899',
  'discovery': '#14b8a6', 'lateral-movement': '#f59e0b', 'collection': '#e63946',
  'command-and-control': '#64748b', 'exfiltration': '#eab308', 'impact': '#dc2626',
  'reconnaissance': '#e63946', 'resource-development': '#457b9d',
}
const getTacticColor = (tactic) => tacticColors[tactic?.toLowerCase().replace(/\s+/g, '-')] || '#64748b'

const severityIcons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' }

export default function Timeline({ timeline = [], scenario }) {
  const [filter, setFilter] = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [selectedPhase, setSelectedPhase] = useState(null)
  const [expandedEvent, setExpandedEvent] = useState(null)
  const [showCount, setShowCount] = useState(100)
  const listRef = useRef(null)

  const phases = scenario?.phases || []

  if (!timeline.length) {
    return (
      <div className="flex items-center justify-center min-h-[60vh] animate-fade-in-up">
        <div className="card p-12 text-center max-w-md">
          <div className="w-16 h-16 rounded-2xl bg-[#457b9d]/10 border border-[#e63946]/20 flex items-center justify-center mx-auto mb-4">
            <Clock className="w-8 h-8 text-[#e63946]" />
          </div>
          <h2 className="text-xl font-bold text-white mb-2">Attack Timeline</h2>
          <p className="text-gray-400 text-sm">Run a simulation to see the attack timeline with detailed event tracking and phase analysis.</p>
        </div>
      </div>
    )
  }

  // Filter logic
  const filtered = useMemo(() => {
    let f = timeline
    if (filter === 'malicious') f = f.filter(e => e.is_malicious)
    if (filter === 'benign') f = f.filter(e => !e.is_malicious)
    if (severityFilter !== 'all') f = f.filter(e => e.severity === severityFilter)
    if (selectedPhase !== null) f = f.filter(e => {
      const phase = phases[selectedPhase]
      return phase && e.technique_id && (e.technique_id === phase.technique_id || e.technique_id.startsWith(phase.technique_id))
    })
    if (search) {
      const q = search.toLowerCase()
      f = f.filter(e => (e.description || '').toLowerCase().includes(q) || (e.src_host || '').toLowerCase().includes(q) || (e.user || '').toLowerCase().includes(q))
    }
    return f
  }, [timeline, filter, severityFilter, selectedPhase, search, phases])

  const display = filtered.slice(0, showCount)

  // Stats
  const malCount = timeline.filter(e => e.is_malicious).length
  const benCount = timeline.length - malCount
  const malPct = Math.round((malCount / timeline.length) * 100)

  // Time span
  const timestamps = timeline.filter(e => e.timestamp).map(e => new Date(e.timestamp).getTime()).filter(t => !isNaN(t))
  const timeSpan = timestamps.length >= 2
    ? `${Math.round((Math.max(...timestamps) - Math.min(...timestamps)) / 60000)} min`
    : 'N/A'

  return (
    <div className="space-y-6 animate-fade-in-up">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-2xl flex items-center justify-center" style={{ background:'rgba(69,123,157,0.1)', border:'1px solid rgba(230,57,70,0.2)' }}>
            <Clock className="w-6 h-6 text-[#e63946]" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Attack Timeline</h1>
            <p className="text-sm mt-0.5" style={{ color:'#8b949e' }}>
              {filtered.length} events shown of {timeline.length} total
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => exportToCSV(filtered.slice(0, showCount), `timeline_${Date.now()}.csv`)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold transition-colors"
            style={{ background:'#21262d', color:'#8b949e', border:'1px solid #30363d' }}
            onMouseOver={e => e.currentTarget.style.color='#e6edf3'}
            onMouseOut={e => e.currentTarget.style.color='#8b949e'}
          >
            <Download className="w-3.5 h-3.5" /> CSV
          </button>
          <button
            onClick={() => exportToJSON(filtered, `timeline_full_${Date.now()}.json`)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold transition-colors"
            style={{ background:'#21262d', color:'#8b949e', border:'1px solid #30363d' }}
            onMouseOver={e => e.currentTarget.style.color='#e6edf3'}
            onMouseOut={e => e.currentTarget.style.color='#8b949e'}
          >
            <Download className="w-3.5 h-3.5" /> JSON
          </button>
        </div>
      </div>

      {/* Stats Bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 stagger-children">
        <div className="card p-4 text-center">
          <p className="stat-number text-[#e63946]">{timeline.length}</p>
          <p className="text-xs text-gray-500 mt-1">Total Events</p>
        </div>
        <div className="card p-4 text-center">
          <p className="stat-number text-red-400">{malCount}</p>
          <p className="text-xs text-gray-500 mt-1">Malicious</p>
        </div>
        <div className="card p-4 text-center">
          <p className="stat-number text-green-400">{benCount}</p>
          <p className="text-xs text-gray-500 mt-1">Benign</p>
        </div>
        <div className="card p-4">
          <div className="flex justify-between text-xs text-gray-500 mb-2">
            <span>Malicious Ratio</span>
            <span className="font-mono text-red-400">{malPct}%</span>
          </div>
          <div className="w-full h-3 bg-gray-800 rounded-full overflow-hidden">
            <div className="h-full bg-gradient-to-r from-red-500 to-red-600 rounded-full transition-all duration-1000" style={{ width: `${malPct}%` }} />
          </div>
          <div className="flex justify-between text-xs text-gray-600 mt-1.5">
            <span>Time span: {timeSpan}</span>
          </div>
        </div>
      </div>

      {/* Attack Phase Overview */}
      {phases.length > 0 && (
        <div className="card p-6">
          <div className="flex items-center gap-3 mb-4">
            <Zap className="w-5 h-5 text-[#457b9d]" />
            <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wide">Attack Kill Chain</h3>
          </div>
          <div className="space-y-2 stagger-children">
            {phases.map((phase, i) => {
              const color = getTacticColor(phase.tactic)
              const isSelected = selectedPhase === i
              const stealthOpacity = phase.stealth_level === 'high' ? 0.6 : phase.stealth_level === 'low' ? 1 : 0.8
              const phaseMalEvents = timeline.filter(e => e.is_malicious && e.technique_id && (e.technique_id === phase.technique_id || e.technique_id.startsWith(phase.technique_id))).length
              const barWidth = Math.max(10, Math.min(100, (phaseMalEvents / Math.max(malCount, 1)) * 100 * phases.length))

              return (
                <button key={i}
                  onClick={() => setSelectedPhase(isSelected ? null : i)}
                  className="w-full text-left group"
                >
                  <div className={`flex items-center gap-3 p-3 rounded-lg border transition-all ${
                    isSelected ? 'border-[#e63946]/50 bg-[#457b9d]/10' : 'border-transparent hover:border-gray-700 hover:bg-gray-800/50'
                  }`}>
                    <div className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
                      style={{ background: `${color}22`, color, border: `2px solid ${color}` }}>
                      {i + 1}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-sm text-gray-200 truncate">{phase.name || phase.technique_name}</span>
                        <span className="text-xs font-mono px-1.5 py-0.5 rounded" style={{ background: `${color}22`, color }}>{phase.technique_id}</span>
                        {phase.stealth_level && (
                          <span className="text-xs text-gray-500 flex items-center gap-1">
                            {phase.stealth_level === 'high' ? <EyeOff size={12} /> : <Eye size={12} />}
                            {phase.stealth_level}
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-gray-500 mt-1">{phase.tactic}</div>
                    </div>
                    <div className="w-32 shrink-0">
                      <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                        <div className="h-full rounded-full transition-all duration-700"
                          style={{ width: `${barWidth}%`, background: color, opacity: stealthOpacity }} />
                      </div>
                      <div className="text-xs text-gray-600 text-right mt-0.5">{phaseMalEvents} events</div>
                    </div>
                  </div>
                </button>
              )
            })}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="card p-4">
        <div className="flex flex-wrap gap-3 items-center">
          <div className="relative flex-1 max-w-xs">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search events..."
              className="w-full pl-9 pr-3 py-2 bg-gray-800/50 border border-gray-700 rounded-lg text-sm text-gray-300 focus:outline-none focus:border-[#e63946] transition-colors"
            />
          </div>
          <div className="flex gap-1">
            {['all', 'malicious', 'benign'].map(f => (
              <button key={f} onClick={() => setFilter(f)}
                className={`px-3 py-2 rounded-lg text-xs font-medium transition ${
                  filter === f
                    ? (f === 'malicious' ? 'bg-red-600/20 text-red-400 border border-red-600/30'
                      : f === 'benign' ? 'bg-green-600/20 text-green-400 border border-green-600/30'
                      : 'bg-[#457b9d]/20 text-[#e63946] border border-[#e63946]/30')
                    : 'bg-gray-800 text-gray-400 hover:bg-gray-700 border border-transparent'
                }`}>{f === 'all' ? 'All' : f === 'malicious' ? 'Malicious' : 'Benign'}</button>
            ))}
          </div>
          <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}
            className="bg-gray-800/50 text-gray-300 text-xs rounded-lg px-3 py-2 border border-gray-700 focus:border-[#e63946] transition-colors">
            <option value="all">All severities</option>
            {['critical', 'high', 'medium', 'low', 'info'].map(s => (
              <option key={s} value={s}>{severityIcons[s]} {s}</option>
            ))}
          </select>
          {selectedPhase !== null && (
            <button onClick={() => setSelectedPhase(null)}
              className="px-3 py-2 rounded-lg text-xs bg-[#457b9d]/20 text-[#457b9d] border border-[#457b9d]/30 flex items-center gap-1">
              Phase {selectedPhase + 1} <XIcon size={12} />
            </button>
          )}
        </div>
      </div>

      {/* Event Stream */}
      <div className="card overflow-hidden" ref={listRef}>
        <div className="divide-y divide-gray-800/50">
          {display.map((event, i) => {
            const isExpanded = expandedEvent === i
            return (
              <div key={i}
                className={`px-4 py-3 cursor-pointer transition-all ${
                  event.is_malicious ? 'hover:bg-red-600/5 border-l-2 border-l-red-500' : 'hover:bg-gray-800/30 border-l-2 border-l-transparent'
                } ${isExpanded ? 'bg-gray-800/30' : ''}`}
                onClick={() => setExpandedEvent(isExpanded ? null : i)}>
                <div className="flex items-center gap-3">
                  <div className="shrink-0 relative">
                    <div className={`w-3 h-3 rounded-full ${
                      event.is_malicious ? 'bg-red-500' :
                      event.severity === 'critical' ? 'bg-red-500' :
                      event.severity === 'high' ? 'bg-orange-500' :
                      event.severity === 'medium' ? 'bg-yellow-500' :
                      event.severity === 'low' ? 'bg-[#457b9d]' : 'bg-gray-600'
                    }`} />
                    {event.is_malicious && (
                      <div className="absolute inset-0 w-3 h-3 rounded-full bg-red-500 animate-ping opacity-30" />
                    )}
                  </div>
                  <span className="text-xs text-gray-500 font-mono w-24 shrink-0">
                    {event.timestamp?.split('T')[1]?.slice(0, 8) || ''}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-xs font-semibold shrink-0 ${
                    event.is_malicious ? 'bg-red-600/20 text-red-400' : 'bg-gray-700/50 text-gray-400'
                  }`}>{event.event_type}</span>
                  {event.technique_id && (
                    <span className="text-xs text-[#e63946] font-mono bg-[#457b9d]/10 px-1.5 py-0.5 rounded shrink-0">
                      {event.technique_id}
                    </span>
                  )}
                  <span className="text-sm text-gray-300 truncate flex-1">{event.description}</span>
                  {isExpanded ? <ChevronDown size={14} className="text-gray-500 shrink-0" /> : <ChevronRight size={14} className="text-gray-600 shrink-0" />}
                </div>

                {isExpanded && (
                  <div className="mt-3 ml-6 pl-4 border-l-2 border-gray-700 space-y-1 text-xs">
                    {(event.windows_event_id || event.sysmon_event_id) && (
                      <div className="flex items-center gap-2 mb-2">
                        {event.sysmon_event_id && (
                          <span className="inline-flex items-center gap-1 px-2 py-1 rounded bg-[#457b9d]/20 text-[#457b9d] font-mono font-bold">
                            Sysmon EID {event.sysmon_event_id}
                          </span>
                        )}
                        {event.windows_event_id && (
                          <span className="inline-flex items-center gap-1 px-2 py-1 rounded bg-[#457b9d]/20 text-[#e63946] font-mono font-bold">
                            Win EID {event.windows_event_id}
                          </span>
                        )}
                        {event.event_source && (
                          <span className="text-gray-500">({event.event_source})</span>
                        )}
                      </div>
                    )}
                    {event.event_id_description && (
                      <p><span className="text-gray-500">Event Description:</span> <span className="text-yellow-400">{event.event_id_description}</span></p>
                    )}
                    <p><span className="text-gray-500">Host:</span> <span className="text-[#e63946] font-mono">{event.src_host}</span></p>
                    {event.user && <p><span className="text-gray-500">User:</span> <span className="text-[#457b9d]">{event.user}</span></p>}
                    {event.dst_host && <p><span className="text-gray-500">Destination:</span> <span className="text-orange-400 font-mono">{event.dst_host}</span></p>}
                    <p><span className="text-gray-500">Severity:</span> <span className={
                      event.severity === 'critical' ? 'text-red-400' :
                      event.severity === 'high' ? 'text-orange-400' :
                      event.severity === 'medium' ? 'text-yellow-400' : 'text-gray-400'
                    }>{event.severity}</span></p>
                    <p><span className="text-gray-500">Description:</span> <span className="text-gray-300">{event.description}</span></p>
                    {event.technique_id && <p><span className="text-gray-500">MITRE:</span> <span className="text-[#e63946]">{event.technique_id}</span></p>}
                  </div>
                )}
              </div>
            )
          })}
        </div>

        {filtered.length > showCount && (
          <button onClick={() => setShowCount(s => s + 100)}
            className="w-full py-3 text-center text-sm text-[#e63946] hover:bg-gray-800/50 transition border-t border-gray-800/50">
            Load more ({filtered.length - showCount} remaining)
          </button>
        )}

        {display.length === 0 && (
          <div className="py-12 text-center text-gray-500 text-sm">
            No events match the current filters.
          </div>
        )}
      </div>

      {/* Bottom Stats */}
      <div className="card p-4">
        <div className="flex items-center justify-around text-center text-xs text-gray-400">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-[#e63946]" />
            <span><strong className="text-white">{timeline.length}</strong> total events</span>
          </div>
          <div className="w-px h-4 bg-gray-700" />
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-red-400" />
            <span><strong className="text-white">{malCount}</strong> malicious ({malPct}%)</span>
          </div>
          <div className="w-px h-4 bg-gray-700" />
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-[#457b9d]" />
            <span>Time span: <strong className="text-white">{timeSpan}</strong></span>
          </div>
        </div>
      </div>
    </div>
  )
}

// Small X icon component
const XIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
    <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
  </svg>
)
