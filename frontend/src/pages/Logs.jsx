import React, { useState, useEffect } from 'react'
import { FileText, Search, Filter, AlertCircle, ChevronLeft, ChevronRight, Download } from 'lucide-react'
import { LogsSkeleton } from '../components/Skeleton'
import { exportToCSV, exportToJSON } from '../utils/export'

const SEVERITY_LEVELS = ['all', 'critical', 'high', 'medium', 'low', 'info']

const SeverityBadge = ({ severity }) => {
  const cls = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
    info: 'bg-gray-600/20 text-gray-400 border border-gray-600/30',
  }
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${cls[severity] || cls.info}`}>
      {severity}
    </span>
  )
}

export default function Logs({ logs = [], stats }) {
  const [search, setSearch] = useState('')
  const [sourceFilter, setSourceFilter] = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [maliciousOnly, setMaliciousOnly] = useState(false)
  const [page, setPage] = useState(0)
  const pageSize = 50
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const timer = setTimeout(() => setLoading(false), 500)
    return () => clearTimeout(timer)
  }, [])

  if (loading) return <LogsSkeleton />

  if (!logs.length) {
    return (
      <div className="flex flex-col items-center justify-center h-96 animate-fade-in-up">
        <div className="card p-12 text-center max-w-md">
          <FileText className="w-16 h-16 mb-4 text-gray-600 mx-auto" />
          <h3 className="text-lg font-semibold text-gray-400 mb-2">No Logs Available</h3>
          <p className="text-gray-500 text-sm">No logs available. Run a simulation first.</p>
        </div>
      </div>
    )
  }

  const sources = [...new Set(logs.map(l => l.log_source))].sort()

  let filtered = logs
  if (sourceFilter !== 'all') filtered = filtered.filter(l => l.log_source === sourceFilter)
  if (severityFilter !== 'all') filtered = filtered.filter(l => l.severity === severityFilter)
  if (maliciousOnly) filtered = filtered.filter(l => l.is_malicious)
  if (search) {
    const q = search.toLowerCase()
    filtered = filtered.filter(l =>
      l.description?.toLowerCase().includes(q) ||
      l.user?.toLowerCase().includes(q) ||
      l.src_host?.toLowerCase().includes(q) ||
      l.event_type?.toLowerCase().includes(q) ||
      l.event_id_description?.toLowerCase().includes(q) ||
      String(l.windows_event_id || '').includes(q) ||
      String(l.sysmon_event_id || '').includes(q)
    )
  }

  const totalPages = Math.ceil(filtered.length / pageSize)
  const display = filtered.slice(page * pageSize, (page + 1) * pageSize)

  // Source breakdown
  const sourceBreakdown = {}
  logs.forEach(l => {
    sourceBreakdown[l.log_source] = (sourceBreakdown[l.log_source] || 0) + 1
  })

  return (
    <div className="space-y-6 animate-fade-in-up">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl shadow-lg" style={{ background:'linear-gradient(135deg,#457b9d,#1d6190)', boxShadow:'0 4px 15px rgba(69,123,157,0.3)' }}>
            <FileText className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Log Explorer</h1>
            <p className="text-sm" style={{ color:'#8b949e' }}>
              {filtered.length} of {logs.length} logs
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => exportToCSV(display, `logs_page_${Date.now()}.csv`)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold transition-colors"
            style={{ background:'#21262d', color:'#8b949e', border:'1px solid #30363d' }}
            onMouseOver={e => e.currentTarget.style.color='#e6edf3'}
            onMouseOut={e => e.currentTarget.style.color='#8b949e'}
            title="Export current page as CSV"
          >
            <Download className="w-3.5 h-3.5" /> CSV
          </button>
          <button
            onClick={() => exportToJSON(filtered, `logs_${Date.now()}.json`)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold transition-colors"
            style={{ background:'#21262d', color:'#8b949e', border:'1px solid #30363d' }}
            onMouseOver={e => e.currentTarget.style.color='#e6edf3'}
            onMouseOut={e => e.currentTarget.style.color='#8b949e'}
            title="Export all filtered logs as JSON"
          >
            <Download className="w-3.5 h-3.5" /> JSON
          </button>
        </div>
      </div>

      {/* Search Bar */}
      <div className="card p-1.5">
        <div className="relative">
          <Search className="absolute left-4 top-3 w-5 h-5 text-gray-500" />
          <input
            type="text"
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(0) }}
            placeholder="Search logs by event type, host, description, Event ID..."
            className="w-full bg-gray-900/50 border border-gray-700/30 rounded-lg pl-12 pr-4 py-2.5 text-sm text-gray-300 focus:outline-none focus:border-[#e63946]/50 focus:ring-1 focus:ring-[#e63946]/20 transition-all placeholder-gray-600"
          />
        </div>
      </div>

      {/* Filter Row */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Severity Filter Buttons */}
        <div className="flex items-center gap-1 card p-1">
          {SEVERITY_LEVELS.map(level => (
            <button
              key={level}
              onClick={() => { setSeverityFilter(level); setPage(0) }}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold uppercase tracking-wider transition-all ${
                severityFilter === level
                  ? level === 'all' ? 'bg-[#e63946]/20 text-[#e63946] border border-[#e63946]/30'
                    : level === 'critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                    : level === 'high' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                    : level === 'medium' ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                    : level === 'low' ? 'bg-[#e63946]/20 text-[#e63946] border border-[#e63946]/30'
                    : 'bg-gray-500/20 text-gray-400 border border-gray-500/30'
                  : 'text-gray-500 hover:text-gray-300 border border-transparent'
              }`}
            >
              {level}
            </button>
          ))}
        </div>

        {/* Source Filter */}
        <div className="card p-1">
          <select
            value={sourceFilter}
            onChange={e => { setSourceFilter(e.target.value); setPage(0) }}
            className="bg-transparent border-none rounded-md px-3 py-1.5 text-xs text-gray-300 focus:outline-none cursor-pointer"
          >
            <option value="all" className="bg-gray-900">All sources</option>
            {sources.map(s => <option key={s} value={s} className="bg-gray-900">{s}</option>)}
          </select>
        </div>

        {/* Malicious Only Toggle */}
        <button
          onClick={() => { setMaliciousOnly(!maliciousOnly); setPage(0) }}
          className={`card px-3 py-2 text-xs font-semibold flex items-center gap-2 transition-all ${
            maliciousOnly
              ? 'border-red-500/40 text-red-400 bg-red-500/5'
              : 'text-gray-400 hover:text-gray-300'
          }`}
        >
          <AlertCircle className="w-3.5 h-3.5" />
          Malicious Only
        </button>
      </div>

      {/* Stats Bar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="card px-3 py-1.5 text-xs">
          <span className="text-gray-500">Total:</span>
          <span className="text-white font-mono ml-1.5">{logs.length}</span>
        </div>
        {stats && (
          <>
            <div className="card px-3 py-1.5 text-xs">
              <span className="text-gray-500">Malicious:</span>
              <span className="text-red-400 font-mono font-semibold ml-1.5">{stats.malicious_logs}</span>
            </div>
            <div className="card px-3 py-1.5 text-xs">
              <span className="text-gray-500">Benign:</span>
              <span className="text-emerald-400 font-mono font-semibold ml-1.5">{stats.benign_logs}</span>
            </div>
          </>
        )}
        <div className="h-4 w-px bg-gray-700/50 mx-1" />
        {Object.entries(sourceBreakdown).map(([source, count]) => (
          <span key={source} className="text-[10px] bg-gray-800/50 text-gray-400 px-2.5 py-1 rounded-full border border-gray-700/30 font-mono">
            {source} <strong className="text-gray-300">{count}</strong>
          </span>
        ))}
      </div>

      {/* Log Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Event ID</th>
                <th>Source</th>
                <th>Type</th>
                <th>Host</th>
                <th>User</th>
                <th>Description</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {display.map((l, i) => (
                <tr key={i} className={
                  l.is_malicious
                    ? 'border-l-2 border-l-red-500 bg-red-500/[0.03] hover:bg-red-500/[0.06]'
                    : 'hover:bg-gray-800/30'
                }>
                  <td className="font-mono text-gray-500 text-xs whitespace-nowrap">
                    {l.timestamp?.split('T')[1]?.slice(0, 12)}
                  </td>
                  <td className="whitespace-nowrap">
                    {(l.windows_event_id || l.sysmon_event_id) ? (
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold ${
                        l.event_source === 'Sysmon'
                          ? 'bg-[#e63946]/15 text-[#e63946] border border-[#e63946]/20'
                          : l.event_source === 'Windows Security'
                          ? 'bg-[#457b9d]/15 text-[#457b9d] border border-[#457b9d]/20'
                          : 'bg-gray-700/50 text-gray-400 border border-gray-700/30'
                      }`}>
                        {l.sysmon_event_id ? `Sysmon ${l.sysmon_event_id}` : l.windows_event_id}
                        {l.sysmon_event_id && l.windows_event_id && (
                          <span className="text-gray-600 ml-0.5">| {l.windows_event_id}</span>
                        )}
                      </span>
                    ) : (
                      <span className="text-gray-700 text-xs">--</span>
                    )}
                  </td>
                  <td>
                    <span className={`text-[11px] px-2 py-0.5 rounded font-medium ${
                      l.log_source === 'Sysmon' ? 'bg-[#e63946]/10 text-[#e63946]' :
                      l.log_source === 'Windows Security' ? 'bg-[#457b9d]/10 text-[#457b9d]' :
                      l.log_source === 'PowerShell' ? 'bg-yellow-500/10 text-yellow-400' :
                      l.log_source === 'Windows System' ? 'bg-teal-500/10 text-teal-400' :
                      'bg-gray-500/10 text-gray-400'
                    }`}>
                      {l.log_source}
                    </span>
                  </td>
                  <td className="text-gray-400 text-xs">{l.event_type}</td>
                  <td className="text-gray-400 text-xs font-mono">{l.src_host}</td>
                  <td className="text-gray-400 text-xs">{l.user}</td>
                  <td className="text-gray-300 text-xs max-w-xs truncate">{l.description}</td>
                  <td><SeverityBadge severity={l.severity} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-3">
          <button
            onClick={() => setPage(Math.max(0, page - 1))}
            disabled={page === 0}
            className="card px-4 py-2 text-sm font-medium flex items-center gap-1.5 disabled:opacity-30 disabled:cursor-not-allowed hover:border-[#e63946]/30 transition-colors"
          >
            <ChevronLeft className="w-4 h-4" />
            Previous
          </button>
          <div className="card px-4 py-2">
            <span className="text-sm font-mono">
              Page <strong className="text-[#e63946]">{page + 1}</strong> of <strong className="text-gray-300">{totalPages}</strong>
            </span>
          </div>
          <button
            onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
            disabled={page >= totalPages - 1}
            className="card px-4 py-2 text-sm font-medium flex items-center gap-1.5 disabled:opacity-30 disabled:cursor-not-allowed hover:border-[#e63946]/30 transition-colors"
          >
            Next
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      )}
    </div>
  )
}
