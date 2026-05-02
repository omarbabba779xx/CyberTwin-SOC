import React, { useCallback, useEffect, useMemo, useState } from 'react'
import {
  AlertCircle,
  Database,
  EyeOff,
  FlaskConical,
  RefreshCw,
  Search,
  ShieldCheck,
  Target,
} from 'lucide-react'
import { apiUrl, authHeaders } from '../utils/api'

function StatCard({ icon: Icon, label, value, tone = 'text-gray-200' }) {
  return (
    <div className="card p-5">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-xs text-gray-500 uppercase tracking-wider">{label}</p>
          <p className={`text-2xl font-bold mt-1 tabular-nums ${tone}`}>{value}</p>
        </div>
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20">
          <Icon className="w-5 h-5 text-red-400" />
        </div>
      </div>
    </div>
  )
}

function Pill({ children }) {
  return (
    <span className="inline-flex items-center rounded-full border border-gray-700 bg-gray-800/70 px-2 py-0.5 text-[11px] text-gray-300">
      {children}
    </span>
  )
}

function EmptyState({ icon: Icon, title, body }) {
  return (
    <div className="card p-8 text-center">
      <Icon className="w-10 h-10 mx-auto mb-3 text-gray-600" />
      <h3 className="text-base font-semibold text-gray-200">{title}</h3>
      <p className="text-sm text-gray-500 mt-2">{body}</p>
    </div>
  )
}

export default function AtomicRedTeam({ token }) {
  const [catalogue, setCatalogue] = useState(null)
  const [selectedId, setSelectedId] = useState('')
  const [detail, setDetail] = useState(null)
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(true)
  const [detailLoading, setDetailLoading] = useState(false)
  const [error, setError] = useState('')

  const loadCatalogue = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const response = await fetch(apiUrl('/api/mitre/atomic-red-team?limit=2000'), {
        headers: authHeaders(token),
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const data = await response.json()
      setCatalogue(data)
      const first = data?.techniques?.[0] || ''
      setSelectedId((current) => current || first)
    } catch {
      setError('Atomic Red Team catalogue is not reachable.')
    } finally {
      setLoading(false)
    }
  }, [token])

  useEffect(() => {
    loadCatalogue()
  }, [loadCatalogue])

  useEffect(() => {
    if (!selectedId || !catalogue?.available) {
      setDetail(null)
      return
    }

    let ignore = false
    setDetailLoading(true)
    fetch(apiUrl(`/api/mitre/atomic-red-team/${encodeURIComponent(selectedId)}`), {
      headers: authHeaders(token),
    })
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`)
        return response.json()
      })
      .then((data) => {
        if (!ignore) setDetail(data)
      })
      .catch(() => {
        if (!ignore) setDetail(null)
      })
      .finally(() => {
        if (!ignore) setDetailLoading(false)
      })

    return () => {
      ignore = true
    }
  }, [catalogue?.available, selectedId, token])

  const techniques = catalogue?.techniques || []
  const filteredTechniques = useMemo(() => {
    const term = query.trim().toLowerCase()
    if (!term) return techniques
    return techniques.filter((id) => id.toLowerCase().includes(term))
  }, [query, techniques])

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-96 text-gray-500">
        <RefreshCw className="w-10 h-10 mb-3 animate-spin text-gray-700" />
        <p>Loading Atomic Red Team metadata...</p>
      </div>
    )
  }

  if (error) {
    return <EmptyState icon={AlertCircle} title="Atomic Red Team unavailable" body={error} />
  }

  if (!catalogue?.available) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-red-500/10 rounded-lg border border-red-500/20">
            <Target className="w-6 h-6 text-red-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Atomic Red Team</h1>
            <p className="text-sm text-gray-400">Catalogue status and safe ATT&CK metadata</p>
          </div>
        </div>

        <EmptyState
          icon={Database}
          title="Catalogue not configured"
          body={catalogue?.reason || 'Set ATOMIC_RED_TEAM_PATH on the backend to enable metadata browsing.'}
        />
      </div>
    )
  }

  const tests = detail?.tests || []

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-red-500/10 rounded-lg border border-red-500/20">
            <Target className="w-6 h-6 text-red-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Atomic Red Team</h1>
            <p className="text-sm text-gray-400">Safe local metadata mapped to MITRE ATT&CK</p>
          </div>
        </div>
        <button
          onClick={loadCatalogue}
          className="flex items-center gap-2 rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-300 hover:border-red-500/40 hover:text-white"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <StatCard icon={Database} label="Techniques indexed" value={catalogue.technique_count || techniques.length} tone="text-red-300" />
        <StatCard icon={ShieldCheck} label="Safe metadata mode" value="On" tone="text-emerald-400" />
        <StatCard icon={EyeOff} label="Commands exposed" value="0" tone="text-gray-200" />
        <StatCard icon={FlaskConical} label="ATT&CK compatibility" value="v19" tone="text-sky-300" />
      </div>

      {(catalogue.upstream_commit || catalogue.compatibility) && (
        <div className="card p-4 flex flex-wrap gap-2 text-xs text-gray-400">
          {catalogue.compatibility && <Pill>{catalogue.compatibility}</Pill>}
          {catalogue.upstream_commit && <Pill>commit {catalogue.upstream_commit}</Pill>}
          {catalogue.upstream_commit_date && <Pill>{catalogue.upstream_commit_date}</Pill>}
          {catalogue.upstream_commit_subject && <Pill>{catalogue.upstream_commit_subject}</Pill>}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-[360px_1fr] gap-6">
        <div className="card overflow-hidden">
          <div className="p-4 border-b border-gray-800">
            <div className="relative">
              <Search className="absolute left-3 top-2.5 w-4 h-4 text-gray-500" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search technique ID"
                className="w-full rounded-lg border border-gray-700 bg-gray-900/70 py-2 pl-9 pr-3 text-sm text-gray-200 outline-none focus:border-red-500/60"
              />
            </div>
          </div>
          <div className="max-h-[640px] overflow-y-auto p-2 space-y-1">
            {filteredTechniques.map((id) => (
              <button
                key={id}
                onClick={() => setSelectedId(id)}
                className={`w-full rounded-lg px-3 py-2 text-left font-mono text-sm transition ${
                  selectedId === id
                    ? 'bg-red-500/15 text-red-300 border border-red-500/30'
                    : 'text-gray-300 hover:bg-gray-800 border border-transparent'
                }`}
              >
                {id}
              </button>
            ))}
            {!filteredTechniques.length && (
              <p className="px-3 py-8 text-center text-sm text-gray-500">No technique matched.</p>
            )}
          </div>
        </div>

        <div className="space-y-4">
          {detailLoading && (
            <div className="card p-8 text-center text-gray-500">
              <RefreshCw className="w-8 h-8 mx-auto mb-3 animate-spin text-gray-700" />
              Loading technique detail...
            </div>
          )}

          {!detailLoading && detail && (
            <>
              <div className="card p-6">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div>
                    <code className="text-sm text-red-300">{detail.technique_id}</code>
                    <h2 className="text-xl font-bold mt-1">{detail.display_name || detail.technique_id}</h2>
                    <p className="text-xs text-gray-500 mt-1 break-all">{detail.source_path}</p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Pill>{detail.atomic_test_count || tests.length} tests</Pill>
                    {(detail.executors || []).map((executor) => <Pill key={executor}>{executor}</Pill>)}
                  </div>
                </div>

                <div className="mt-5">
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Supported platforms</p>
                  <div className="flex flex-wrap gap-2">
                    {(detail.supported_platforms || []).map((platform) => <Pill key={platform}>{platform}</Pill>)}
                    {!detail.supported_platforms?.length && <span className="text-sm text-gray-500">None listed</span>}
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                {tests.map((test) => (
                  <div key={test.guid || test.name} className="card p-5">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <h3 className="font-semibold text-gray-100">{test.name || 'Unnamed test'}</h3>
                        <p className="text-xs text-gray-500 mt-1 font-mono">{test.guid}</p>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {test.executor && <Pill>{test.executor}</Pill>}
                        {test.elevation_required && <Pill>elevation required</Pill>}
                        <Pill>{test.dependency_count || 0} dependencies</Pill>
                      </div>
                    </div>

                    {test.description && (
                      <p className="text-sm text-gray-400 mt-4 leading-relaxed">{test.description}</p>
                    )}

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                      <div>
                        <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Platforms</p>
                        <div className="flex flex-wrap gap-2">
                          {(test.supported_platforms || []).map((platform) => <Pill key={platform}>{platform}</Pill>)}
                        </div>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Input arguments</p>
                        <div className="flex flex-wrap gap-2">
                          {(test.input_arguments || []).map((argument) => <Pill key={argument}>{argument}</Pill>)}
                          {!test.input_arguments?.length && <span className="text-sm text-gray-500">None</span>}
                        </div>
                      </div>
                    </div>

                    {test.validation_plan && (
                      <div className="mt-4 rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3">
                        <p className="text-xs text-emerald-300 uppercase tracking-wider mb-2">Validation plan</p>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                          <div>
                            <p className="text-gray-500 mb-1">Telemetry</p>
                            <div className="flex flex-wrap gap-1.5">
                              {(test.validation_plan.telemetry_to_watch || []).map((item) => <Pill key={item}>{item}</Pill>)}
                            </div>
                          </div>
                          <div>
                            <p className="text-gray-500 mb-1">Expected SOC artifacts</p>
                            <ul className="space-y-1 text-gray-300">
                              {(test.validation_plan.expected_soc_artifacts || []).map((item) => <li key={item}>{item}</li>)}
                            </ul>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                ))}

                {!tests.length && (
                  <EmptyState icon={FlaskConical} title="No tests found" body="The selected Atomic technique has no parsed tests." />
                )}
              </div>
            </>
          )}

          {!detailLoading && !detail && (
            <EmptyState icon={Target} title="Technique detail unavailable" body="Select another technique or refresh the catalogue." />
          )}
        </div>
      </div>
    </div>
  )
}
