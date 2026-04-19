import React, { useState } from 'react'
import { Play, Loader2, Shield, Layers, Crosshair } from 'lucide-react'

const ACTOR_META = {
  'APT29': { flag: '\u{1F1F7}\u{1F1FA}', alias: 'Cozy Bear' },
  'APT28': { flag: '\u{1F1F7}\u{1F1FA}', alias: 'Fancy Bear' },
  'TeamTNT': { flag: '\u{1F3F4}\u200D\u2620\uFE0F', alias: 'Cloud Threat' },
  'Lazarus': { flag: '\u{1F1F0}\u{1F1F5}', alias: 'Hidden Cobra' },
  'APT41': { flag: '\u{1F1E8}\u{1F1F3}', alias: 'Double Dragon' },
  'Insider': { flag: '\u{1F3E2}', alias: 'Internal Threat' },
}

function getActorMeta(name) {
  if (!name) return { flag: '\u{1F3F4}', alias: '' }
  for (const [key, meta] of Object.entries(ACTOR_META)) {
    if (name.includes(key)) return meta
  }
  return { flag: '\u{1F3F4}', alias: '' }
}

const SEVERITY_BORDER = {
  critical: '#f85149',
  high: '#f4a261',
  medium: '#457b9d',
  low: '#3fb950',
}

export default function Scenarios({ scenarios, onRun, loading }) {
  const [filter, setFilter] = useState('all')
  const [runningId, setRunningId] = useState(null)

  const filteredScenarios = filter === 'all'
    ? scenarios
    : scenarios.filter(s => s.severity === filter)

  const handleRun = (id) => {
    setRunningId(id)
    onRun(id)
  }

  const filterButtons = [
    { key: 'all', label: 'All', count: scenarios.length },
    { key: 'critical', label: 'Critical', count: scenarios.filter(s => s.severity === 'critical').length },
    { key: 'high', label: 'High', count: scenarios.filter(s => s.severity === 'high').length },
    { key: 'medium', label: 'Medium', count: scenarios.filter(s => s.severity === 'medium').length },
  ].filter(f => f.count > 0)

  return (
    <div className="space-y-8 animate-fade-in-up">
      {/* Header Section */}
      <div>
        <h1 className="text-3xl font-bold text-white tracking-tight">
          Attack Scenarios
        </h1>
        <p className="text-gray-400 text-sm mt-2 max-w-2xl">
          Select a scenario based on real-world threat actor campaigns. Each simulation replays
          authentic attack patterns mapped to the MITRE ATT&CK framework.
        </p>

        {/* Filter Pills */}
        <div className="flex items-center gap-2 mt-5">
          {filterButtons.map(f => (
            <button
              key={f.key}
              onClick={() => setFilter(f.key)}
              className={`px-4 py-1.5 rounded-full text-xs font-semibold tracking-wide transition-all duration-200 border ${
                filter === f.key
                  ? 'text-white border-transparent'
                  : 'text-gray-500 border-gray-700/50 hover:text-gray-300'
              }`}
              style={filter === f.key ? { background: '#e63946', borderColor: '#e63946' } : { background: 'rgba(255,255,255,0.03)' }}
            >
              {f.label}
              <span className={`ml-1.5 text-xs ${filter === f.key ? 'opacity-80' : 'opacity-50'}`}>
                {f.count}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Scenario Cards Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 stagger">
        {filteredScenarios.map(s => {
          const actorMeta = getActorMeta(s.threat_actor?.name)
          const isRunning = loading && runningId === s.id
          const isDisabled = loading && runningId !== s.id
          const borderColor = SEVERITY_BORDER[s.severity] || SEVERITY_BORDER.low

          return (
            <div
              key={s.id}
              className="card group relative overflow-hidden rounded-xl transition-all duration-300 hover:scale-[1.01] hover:shadow-xl"
              style={{
                opacity: isDisabled ? 0.5 : 1,
                pointerEvents: isDisabled ? 'none' : 'auto',
              }}
            >
              {/* Top Severity Band */}
              <div
                className="h-[3px] w-full"
                style={{ background: borderColor }}
              />

              <div className="p-6">
                {/* Threat Actor Section */}
                {s.threat_actor && (
                  <div className="flex items-center gap-3 mb-4 rounded-lg px-3 py-2.5" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid #21262d' }}>
                    <span className="text-xl">{actorMeta.flag}</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-bold text-white">{s.threat_actor.name}</span>
                        {(s.threat_actor.aliases?.[0] || actorMeta.alias) && (
                          <span className="text-xs text-gray-500 italic">
                            {s.threat_actor.aliases?.[0] || actorMeta.alias}
                          </span>
                        )}
                      </div>
                    </div>
                    {s.threat_actor.motivation && (
                      <span className="text-xs px-2 py-0.5 rounded font-medium shrink-0" style={{ background: 'rgba(69,123,157,0.15)', color: '#457b9d', border: '1px solid rgba(69,123,157,0.2)' }}>
                        {s.threat_actor.motivation}
                      </span>
                    )}
                  </div>
                )}

                {/* Scenario Title */}
                <h3 className="text-lg font-bold text-white mb-2 transition-colors" style={{ fontSize: '18px' }}>
                  {s.name}
                </h3>

                {/* Severity Badge */}
                <div className="mb-3">
                  <span className={`text-xs px-2.5 py-0.5 rounded font-bold uppercase tracking-wider ${
                    s.severity === 'critical' ? 'badge-critical' :
                    s.severity === 'high' ? 'badge-high' :
                    s.severity === 'medium' ? 'badge-medium' :
                    'badge-low'
                  }`}>
                    {s.severity}
                  </span>
                </div>

                {/* Description */}
                <p className="text-sm text-gray-400 mb-4 line-clamp-2 leading-relaxed">
                  {s.description}
                </p>

                {/* Stats Row */}
                <div className="flex items-center gap-4 text-xs text-gray-500 mb-4 pb-4" style={{ borderBottom: '1px solid #21262d' }}>
                  <div className="flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5" style={{ color: '#f4a261' }} />
                    <span><span className="text-gray-300 font-semibold">{s.phases}</span> phases</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Crosshair className="w-3.5 h-3.5" style={{ color: '#e63946' }} />
                    <span><span className="text-gray-300 font-semibold">{s.mitre_techniques?.length || 0}</span> techniques</span>
                  </div>
                  {s.category && (
                    <div className="flex items-center gap-1.5">
                      <Shield className="w-3.5 h-3.5" style={{ color: '#2a9d8f' }} />
                      <span className="capitalize">{s.category.replace('_', ' ')}</span>
                    </div>
                  )}
                </div>

                {/* MITRE Technique Pills */}
                <div className="flex flex-wrap gap-1.5 mb-5">
                  {(s.mitre_techniques || []).map(t => (
                    <span
                      key={t}
                      className="px-2 py-0.5 rounded text-xs font-mono font-medium"
                      style={{ color: '#e63946', background: 'rgba(230,57,70,0.08)', border: '1px solid rgba(230,57,70,0.15)' }}
                    >
                      {t}
                    </span>
                  ))}
                </div>

                {/* Launch Button */}
                <button
                  onClick={() => handleRun(s.id)}
                  disabled={loading}
                  className={`btn-primary w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg text-sm font-bold transition-all duration-200 ${
                    isRunning
                      ? 'opacity-70 cursor-wait'
                      : isDisabled
                      ? 'opacity-30 cursor-not-allowed'
                      : 'hover:scale-[1.02] active:scale-[0.98]'
                  }`}
                >
                  {isRunning ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Running...
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4" />
                      Launch Simulation
                    </>
                  )}
                </button>
              </div>
            </div>
          )
        })}
      </div>

      {/* Empty State */}
      {filteredScenarios.length === 0 && (
        <div className="text-center py-16">
          <Shield className="w-12 h-12 text-gray-700 mx-auto mb-4" />
          <p className="text-gray-500 text-sm">No scenarios match the selected filter.</p>
          <button
            onClick={() => setFilter('all')}
            className="mt-3 text-sm font-medium transition-colors"
            style={{ color: '#e63946' }}
          >
            Show all scenarios
          </button>
        </div>
      )}
    </div>
  )
}
