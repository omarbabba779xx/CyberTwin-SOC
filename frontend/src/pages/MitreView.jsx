import React, { useState, useEffect } from 'react'
import { Grid3X3, ShieldCheck, ShieldX, CheckCircle2, XCircle, Target, Eye, EyeOff } from 'lucide-react'
import { MitreSkeleton } from '../components/Skeleton'

const TACTICS_ORDER = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
]

const TACTIC_IDS = {
  'Reconnaissance': 'TA0043',
  'Resource Development': 'TA0042',
  'Initial Access': 'TA0001',
  'Execution': 'TA0002',
  'Persistence': 'TA0003',
  'Privilege Escalation': 'TA0004',
  'Defense Evasion': 'TA0005',
  'Credential Access': 'TA0006',
  'Discovery': 'TA0007',
  'Lateral Movement': 'TA0008',
  'Collection': 'TA0009',
  'Command and Control': 'TA0011',
  'Exfiltration': 'TA0010',
  'Impact': 'TA0040',
}

function CoverageRing({ percent, size = 80, strokeWidth = 6 }) {
  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (percent / 100) * circumference
  const color = percent >= 80 ? '#10b981' : percent >= 50 ? '#f59e0b' : '#ef4444'

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius}
          fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth={strokeWidth} />
        <circle cx={size / 2} cy={size / 2} r={radius}
          fill="none" stroke={color} strokeWidth={strokeWidth}
          strokeDasharray={circumference} strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all duration-1000 ease-out" />
      </svg>
      <span className="absolute stat-number text-xl" style={{ color }}>{percent}%</span>
    </div>
  )
}

export default function MitreView({ coverage, scores }) {
  const [hoveredCell, setHoveredCell] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const timer = setTimeout(() => setLoading(false), 500)
    return () => clearTimeout(timer)
  }, [])

  if (loading) return <MitreSkeleton />

  if (!coverage) {
    return (
      <div className="flex flex-col items-center justify-center h-96 animate-fade-in-up">
        <div className="card p-12 text-center max-w-md">
          <Grid3X3 className="w-16 h-16 mb-4 text-gray-600 mx-auto" />
          <h3 className="text-lg font-semibold text-gray-400 mb-2">No Coverage Data</h3>
          <p className="text-gray-500 text-sm">Run a simulation to see MITRE ATT&CK coverage analysis</p>
        </div>
      </div>
    )
  }

  const { coverage_matrix, heatmap, tactics_covered, total_techniques_detected } = coverage
  const missedTechniques = scores?.details?.techniques_missed || []
  const expectedTechniques = scores?.details?.techniques_expected || []

  // Build a lookup of detected techniques by tactic
  const detectedByTactic = {}
  Object.entries(coverage_matrix || {}).forEach(([tactic, techniques]) => {
    if (!detectedByTactic[tactic]) detectedByTactic[tactic] = []
    techniques.forEach(t => {
      detectedByTactic[tactic].push({
        ...t,
        status: 'detected',
      })
    })
  })

  const missedSet = new Set(missedTechniques)

  // Build the full matrix data
  const matrixData = {}
  TACTICS_ORDER.forEach(tactic => {
    matrixData[tactic] = []
    if (detectedByTactic[tactic]) {
      detectedByTactic[tactic].forEach(t => {
        matrixData[tactic].push({
          id: t.technique_id,
          name: t.technique_name,
          status: 'detected',
          alertCount: t.alert_count || 0,
        })
      })
    }
  })

  missedTechniques.forEach(techId => {
    let placed = false
    Object.values(matrixData).forEach(techniques => {
      if (techniques.find(t => t.id === techId)) placed = true
    })
    if (!placed) {
      matrixData._missed = matrixData._missed || []
      matrixData._missed.push({
        id: techId,
        name: techId,
        status: 'missed',
        alertCount: 0,
      })
    }
  })

  const totalExpected = expectedTechniques.length || (total_techniques_detected + missedTechniques.length)
  const coveragePercent = totalExpected > 0 ? Math.round((total_techniques_detected / totalExpected) * 100) : 0

  const maxTechniquesInTactic = Math.max(
    ...TACTICS_ORDER.map(t => (matrixData[t]?.length || 0)),
    1
  )

  const allDetected = []
  const allMissed = []
  Object.entries(matrixData).forEach(([tactic, techs]) => {
    if (tactic === '_missed') {
      techs.forEach(t => allMissed.push(t))
    } else {
      techs.forEach(t => {
        if (t.status === 'detected') allDetected.push({ ...t, tactic })
        else allMissed.push({ ...t, tactic })
      })
    }
  })

  return (
    <div className="space-y-6 animate-fade-in-up">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-2.5 bg-gradient-to-br from-[#2a9d8f] to-[#2a9d8f] rounded-xl shadow-lg shadow-[#2a9d8f]/20">
          <Grid3X3 className="w-6 h-6 text-white" />
        </div>
        <div>
          <h1 className="text-2xl font-bold tracking-tight">MITRE ATT&CK Coverage</h1>
          <p className="text-gray-400 text-sm">
            {total_techniques_detected} techniques detected across {tactics_covered?.length || 0} tactics
          </p>
        </div>
      </div>

      {/* Top Stats KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 stagger-children">
        {/* Techniques Detected */}
        <div className="card p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-gray-400 uppercase tracking-wider mb-1">Techniques Detected</p>
              <div className="flex items-baseline gap-1">
                <span className="stat-number text-3xl text-emerald-400">{total_techniques_detected}</span>
                <span className="text-gray-500 text-sm">/ {totalExpected}</span>
              </div>
            </div>
            <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20">
              <Eye className="w-6 h-6 text-emerald-400" />
            </div>
          </div>
        </div>

        {/* Techniques Missed */}
        <div className="card p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-gray-400 uppercase tracking-wider mb-1">Techniques Missed</p>
              <span className="stat-number text-3xl text-red-400">{missedTechniques.length}</span>
            </div>
            <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/20">
              <EyeOff className="w-6 h-6 text-red-400" />
            </div>
          </div>
        </div>

        {/* Coverage % */}
        <div className="card p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-gray-400 uppercase tracking-wider mb-1">Coverage Score</p>
              <span className={`text-xs px-2 py-0.5 rounded-full font-semibold ${
                coveragePercent >= 80 ? 'bg-emerald-500/20 text-emerald-400' :
                coveragePercent >= 50 ? 'bg-yellow-500/20 text-yellow-400' :
                'bg-red-500/20 text-red-400'
              }`}>
                {coveragePercent >= 80 ? 'Good' : coveragePercent >= 50 ? 'Moderate' : 'Low'}
              </span>
            </div>
            <CoverageRing percent={scores?.coverage_score || coveragePercent} />
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Matrix Heatmap */}
      <div className="card p-6">
        <h3 className="text-lg font-semibold mb-5 flex items-center gap-2">
          <Target className="w-5 h-5 text-[#2a9d8f]" />
          ATT&CK Matrix Heatmap
        </h3>

        <div className="overflow-x-auto pb-2">
          <div className="inline-grid gap-1.5" style={{
            gridTemplateColumns: `repeat(${TACTICS_ORDER.length}, minmax(80px, 1fr))`,
            minWidth: `${TACTICS_ORDER.length * 85}px`,
          }}>
            {/* Header Row - Tactic Names (rotated) */}
            {TACTICS_ORDER.map(tactic => {
              const count = heatmap?.[tactic] || 0
              const hasTechniques = (matrixData[tactic]?.length || 0) > 0
              return (
                <div key={tactic} className="text-center pb-3 h-24 flex flex-col justify-end">
                  <div className="overflow-hidden" style={{ height: '60px' }}>
                    <p className="text-[10px] font-semibold text-gray-300 leading-tight origin-bottom-left whitespace-nowrap"
                       style={{ transform: 'rotate(-45deg)', transformOrigin: 'center', display: 'inline-block' }}>
                      {tactic}
                    </p>
                  </div>
                  <p className="text-[9px] text-gray-600 font-mono mt-1">{TACTIC_IDS[tactic]}</p>
                  <div className={`h-0.5 mt-1 rounded-full ${
                    hasTechniques
                      ? count > 0 ? 'bg-emerald-500/60' : 'bg-red-500/60'
                      : 'bg-gray-700/40'
                  }`} />
                </div>
              )
            })}

            {/* Technique Cells */}
            {Array.from({ length: maxTechniquesInTactic }).map((_, rowIdx) => (
              TACTICS_ORDER.map(tactic => {
                const techniques = matrixData[tactic] || []
                const tech = techniques[rowIdx]

                if (!tech) {
                  return (
                    <div key={`${tactic}-${rowIdx}`}
                         className="h-7 w-full rounded bg-gray-800/20 border border-gray-800/10" />
                  )
                }

                const isDetected = tech.status === 'detected'
                const isMissed = missedSet.has(tech.id)
                const cellKey = `${tactic}-${rowIdx}`

                return (
                  <div
                    key={cellKey}
                    className={`h-7 w-full rounded flex items-center justify-center cursor-pointer transition-all duration-200 relative group ${
                      isDetected && !isMissed
                        ? 'bg-emerald-500/30 border border-emerald-500/50 hover:bg-emerald-500/40 hover:border-emerald-400/70 hover:shadow-lg hover:shadow-emerald-500/10'
                        : isMissed
                        ? 'bg-red-500/30 border border-red-500/50 hover:bg-red-500/40 hover:border-red-400/70 hover:shadow-lg hover:shadow-red-500/10'
                        : 'bg-gray-800/30 border border-gray-700/30 hover:bg-gray-700/30'
                    }`}
                    onMouseEnter={() => setHoveredCell(cellKey)}
                    onMouseLeave={() => setHoveredCell(null)}
                  >
                    <span className={`text-[8px] font-mono font-bold px-0.5 text-center leading-none ${
                      isDetected && !isMissed ? 'text-emerald-300' :
                      isMissed ? 'text-red-300' : 'text-gray-500'
                    }`}>
                      {tech.id}
                    </span>

                    {/* Tooltip */}
                    {hoveredCell === cellKey && (
                      <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 z-50 pointer-events-none">
                        <div className="bg-gray-900/95 backdrop-blur-xl border border-gray-700/50 rounded-lg shadow-2xl px-4 py-3 whitespace-nowrap">
                          <p className="text-xs font-bold text-white">{tech.id}</p>
                          <p className="text-[11px] text-gray-400 mt-0.5">{tech.name}</p>
                          <div className={`flex items-center gap-1.5 mt-1.5 text-[11px] font-semibold ${
                            isDetected && !isMissed ? 'text-emerald-400' : 'text-red-400'
                          }`}>
                            {isDetected && !isMissed
                              ? <><CheckCircle2 className="w-3 h-3" /> Detected ({tech.alertCount} alerts)</>
                              : <><XCircle className="w-3 h-3" /> MISSED - Not detected</>
                            }
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )
              })
            ))}
          </div>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-6 mt-5 pt-4 border-t border-gray-700/30">
          <div className="flex items-center gap-2">
            <div className="w-5 h-5 rounded bg-emerald-500/30 border border-emerald-500/50" />
            <span className="text-xs text-gray-400">Detected</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-5 h-5 rounded bg-red-500/30 border border-red-500/50" />
            <span className="text-xs text-gray-400">Missed (Expected)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-5 h-5 rounded bg-gray-800/40 border border-gray-700/30" />
            <span className="text-xs text-gray-400">Not in scenario</span>
          </div>
        </div>
      </div>

      {/* Detected vs Missed Lists */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 stagger-children">
        {/* Detected Techniques */}
        <div className="card p-6">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            <span className="text-emerald-400">Detected Techniques</span>
            <span className="text-xs bg-emerald-500/20 text-emerald-400 px-2.5 py-0.5 rounded-full ml-auto font-mono">
              {total_techniques_detected}
            </span>
          </h3>
          <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
            {Object.entries(coverage_matrix || {}).map(([tactic, techniques]) => (
              <div key={tactic}>
                <p className="text-[10px] text-gray-500 font-semibold uppercase tracking-wider mb-1.5">{tactic}</p>
                {techniques.map((t, i) => (
                  <div key={i} className="card flex items-center justify-between px-3 py-2.5 mb-1.5 hover:border-emerald-500/30 transition-colors">
                    <div className="flex items-center gap-2.5">
                      <ShieldCheck className="w-4 h-4 text-emerald-500 flex-shrink-0" />
                      <span className="text-sm text-emerald-400 font-mono font-semibold">{t.technique_id}</span>
                    </div>
                    <span className="text-xs text-gray-400 truncate mx-3 flex-1">{t.technique_name}</span>
                    <span className="text-[10px] text-gray-500 font-mono flex-shrink-0 bg-gray-800/50 px-2 py-0.5 rounded">{t.alert_count} alerts</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>

        {/* Missed Techniques */}
        <div className="card p-6">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <XCircle className="w-5 h-5 text-red-400" />
            <span className="text-red-400">Missed Techniques</span>
            <span className="text-xs bg-red-500/20 text-red-400 px-2.5 py-0.5 rounded-full ml-auto font-mono">
              {missedTechniques.length}
            </span>
          </h3>
          {missedTechniques.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-10 text-gray-500">
              <div className="p-4 rounded-full bg-emerald-500/10 mb-3">
                <ShieldCheck className="w-8 h-8 text-emerald-500" />
              </div>
              <p className="text-sm text-emerald-400 font-medium">All expected techniques were detected!</p>
            </div>
          ) : (
            <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
              {missedTechniques.map((t, i) => (
                <div key={i} className="card flex items-center gap-3 px-3 py-2.5 hover:border-red-500/30 transition-colors border-l-2 border-l-red-500/50">
                  <ShieldX className="w-4 h-4 text-red-500 flex-shrink-0" />
                  <span className="text-sm text-red-400 font-mono font-semibold">{t}</span>
                  <span className="text-[10px] text-gray-600 ml-auto bg-red-500/10 px-2 py-0.5 rounded">Not detected</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
