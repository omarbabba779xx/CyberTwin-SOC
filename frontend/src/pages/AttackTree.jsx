import React from 'react'
import { GitBranch, Shield, ArrowRight } from 'lucide-react'

function TreeNode({ phase, index, detected }) {
  return (
    <div
      className="card p-4 w-64 border-l-4 transition-all hover:scale-[1.02]"
      style={{
        borderLeftColor: detected ? '#2a9d8f' : '#e63946',
      }}
    >
      <div className="flex items-center gap-2">
        <span
          className="w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0"
          style={{
            background: detected ? 'rgba(42, 157, 143, 0.15)' : 'rgba(230, 57, 70, 0.15)',
            color: detected ? '#2a9d8f' : '#e63946',
          }}
        >
          {index}
        </span>
        <div className="min-w-0">
          <div className="font-semibold text-sm text-white truncate">{phase.technique_name}</div>
          <div className="text-xs font-mono" style={{ color: '#8b949e' }}>{phase.technique_id}</div>
        </div>
      </div>
      <div className="mt-2 text-xs" style={{ color: '#6e7681' }}>{phase.tactic}</div>
      {phase.stealth !== undefined && (
        <div className="mt-1.5 flex items-center gap-1.5">
          <span className="text-xs" style={{ color: '#6e7681' }}>Stealth:</span>
          <div className="flex-1 h-1.5 rounded-full" style={{ background: 'rgba(255,255,255,0.06)' }}>
            <div
              className="h-full rounded-full transition-all"
              style={{
                width: `${(phase.stealth || 0.5) * 100}%`,
                background: phase.stealth > 0.7 ? '#e63946' : phase.stealth > 0.4 ? '#f4a261' : '#2a9d8f',
              }}
            />
          </div>
        </div>
      )}
      <div className={`mt-2 text-xs font-semibold ${detected ? 'text-[#2a9d8f]' : 'text-[#e63946]'}`}>
        {detected ? '\u2713 DETECTED' : '\u2717 MISSED'}
      </div>
    </div>
  )
}

function TreeLine({ detected }) {
  return (
    <div
      className="mx-auto"
      style={{
        width: 2,
        height: 40,
        background: detected ? '#2a9d8f' : '#21262d',
      }}
    />
  )
}

function TreeBranch({ children }) {
  return (
    <div className="flex items-start justify-center gap-8 relative">
      {/* Horizontal connector line */}
      <div
        className="absolute top-0 left-1/2 -translate-x-1/2"
        style={{
          height: 2,
          background: '#21262d',
          width: `calc(100% - 16rem)`,
          top: 0,
        }}
      />
      {children.map((child, i) => (
        <div key={i} className="flex flex-col items-center relative">
          {/* Vertical stub from horizontal line to node */}
          <div style={{ width: 2, height: 20, background: '#21262d' }} />
          {child}
        </div>
      ))}
    </div>
  )
}

export default function AttackTree({ result, scenario, i18n }) {
  const t = i18n?.t || ((k) => k)

  if (!result || !scenario) {
    return (
      <div className="flex flex-col items-center justify-center h-full animate-fade-in-up">
        <div className="text-center">
          <div className="relative inline-block mb-6">
            <GitBranch className="w-16 h-16" style={{ color: '#e63946' }} />
          </div>
          <h2 className="text-3xl font-bold text-white mb-3">{t('attackTree.title')}</h2>
          <p className="text-gray-400 text-base mb-2">{t('attackTree.empty')}</p>
          <p className="text-gray-500 text-sm flex items-center justify-center gap-2">
            Launch from the Scenarios page
            <ArrowRight className="w-4 h-4" style={{ color: '#e63946' }} />
          </p>
        </div>
      </div>
    )
  }

  const phases = scenario.phases || []
  const alerts = result.alerts || []
  const detectedTechniques = new Set(alerts.map(a => a.technique_id))

  // Build tree levels - group phases that can run in parallel
  // Simple approach: each phase is a level, but if consecutive phases share a tactic, branch them
  const buildTreeLevels = () => {
    const levels = []
    let i = 0
    while (i < phases.length) {
      // Check if next phase has same parent (can be parallel)
      if (i + 1 < phases.length && phases[i].phase === phases[i + 1].phase) {
        // Parallel branch
        const group = [phases[i]]
        while (i + 1 < phases.length && phases[i].phase === phases[i + 1].phase) {
          i++
          group.push(phases[i])
        }
        levels.push(group)
      } else {
        levels.push([phases[i]])
      }
      i++
    }
    return levels
  }

  const levels = buildTreeLevels()

  // Stats
  const totalPhases = phases.length
  const detectedCount = phases.filter(p => detectedTechniques.has(p.technique_id)).length
  const missedCount = totalPhases - detectedCount

  return (
    <div className="space-y-6 animate-fade-in-up">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <GitBranch className="w-6 h-6" style={{ color: '#e63946' }} />
            {t('attackTree.title')}
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            Scenario: <span style={{ color: '#e63946' }} className="font-medium">{scenario.name}</span>
          </p>
        </div>
        {/* Summary badges */}
        <div className="flex items-center gap-3">
          <span
            className="px-3 py-1.5 rounded-lg text-xs font-bold"
            style={{ background: 'rgba(42, 157, 143, 0.15)', color: '#2a9d8f', border: '1px solid rgba(42, 157, 143, 0.3)' }}
          >
            {detectedCount} {t('attackTree.detected')}
          </span>
          <span
            className="px-3 py-1.5 rounded-lg text-xs font-bold"
            style={{ background: 'rgba(230, 57, 70, 0.15)', color: '#e63946', border: '1px solid rgba(230, 57, 70, 0.3)' }}
          >
            {missedCount} {t('attackTree.missed')}
          </span>
        </div>
      </div>

      {/* Tree Visualization */}
      <div className="card p-8 overflow-x-auto">
        <div className="flex flex-col items-center min-w-fit">
          {levels.map((level, li) => {
            const isFirst = li === 0
            return (
              <React.Fragment key={li}>
                {/* Connector line from previous level */}
                {!isFirst && (
                  <TreeLine detected={
                    level.length === 1 && detectedTechniques.has(levels[li - 1][0]?.technique_id)
                  } />
                )}

                {/* Level nodes */}
                {level.length === 1 ? (
                  <TreeNode
                    phase={level[0]}
                    index={level[0].phase || li + 1}
                    detected={detectedTechniques.has(level[0].technique_id)}
                  />
                ) : (
                  <div className="flex flex-col items-center">
                    {/* Split indicator */}
                    <div className="relative flex items-start justify-center gap-8">
                      {/* Horizontal line connecting branches */}
                      {level.length > 1 && (
                        <div
                          className="absolute"
                          style={{
                            height: 2,
                            background: '#21262d',
                            top: 0,
                            left: '50%',
                            transform: 'translateX(-50%)',
                            width: `${(level.length - 1) * 280}px`,
                          }}
                        />
                      )}
                      {level.map((phase, pi) => (
                        <div key={pi} className="flex flex-col items-center">
                          <div style={{ width: 2, height: 20, background: '#21262d' }} />
                          <TreeNode
                            phase={phase}
                            index={phase.phase || `${li + 1}.${pi + 1}`}
                            detected={detectedTechniques.has(phase.technique_id)}
                          />
                        </div>
                      ))}
                    </div>
                    {/* Merge line */}
                    {li < levels.length - 1 && (
                      <div className="relative w-full flex justify-center">
                        {level.length > 1 && (
                          <div
                            className="absolute"
                            style={{
                              height: 2,
                              background: '#21262d',
                              top: 0,
                              left: '50%',
                              transform: 'translateX(-50%)',
                              width: `${(level.length - 1) * 280}px`,
                            }}
                          />
                        )}
                        {level.map((_, pi) => (
                          <div
                            key={pi}
                            className="absolute"
                            style={{
                              width: 2,
                              height: 20,
                              background: '#21262d',
                              top: 0,
                              left: `calc(50% + ${(pi - (level.length - 1) / 2) * 280}px)`,
                            }}
                          />
                        ))}
                        <div style={{ width: 2, height: 20, background: '#21262d', marginTop: 0 }} />
                      </div>
                    )}
                  </div>
                )}
              </React.Fragment>
            )
          })}
        </div>
      </div>

      {/* Legend */}
      <div className="card p-4 flex items-center gap-6 text-xs">
        <span className="text-gray-400 font-semibold uppercase tracking-wider">Legend:</span>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-sm" style={{ background: '#2a9d8f' }} />
          <span style={{ color: '#8b949e' }}>{t('attackTree.detected')}</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-sm" style={{ background: '#e63946' }} />
          <span style={{ color: '#8b949e' }}>{t('attackTree.missed')}</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-8 h-1.5 rounded-full" style={{ background: 'linear-gradient(to right, #2a9d8f, #f4a261, #e63946)' }} />
          <span style={{ color: '#8b949e' }}>{t('attackTree.stealth')} Level</span>
        </div>
      </div>
    </div>
  )
}
