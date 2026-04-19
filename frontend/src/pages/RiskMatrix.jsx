import React, { useMemo } from 'react'
import { AlertTriangle, ShieldAlert, TrendingUp, Info } from 'lucide-react'

const LEVELS = ['Very Low', 'Low', 'Medium', 'High', 'Very High']

// risk[likelihood][impact] — 0=VL row (bottom), 4=VH row (top)
const RISK_GRID = [
  ['low',  'low',  'low',  'med',  'med'],   // VL likelihood
  ['low',  'low',  'med',  'med',  'high'],   // L
  ['low',  'med',  'med',  'high', 'crit'],   // M
  ['low',  'med',  'high', 'crit', 'crit'],   // H
  ['med',  'high', 'crit', 'crit', 'crit'],   // VH
]

const RISK_COLORS = {
  low: '#2a9d8f',
  med: '#f4a261',
  high: '#e63946',
  crit: '#991b1b',
}

const RISK_BG = {
  low: 'rgba(42, 157, 143, 0.15)',
  med: 'rgba(244, 162, 97, 0.15)',
  high: 'rgba(230, 57, 70, 0.15)',
  crit: 'rgba(153, 27, 27, 0.25)',
}

const RISK_LABELS = {
  low: 'Low',
  med: 'Medium',
  high: 'High',
  crit: 'Critical',
}

function computePosition(scenario) {
  // Map severity 1-10 to impact index 0-4
  const severity = scenario.severity ?? 5
  const detection = scenario.detection_score ?? scenario.detection ?? 50

  const impactIdx = Math.min(4, Math.max(0, Math.round((severity / 10) * 4)))
  // Higher detection = lower likelihood (better detection means less likely to succeed)
  const likelihoodIdx = Math.min(4, Math.max(0, Math.round(((100 - detection) / 100) * 4)))

  return { impactIdx, likelihoodIdx }
}

function getRecommendation(level) {
  switch (level) {
    case 'crit': return 'Immediate action required. Escalate to SOC leadership and activate incident response plan.'
    case 'high': return 'Priority remediation needed. Deploy additional monitoring and containment measures.'
    case 'med': return 'Schedule remediation. Enhance detection rules and review access controls.'
    case 'low': return 'Monitor and track. Ensure baseline controls are maintained.'
    default: return 'Assess and categorize.'
  }
}

export default function RiskMatrix({ result, scenarios }) {
  const scenarioList = scenarios || []

  // Place each scenario in the grid
  const placements = useMemo(() => {
    return scenarioList.map((sc) => {
      const { impactIdx, likelihoodIdx } = computePosition(sc)
      const riskLevel = RISK_GRID[likelihoodIdx][impactIdx]
      return { ...sc, impactIdx, likelihoodIdx, riskLevel }
    })
  }, [scenarioList])

  // Group placements by cell
  const cellMap = useMemo(() => {
    const map = {}
    placements.forEach((p) => {
      const key = `${p.likelihoodIdx}-${p.impactIdx}`
      if (!map[key]) map[key] = []
      map[key].push(p)
    })
    return map
  }, [placements])

  const riskCounts = useMemo(() => {
    const counts = { low: 0, med: 0, high: 0, crit: 0 }
    placements.forEach((p) => counts[p.riskLevel]++)
    return counts
  }, [placements])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div
          className="flex items-center justify-center"
          style={{
            width: 40,
            height: 40,
            borderRadius: 10,
            backgroundColor: 'rgba(244, 162, 97, 0.12)',
            border: '1px solid rgba(244, 162, 97, 0.25)',
          }}
        >
          <AlertTriangle style={{ width: 22, height: 22, color: '#f4a261' }} />
        </div>
        <div>
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary, #e6edf3)' }}>
            Risk Assessment Matrix
          </h1>
          <p style={{ fontSize: 13, color: 'var(--text-muted, #6e7681)' }}>
            Likelihood vs Impact analysis of threat scenarios
          </p>
        </div>
      </div>

      {/* Risk summary stats */}
      <div className="grid grid-cols-4 gap-4">
        {Object.entries(RISK_LABELS).map(([key, label]) => (
          <div key={key} className="card" style={{ padding: 14 }}>
            <div className="flex items-center justify-between">
              <div>
                <p style={{ fontSize: 11, color: 'var(--text-muted, #6e7681)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
                  {label} Risk
                </p>
                <p className="stat-value" style={{ fontSize: 24, color: RISK_COLORS[key] }}>
                  {riskCounts[key]}
                </p>
              </div>
              <div
                style={{
                  width: 10,
                  height: 10,
                  borderRadius: '50%',
                  backgroundColor: RISK_COLORS[key],
                }}
              />
            </div>
          </div>
        ))}
      </div>

      {/* Matrix grid */}
      <div className="card" style={{ padding: 24 }}>
        <div style={{ display: 'flex', alignItems: 'stretch' }}>
          {/* Y-axis label */}
          <div
            style={{
              writingMode: 'vertical-rl',
              transform: 'rotate(180deg)',
              textAlign: 'center',
              fontSize: 12,
              fontWeight: 700,
              color: 'var(--text-secondary, #8b949e)',
              paddingRight: 8,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
            }}
          >
            Likelihood
          </div>

          {/* Y-axis level labels + Grid */}
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              {/* Grid rows — from top (VH) to bottom (VL) */}
              {[...LEVELS].reverse().map((likelihood, rowVisualIdx) => {
                const likelihoodIdx = 4 - rowVisualIdx // VH=4, H=3, M=2, L=1, VL=0
                return (
                  <div key={likelihood} style={{ display: 'flex', alignItems: 'stretch' }}>
                    {/* Row label */}
                    <div
                      style={{
                        width: 70,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'flex-end',
                        paddingRight: 10,
                        fontSize: 11,
                        fontWeight: 600,
                        color: 'var(--text-muted, #6e7681)',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {likelihood}
                    </div>

                    {/* Cells */}
                    {LEVELS.map((_, impactIdx) => {
                      const level = RISK_GRID[likelihoodIdx][impactIdx]
                      const key = `${likelihoodIdx}-${impactIdx}`
                      const items = cellMap[key] || []

                      return (
                        <div
                          key={impactIdx}
                          style={{
                            flex: 1,
                            minHeight: 64,
                            margin: 2,
                            borderRadius: 6,
                            backgroundColor: RISK_BG[level],
                            border: `1px solid ${RISK_COLORS[level]}33`,
                            padding: 6,
                            display: 'flex',
                            flexDirection: 'column',
                            gap: 3,
                            position: 'relative',
                          }}
                          title={`${RISK_LABELS[level]} risk`}
                        >
                          {/* Level label in corner */}
                          <span
                            style={{
                              position: 'absolute',
                              top: 3,
                              right: 5,
                              fontSize: 8,
                              fontWeight: 700,
                              color: RISK_COLORS[level],
                              opacity: 0.5,
                              textTransform: 'uppercase',
                            }}
                          >
                            {RISK_LABELS[level]}
                          </span>

                          {/* Scenario badges */}
                          {items.map((sc) => (
                            <span
                              key={sc.id}
                              style={{
                                fontSize: 9,
                                fontWeight: 600,
                                padding: '2px 5px',
                                borderRadius: 4,
                                backgroundColor: `${RISK_COLORS[level]}30`,
                                color: RISK_COLORS[level],
                                border: `1px solid ${RISK_COLORS[level]}50`,
                                whiteSpace: 'nowrap',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                maxWidth: '100%',
                                display: 'block',
                              }}
                              title={sc.name || sc.id}
                            >
                              {sc.name || sc.id}
                            </span>
                          ))}
                        </div>
                      )
                    })}
                  </div>
                )
              })}

              {/* X-axis labels */}
              <div style={{ display: 'flex', paddingLeft: 70 }}>
                {LEVELS.map((label) => (
                  <div
                    key={label}
                    style={{
                      flex: 1,
                      textAlign: 'center',
                      fontSize: 11,
                      fontWeight: 600,
                      color: 'var(--text-muted, #6e7681)',
                      paddingTop: 8,
                    }}
                  >
                    {label}
                  </div>
                ))}
              </div>

              {/* X-axis title */}
              <div
                style={{
                  textAlign: 'center',
                  fontSize: 12,
                  fontWeight: 700,
                  color: 'var(--text-secondary, #8b949e)',
                  paddingTop: 8,
                  letterSpacing: '0.1em',
                  textTransform: 'uppercase',
                }}
              >
                Impact
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Scenario risk details */}
      {placements.length > 0 && (
        <div className="card" style={{ padding: 20 }}>
          <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary, #e6edf3)', marginBottom: 16 }}>
            <ShieldAlert style={{ width: 16, height: 16, display: 'inline', marginRight: 8, verticalAlign: 'text-bottom' }} />
            Risk Summary &amp; Recommendations
          </h3>
          <div className="space-y-3">
            {placements.map((sc) => (
              <div
                key={sc.id}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: 12,
                  padding: 14,
                  borderRadius: 8,
                  backgroundColor: RISK_BG[sc.riskLevel],
                  border: `1px solid ${RISK_COLORS[sc.riskLevel]}30`,
                }}
              >
                <div
                  style={{
                    width: 10,
                    height: 10,
                    borderRadius: '50%',
                    backgroundColor: RISK_COLORS[sc.riskLevel],
                    marginTop: 4,
                    flexShrink: 0,
                  }}
                />
                <div style={{ flex: 1 }}>
                  <div className="flex items-center gap-2 mb-1">
                    <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary, #e6edf3)' }}>
                      {sc.name || sc.id}
                    </span>
                    <span
                      style={{
                        fontSize: 9,
                        fontWeight: 700,
                        padding: '1px 6px',
                        borderRadius: 4,
                        backgroundColor: `${RISK_COLORS[sc.riskLevel]}25`,
                        color: RISK_COLORS[sc.riskLevel],
                        border: `1px solid ${RISK_COLORS[sc.riskLevel]}40`,
                        textTransform: 'uppercase',
                      }}
                    >
                      {RISK_LABELS[sc.riskLevel]}
                    </span>
                  </div>
                  <p style={{ fontSize: 11, color: 'var(--text-muted, #6e7681)', marginBottom: 4 }}>
                    Impact: {LEVELS[sc.impactIdx]} | Likelihood: {LEVELS[sc.likelihoodIdx]}
                  </p>
                  <div className="flex items-start gap-1" style={{ fontSize: 11, color: 'var(--text-secondary, #8b949e)' }}>
                    <TrendingUp style={{ width: 12, height: 12, marginTop: 1, flexShrink: 0 }} />
                    <span>{getRecommendation(sc.riskLevel)}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {placements.length === 0 && (
        <div className="card" style={{ padding: 40, textAlign: 'center' }}>
          <Info style={{ width: 32, height: 32, color: 'var(--text-muted, #6e7681)', margin: '0 auto 12px' }} />
          <p style={{ fontSize: 14, color: 'var(--text-muted, #6e7681)' }}>
            No scenarios loaded. Scenarios will be plotted on the matrix based on their severity and detection scores.
          </p>
        </div>
      )}
    </div>
  )
}
