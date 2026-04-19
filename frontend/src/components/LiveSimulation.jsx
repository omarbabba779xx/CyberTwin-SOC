import React, { useState, useEffect, useRef, useCallback } from 'react'

/**
 * LiveSimulation — Full-screen WebSocket-driven simulation overlay.
 *
 * Connects to  ws://localhost:8000/ws/simulate/{scenarioId}  and streams
 * events, alerts, phases, scores, and AI analysis in real time with
 * dramatic terminal-style visuals suitable for an academic defense demo.
 */
export default function LiveSimulation({ scenarioId, onComplete, onCancel }) {
  // ---- state ----
  const [status, setStatus] = useState('connecting') // connecting | streaming | complete | error
  const [scenarioName, setScenarioName] = useState('')
  const [totalEvents, setTotalEvents] = useState(0)
  const [totalPhases, setTotalPhases] = useState(0)
  const [severity, setSeverity] = useState('')
  const [threatActor, setThreatActor] = useState('')

  const [events, setEvents] = useState([])
  const [alerts, setAlerts] = useState([])
  const [incidents, setIncidents] = useState([])
  const [currentPhase, setCurrentPhase] = useState(null)
  const [phaseHistory, setPhaseHistory] = useState([])
  const [progress, setProgress] = useState(0)
  const [scores, setScores] = useState(null)
  const [aiAnalysis, setAiAnalysis] = useState(null)
  const [errorMsg, setErrorMsg] = useState('')

  // Counters (track independently so we don't lose count when trimming displayed events)
  const totalEventsReceived = useRef(0)
  const totalMalicious = useRef(0)
  const totalBenign = useRef(0)
  const benignSkipCounter = useRef(0)

  // Visual effects
  const [alertFlash, setAlertFlash] = useState(false)
  const [malFlash, setMalFlash] = useState(false)

  // Refs
  const logRef = useRef(null)
  const wsRef = useRef(null)
  const resultRef = useRef(null)

  // ---- WebSocket connection ----
  useEffect(() => {
    const wsUrl = `ws://localhost:8000/ws/simulate/${scenarioId}`
    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onopen = () => {
      setStatus('connecting') // waiting for start message
    }

    ws.onmessage = (evt) => {
      const msg = JSON.parse(evt.data)

      switch (msg.type) {
        case 'start':
          setStatus('streaming')
          setScenarioName(msg.scenario || scenarioId)
          setTotalEvents(msg.total_events || 0)
          setTotalPhases(msg.total_phases || 0)
          setSeverity(msg.severity || '')
          setThreatActor(msg.threat_actor || '')
          break

        case 'event': {
          const eventData = msg.data
          totalEventsReceived.current += 1
          setProgress(msg.progress || 0)

          if (eventData?.is_malicious) {
            totalMalicious.current += 1
            // Show ALL malicious events
            setEvents(prev => {
              const next = [...prev, eventData]
              return next.length > 50 ? next.slice(-50) : next
            })
            setMalFlash(true)
            setTimeout(() => setMalFlash(false), 350)
          } else {
            totalBenign.current += 1
            benignSkipCounter.current += 1
            // Only show 1 in every 10 benign events
            if (benignSkipCounter.current >= 10) {
              benignSkipCounter.current = 0
              setEvents(prev => {
                const next = [...prev, eventData]
                return next.length > 50 ? next.slice(-50) : next
              })
            }
          }
          break
        }

        case 'phase':
          setCurrentPhase(msg)
          setPhaseHistory(prev => [...prev, msg])
          break

        case 'alert':
          setAlerts(prev => [...prev, msg.data])
          setAlertFlash(true)
          setTimeout(() => setAlertFlash(false), 500)
          break

        case 'incident':
          setIncidents(prev => [...prev, msg.data])
          break

        case 'scores':
          setScores(msg.data)
          break

        case 'ai_analysis':
          setAiAnalysis(msg.data)
          break

        case 'complete':
          setStatus('complete')
          resultRef.current = msg.data
          break

        case 'error':
          setStatus('error')
          setErrorMsg(msg.message || 'Unknown error')
          break

        default:
          break
      }
    }

    ws.onerror = () => {
      setStatus('error')
      setErrorMsg('WebSocket connection failed. Is the backend running on port 8000?')
    }

    ws.onclose = () => {
      setStatus(prev => prev === 'complete' ? prev : prev === 'error' ? prev : 'error')
    }

    return () => {
      ws.close()
    }
  }, [scenarioId])

  // Auto-scroll event log
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight
    }
  }, [events])

  // Auto-close after completion delay (3 seconds)
  useEffect(() => {
    if (status === 'complete' && resultRef.current) {
      const t = setTimeout(() => {
        onComplete(resultRef.current)
      }, 3000)
      return () => clearTimeout(t)
    }
  }, [status, onComplete])

  // ---- derived stats ----
  const maliciousCount = totalMalicious.current
  const benignCount = totalBenign.current
  const eventsProcessed = totalEventsReceived.current
  const pct = Math.round(progress)

  // ---- helpers ----
  const formatTime = (ts) => {
    if (!ts) return '??:??:??'
    const t = ts.split('T')[1]
    return t ? t.slice(0, 8) : ts.slice(0, 8)
  }

  const severityColor = (s) => {
    if (s === 'critical') return '#ef4444'
    if (s === 'high') return '#f97316'
    if (s === 'medium') return '#eab308'
    return '#e63946'
  }

  const severityBadgeClass = (s) => {
    if (s === 'critical') return 'badge-critical'
    if (s === 'high') return 'badge-high'
    if (s === 'medium') return 'badge-medium'
    return 'badge-low'
  }

  // ---- render ----
  return (
    <div
      className="fixed inset-0 z-[9999] flex flex-col"
      style={{
        background: alertFlash
          ? 'rgb(30, 10, 10)'
          : malFlash
          ? 'rgb(20, 8, 8)'
          : 'rgb(2, 6, 23)',
        transition: 'background 0.25s ease',
        fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
      }}
    >
      {/* ===== CSS Animations ===== */}
      <style>{`
        @keyframes livePulse {
          0%, 100% { opacity: 1; box-shadow: 0 0 8px #ef4444; }
          50% { opacity: 0.25; box-shadow: 0 0 2px #ef4444; }
        }
        @keyframes completePulse {
          0%, 100% { opacity: 1; box-shadow: 0 0 8px #22c55e; }
          50% { opacity: 0.5; box-shadow: 0 0 2px #22c55e; }
        }
        @keyframes malFlashAnim {
          0% { background: rgba(239,68,68,0.35); }
          100% { background: transparent; }
        }
        @keyframes glowBar {
          0%, 100% { box-shadow: 0 0 8px rgba(230,57,70,0.6); }
          50% { box-shadow: 0 0 24px rgba(230,57,70,0.9); }
        }
        @keyframes fadeInUp {
          from { opacity: 0; transform: translateY(8px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes scoreGlow {
          0%, 100% { text-shadow: 0 0 20px rgba(230,57,70,0.5), 0 0 40px rgba(230,57,70,0.3); }
          50% { text-shadow: 0 0 40px rgba(230,57,70,0.8), 0 0 80px rgba(230,57,70,0.5); }
        }
        @keyframes completeFadeIn {
          from { opacity: 0; transform: scale(0.9); }
          to { opacity: 1; transform: scale(1); }
        }
        .live-event-enter {
          animation: fadeInUp 0.15s ease-out;
        }
        .mal-event {
          animation: malFlashAnim 0.6s ease-out;
        }
        .glow-progress {
          animation: glowBar 2s ease-in-out infinite;
        }
        .live-dot {
          animation: livePulse 1s ease-in-out infinite;
        }
        .complete-dot {
          animation: completePulse 1.5s ease-in-out infinite;
        }
        .score-glow {
          animation: scoreGlow 2s ease-in-out infinite;
        }
        .complete-screen {
          animation: completeFadeIn 0.5s ease-out;
        }
        /* Scanline effect */
        .scanline-overlay {
          background: repeating-linear-gradient(
            0deg,
            transparent,
            transparent 2px,
            rgba(0, 255, 200, 0.02) 2px,
            rgba(0, 255, 200, 0.02) 4px
          );
          pointer-events: none;
        }
        .scanline-overlay::after {
          content: '';
          position: absolute;
          inset: 0;
          background: linear-gradient(
            180deg,
            transparent 0%,
            rgba(0, 255, 200, 0.03) 50%,
            transparent 100%
          );
          height: 100px;
          animation: scanlineMove 3s linear infinite;
        }
        @keyframes scanlineMove {
          0% { transform: translateY(-100px); }
          100% { transform: translateY(100vh); }
        }
        /* Custom scrollbar */
        .sim-scroll::-webkit-scrollbar { width: 6px; }
        .sim-scroll::-webkit-scrollbar-track { background: rgba(0,0,0,0.3); }
        .sim-scroll::-webkit-scrollbar-thumb { background: rgba(230,57,70,0.3); border-radius: 3px; }
        .sim-scroll::-webkit-scrollbar-thumb:hover { background: rgba(230,57,70,0.5); }
      `}</style>

      {/* ===== SCANLINE EFFECT ===== */}
      {status === 'streaming' && (
        <div className="absolute inset-0 scanline-overlay" style={{ zIndex: 1 }} />
      )}

      {/* ===== COMPLETION OVERLAY ===== */}
      {status === 'complete' && (
        <div
          className="absolute inset-0 flex items-center justify-center complete-screen"
          style={{ zIndex: 100, background: 'rgba(2, 6, 23, 0.95)' }}
        >
          <div className="text-center">
            <div className="text-xs uppercase tracking-[0.3em] text-[#e63946] mb-4 font-bold">
              SIMULATION COMPLETE
            </div>
            <div className="score-glow mb-6" style={{ fontSize: 72, fontWeight: 900, color: '#e63946', lineHeight: 1 }}>
              {scores?.overall_score ?? resultRef.current?.overall_score ?? '---'}
              <span style={{ fontSize: 28, color: '#e63946', opacity: 0.7 }}>/100</span>
            </div>
            {(scores?.risk_level || resultRef.current?.risk_level) && (
              <div className="mb-4">
                <span
                  className={severityBadgeClass(
                    (scores?.risk_level || resultRef.current?.risk_level || '').toLowerCase()
                  )}
                  style={{ fontSize: 14, padding: '6px 20px' }}
                >
                  {scores?.risk_level || resultRef.current?.risk_level}
                </span>
              </div>
            )}
            <div className="flex items-center justify-center gap-8 mt-6">
              <div className="text-center">
                <div style={{ fontSize: 28, fontWeight: 800, color: '#f97316' }}>{alerts.length}</div>
                <div className="text-xs text-gray-500 uppercase tracking-wider mt-1">Alerts Detected</div>
              </div>
              <div style={{ width: 1, height: 40, background: 'rgba(55,65,81,0.5)' }} />
              <div className="text-center">
                <div style={{ fontSize: 28, fontWeight: 800, color: '#ef4444' }}>{maliciousCount}</div>
                <div className="text-xs text-gray-500 uppercase tracking-wider mt-1">Malicious Events</div>
              </div>
              <div style={{ width: 1, height: 40, background: 'rgba(55,65,81,0.5)' }} />
              <div className="text-center">
                <div style={{ fontSize: 28, fontWeight: 800, color: '#e63946' }}>{eventsProcessed}</div>
                <div className="text-xs text-gray-500 uppercase tracking-wider mt-1">Total Events</div>
              </div>
            </div>
            <div className="text-xs text-gray-600 mt-8 animate-pulse">
              Redirecting to dashboard...
            </div>
          </div>
        </div>
      )}

      {/* ===== TOP BAR ===== */}
      <div
        className="flex items-center justify-between px-6 py-3 border-b"
        style={{
          borderColor: status === 'complete' ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.2)',
          background: 'rgba(2, 6, 23, 0.8)',
          backdropFilter: 'blur(12px)',
          zIndex: 10,
        }}
      >
        {/* Left: Live indicator */}
        <div className="flex items-center gap-3">
          <div
            className={status === 'complete' ? 'complete-dot' : 'live-dot'}
            style={{
              width: 12, height: 12, borderRadius: '50%',
              background: status === 'complete' ? '#22c55e' : status === 'error' ? '#6b7280' : '#ef4444',
            }}
          />
          <span
            className="text-sm font-bold uppercase tracking-[0.2em]"
            style={{
              color: status === 'connecting' ? '#e63946'
                : status === 'complete' ? '#22c55e'
                : status === 'error' ? '#ef4444'
                : '#ef4444',
            }}
          >
            {status === 'connecting' && 'INITIALIZING SIMULATION ENGINE...'}
            {status === 'streaming' && 'LIVE SIMULATION IN PROGRESS'}
            {status === 'complete' && 'SIMULATION COMPLETE'}
            {status === 'error' && 'SIMULATION ERROR'}
          </span>
        </div>

        {/* Center: Scenario name + severity + threat actor */}
        <div className="flex items-center gap-3">
          <span className="text-sm text-gray-300 font-semibold">{scenarioName}</span>
          {threatActor && threatActor !== 'Unknown' && (
            <span className="text-[10px] px-2 py-0.5 rounded bg-[#f4a261]/20 text-[#f4a261] border border-[#f4a261]/30 font-bold">
              {threatActor}
            </span>
          )}
          {severity && (
            <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase tracking-wider ${severityBadgeClass(severity)}`}>
              {severity}
            </span>
          )}
        </div>

        {/* Right: Close button */}
        <button
          onClick={onCancel}
          className="text-gray-500 hover:text-white transition-colors px-3 py-1.5 rounded hover:bg-gray-800 border border-gray-700/50 text-xs font-bold tracking-wider"
          title="Close simulation"
        >
          ESC
        </button>
      </div>

      {/* ===== MAIN CONTENT ===== */}
      <div className="flex-1 flex overflow-hidden" style={{ zIndex: 2 }}>

        {/* ---- LEFT: Event Log (70%) ---- */}
        <div className="flex flex-col" style={{ width: '70%', borderRight: '1px solid rgba(55,65,81,0.3)' }}>
          {/* Log header */}
          <div
            className="px-4 py-2 border-b flex items-center justify-between"
            style={{ borderColor: 'rgba(55,65,81,0.3)', background: 'rgba(2, 6, 23, 0.6)' }}
          >
            <div className="flex items-center gap-2">
              <span className="text-xs text-[#e63946] font-bold tracking-wider">EVENT STREAM</span>
              <span className="text-[10px] text-gray-700 font-mono">
                [showing {events.length} of {eventsProcessed} processed]
              </span>
            </div>
            <span className="text-xs text-gray-600 font-mono tabular-nums">
              {eventsProcessed} / {totalEvents} events
            </span>
          </div>

          {/* Log body */}
          <div
            ref={logRef}
            className="flex-1 overflow-y-auto px-4 py-2 sim-scroll"
            style={{ background: 'rgba(0,0,0,0.3)', lineHeight: '1.6', fontFamily: "'JetBrains Mono', 'Fira Code', monospace" }}
          >
            {/* Connecting state */}
            {status === 'connecting' && (
              <div className="flex items-center gap-2 py-8 justify-center">
                <div
                  style={{
                    width: 16, height: 16,
                    border: '2px solid #e63946',
                    borderTopColor: 'transparent',
                    borderRadius: '50%',
                    animation: 'spin 0.8s linear infinite',
                  }}
                />
                <span className="text-[#e63946] text-sm animate-pulse">
                  Running simulation engine... Generating telemetry...
                </span>
              </div>
            )}

            {/* Event list */}
            {events.map((e, i) => {
              const isMal = e.is_malicious
              return (
                <div
                  key={i}
                  className={`text-xs py-[2px] live-event-enter ${isMal ? 'mal-event' : ''}`}
                  style={{
                    color: isMal ? '#fca5a5' : 'rgba(148, 163, 184, 0.35)',
                    borderLeft: isMal ? '3px solid #ef4444' : '2px solid transparent',
                    paddingLeft: 10,
                    marginBottom: 1,
                    background: isMal ? 'rgba(239, 68, 68, 0.05)' : 'transparent',
                  }}
                >
                  <span style={{ color: '#4b5563', fontSize: 10 }}>
                    [{formatTime(e.timestamp)}]
                  </span>{' '}
                  <span
                    style={{
                      color: isMal ? '#f87171' : '#4b5563',
                      fontWeight: isMal ? 700 : 400,
                    }}
                  >
                    {e.event_type}
                  </span>{' '}
                  {e.host && (
                    <span style={{ color: isMal ? '#fbbf24' : '#374151', fontSize: 10 }}>
                      [{e.host}]
                    </span>
                  )}{' '}
                  <span style={{ color: isMal ? '#fca5a5' : '#374151' }}>
                    {(e.description || '').slice(0, 120)}
                  </span>
                  {e.technique_id && (
                    <span style={{ color: '#e63946', marginLeft: 6, fontSize: 10, fontWeight: 600 }}>
                      [{e.technique_id}]
                    </span>
                  )}
                  {isMal && (
                    <span
                      style={{
                        marginLeft: 8,
                        color: '#000',
                        background: '#ef4444',
                        fontWeight: 800,
                        fontSize: 9,
                        letterSpacing: '0.12em',
                        padding: '1px 6px',
                        borderRadius: 3,
                      }}
                    >
                      MALICIOUS
                    </span>
                  )}
                </div>
              )
            })}
          </div>
        </div>

        {/* ---- RIGHT: Stats Panel (30%) ---- */}
        <div
          className="flex flex-col overflow-y-auto sim-scroll"
          style={{ width: '30%', background: 'rgba(2, 6, 23, 0.6)', padding: 20, gap: 16 }}
        >
          {/* Phase indicator */}
          {currentPhase && (
            <div
              className="card"
              style={{
                background: 'rgba(244,162,97,0.08)',
                border: '1px solid rgba(244,162,97,0.3)',
                borderRadius: 10,
                padding: '12px 14px',
              }}
            >
              <div className="text-[10px] text-[#f4a261] font-bold uppercase tracking-wider mb-1">
                CURRENT PHASE {(currentPhase.phase_index || 0) + 1}/{totalPhases}
              </div>
              <div className="text-sm text-[#f4a261] font-semibold">
                {currentPhase.phase_name}
              </div>
              {currentPhase.technique_id && (
                <div className="text-[10px] mt-1.5 flex items-center gap-2">
                  <span className="text-[#e63946] font-mono font-bold">{currentPhase.technique_id}</span>
                  <span className="text-gray-500">/</span>
                  <span className="text-[#f4a261]/70 capitalize">{currentPhase.tactic}</span>
                </div>
              )}
            </div>
          )}

          {/* Progress */}
          <div>
            <div className="flex justify-between text-[10px] text-gray-500 mb-2 uppercase tracking-wider">
              <span>Progress</span>
              <span className="text-[#e63946] font-bold tabular-nums">{pct}%</span>
            </div>
            <div
              style={{
                height: 10, background: 'rgba(17, 24, 39, 0.8)', borderRadius: 5, overflow: 'hidden',
                border: '1px solid rgba(230,57,70,0.15)',
              }}
            >
              <div
                className="glow-progress"
                style={{
                  height: '100%', borderRadius: 5,
                  width: `${pct}%`,
                  background: 'linear-gradient(90deg, #e63946, #f4a261, #ec4899)',
                  transition: 'width 0.3s ease',
                }}
              />
            </div>
          </div>

          {/* Stats Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            {[
              { label: 'Events', value: eventsProcessed, color: '#e63946', icon: '>' },
              { label: 'Malicious', value: maliciousCount, color: '#ef4444', icon: '!' },
              { label: 'Alerts', value: alerts.length, color: '#f97316', icon: '\u26A0' },
              { label: 'Benign', value: benignCount, color: '#22c55e', icon: '\u2713' },
            ].map(item => (
              <div
                key={item.label}
                style={{
                  background: item.label === 'Alerts' && alertFlash
                    ? 'rgba(249,115,22,0.15)'
                    : 'rgba(2, 6, 23, 0.7)',
                  border: item.label === 'Alerts' && alertFlash
                    ? '1px solid rgba(249,115,22,0.5)'
                    : '1px solid rgba(55,65,81,0.4)',
                  borderRadius: 10,
                  padding: '14px 8px',
                  textAlign: 'center',
                  transition: 'all 0.3s',
                }}
              >
                <div className="stat-number" style={{ fontSize: 24, fontWeight: 800, color: item.color, lineHeight: 1 }}>
                  {item.value}
                </div>
                <div style={{ fontSize: 10, color: '#6b7280', marginTop: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                  {item.label}
                </div>
              </div>
            ))}
          </div>

          {/* Alert Feed */}
          <div>
            <div className="text-[10px] text-orange-400 font-bold uppercase tracking-wider mb-2">
              ALERT FEED
            </div>
            <div style={{ maxHeight: 200, overflowY: 'auto' }} className="sim-scroll space-y-2">
              {alerts.length === 0 && (
                <div className="text-gray-700 text-xs italic">Monitoring for threats...</div>
              )}
              {alerts.slice(-10).map((a, i) => (
                <div
                  key={i}
                  className="live-event-enter"
                  style={{
                    background: 'rgba(239,68,68,0.06)',
                    border: '1px solid rgba(239,68,68,0.2)',
                    borderRadius: 8,
                    padding: '8px 10px',
                    fontSize: 11,
                  }}
                >
                  <div style={{ color: '#fca5a5', fontWeight: 600 }}>
                    {a.rule_name || a.name || 'Alert'}
                  </div>
                  <div style={{ color: '#6b7280', fontSize: 10, marginTop: 2 }}>
                    {a.technique_id && <span style={{ color: '#e63946' }}>{a.technique_id}</span>}
                    {a.affected_host && <span> &mdash; {a.affected_host}</span>}
                    {a.severity && (
                      <span
                        style={{
                          marginLeft: 6,
                          color: severityColor(a.severity),
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          fontSize: 9,
                        }}
                      >
                        {a.severity}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Incidents */}
          {incidents.length > 0 && (
            <div>
              <div className="text-[10px] text-red-400 font-bold uppercase tracking-wider mb-2">
                INCIDENTS DETECTED
              </div>
              {incidents.slice(-4).map((inc, i) => (
                <div
                  key={i}
                  className="live-event-enter"
                  style={{
                    background: 'rgba(239,68,68,0.08)',
                    border: '1px solid rgba(239,68,68,0.3)',
                    borderRadius: 8,
                    padding: '8px 10px',
                    fontSize: 11,
                    marginBottom: 6,
                  }}
                >
                  <div style={{ color: '#f87171', fontWeight: 700 }}>{inc.name || inc.title || 'Incident'}</div>
                  <div style={{ color: '#9ca3af', fontSize: 10, marginTop: 2 }}>
                    {inc.description?.slice(0, 80) || `${inc.alert_count || 0} correlated alerts`}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Final Scores */}
          {scores && status !== 'complete' && (
            <div
              className="live-event-enter"
              style={{
                background: 'rgba(2, 6, 23, 0.8)',
                border: '1px solid rgba(230,57,70,0.3)',
                borderRadius: 12,
                padding: 16,
              }}
            >
              <div className="text-[10px] text-[#e63946] font-bold uppercase tracking-wider mb-3">
                FINAL ASSESSMENT
              </div>
              {['overall', 'detection', 'coverage', 'visibility'].map(key => {
                const label = key.charAt(0).toUpperCase() + key.slice(1)
                const val = scores[`${key}_score`] || 0
                const color = key === 'overall'
                  ? (val >= 70 ? '#22c55e' : val >= 40 ? '#f59e0b' : '#ef4444')
                  : key === 'detection' ? '#e63946'
                  : key === 'coverage' ? '#f4a261'
                  : '#22c55e'
                return (
                  <div key={key} className="flex items-center gap-2 mb-2">
                    <span style={{ fontSize: 11, color: '#9ca3af', width: 70 }}>{label}</span>
                    <div style={{ flex: 1, height: 6, background: '#1f2937', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{ height: '100%', borderRadius: 3, width: `${val}%`, background: color, transition: 'width 1s ease' }} />
                    </div>
                    <span style={{ fontSize: 11, fontWeight: 700, width: 36, textAlign: 'right', color, fontVariantNumeric: 'tabular-nums' }}>
                      {val}%
                    </span>
                  </div>
                )
              })}
            </div>
          )}

          {/* AI Analysis teaser */}
          {aiAnalysis?.executive_narrative && (
            <div
              className="live-event-enter"
              style={{
                background: 'rgba(230,57,70,0.04)',
                border: '1px solid rgba(230,57,70,0.2)',
                borderRadius: 8,
                padding: '10px 12px',
              }}
            >
              <div className="text-[10px] text-[#e63946] font-bold uppercase tracking-wider mb-2">
                AI ANALYST SUMMARY
              </div>
              <div style={{ fontSize: 11, color: '#9ca3af', lineHeight: 1.5 }}>
                {aiAnalysis.executive_narrative.slice(0, 200)}
                {aiAnalysis.executive_narrative.length > 200 ? '...' : ''}
              </div>
            </div>
          )}

          {/* Error message */}
          {status === 'error' && (
            <div
              style={{
                background: 'rgba(239,68,68,0.08)',
                border: '1px solid rgba(239,68,68,0.3)',
                borderRadius: 8,
                padding: '12px 14px',
              }}
            >
              <div style={{ color: '#ef4444', fontWeight: 700, fontSize: 12 }}>Connection Error</div>
              <div style={{ color: '#9ca3af', fontSize: 11, marginTop: 4 }}>{errorMsg}</div>
              <button
                onClick={onCancel}
                style={{
                  marginTop: 8, padding: '6px 16px', fontSize: 11,
                  background: 'rgba(239,68,68,0.15)',
                  border: '1px solid rgba(239,68,68,0.4)',
                  borderRadius: 6, color: '#fca5a5', cursor: 'pointer',
                }}
              >
                Close
              </button>
            </div>
          )}
        </div>
      </div>

      {/* ===== BOTTOM PROGRESS BAR ===== */}
      <div style={{ height: 4, background: 'rgba(17, 24, 39, 0.8)', zIndex: 10 }}>
        <div
          className={pct > 0 && pct < 100 ? 'glow-progress' : ''}
          style={{
            height: '100%',
            width: `${pct}%`,
            background: status === 'complete'
              ? 'linear-gradient(90deg, #22c55e, #e63946)'
              : 'linear-gradient(90deg, #e63946, #f4a261, #ec4899)',
            transition: 'width 0.3s ease',
          }}
        />
      </div>
    </div>
  )
}
