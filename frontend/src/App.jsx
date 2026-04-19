import React, { useState, useEffect, useMemo, Suspense } from 'react'
import Sidebar from './components/Sidebar'
import LiveSimulation from './components/LiveSimulation'
import SearchModal from './components/SearchModal'
import ShortcutsHelp from './components/ShortcutsHelp'
import useKeyboardShortcuts from './hooks/useKeyboardShortcuts'
import Login from './pages/Login'
import { createI18n } from './i18n'

// ─── Code-split page components with React.lazy ───
const Dashboard = React.lazy(() => import('./pages/Dashboard'))
const Scenarios = React.lazy(() => import('./pages/Scenarios'))
const Alerts = React.lazy(() => import('./pages/Alerts'))
const Timeline = React.lazy(() => import('./pages/Timeline'))
const MitreView = React.lazy(() => import('./pages/MitreView'))
const Logs = React.lazy(() => import('./pages/Logs'))
const Report = React.lazy(() => import('./pages/Report'))
const Network = React.lazy(() => import('./pages/Network'))
const AIAnalysis = React.lazy(() => import('./pages/AIAnalysis'))
const Comparison = React.lazy(() => import('./pages/Comparison'))
const ScenarioBuilder = React.lazy(() => import('./pages/ScenarioBuilder'))
const ThreatIntel = React.lazy(() => import('./pages/ThreatIntel'))
const ThreatMap = React.lazy(() => import('./pages/ThreatMap'))
const RiskMatrix = React.lazy(() => import('./pages/RiskMatrix'))
const Maturity = React.lazy(() => import('./pages/Maturity'))
const Analytics = React.lazy(() => import('./pages/Analytics'))
const AttackTree = React.lazy(() => import('./pages/AttackTree'))

// ─── Loading Fallback for Suspense ───
function LoadingFallback() {
  return (
    <div className="loading-fallback">
      <div className="flex flex-col items-center gap-4">
        <div className="loading-spinner" />
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Loading...</p>
      </div>
    </div>
  )
}

const API = 'http://localhost:8000'

export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(() => {
    return !!localStorage.getItem('cybertwin_token')
  })
  const [page, setPage] = useState('dashboard')
  const [scenarios, setScenarios] = useState([])
  const [selectedScenario, setSelectedScenario] = useState(null)
  const [simResult, setSimResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [environment, setEnvironment] = useState(null)
  const [techniques, setTechniques] = useState({})
  const [liveSimId, setLiveSimId] = useState(null)
  const [threatIntel, setThreatIntel] = useState(null)
  const [lang, setLang] = useState(() => localStorage.getItem('lang') || 'fr')
  const i18n = useMemo(() => createI18n(lang), [lang])

  const [history, setHistory] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('cybertwin_history') || '[]')
    } catch { return [] }
  })

  const [searchOpen, setSearchOpen] = useState(false)
  const [shortcutsOpen, setShortcutsOpen] = useState(false)

  useKeyboardShortcuts({
    setPage,
    setSearchOpen,
    setShortcutsOpen,
    searchOpen,
    shortcutsOpen,
  })

  // Initialize theme from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('theme')
    if (saved === 'light') document.documentElement.classList.add('light')
  }, [])

  useEffect(() => {
    if (!isLoggedIn) return
    fetch(`${API}/api/scenarios`).then(r => r.json()).then(setScenarios).catch(() => {})
    fetch(`${API}/api/environment`).then(r => r.json()).then(setEnvironment).catch(() => {})
    fetch(`${API}/api/mitre/techniques`).then(r => r.json()).then(setTechniques).catch(() => {})
    fetch(`${API}/api/threat-intel`).then(r => r.json()).then(setThreatIntel).catch(() => {})
  }, [isLoggedIn])

  useEffect(() => {
    localStorage.setItem('cybertwin_history', JSON.stringify(history.slice(-20)))
  }, [history])

  const handleLogin = () => {
    setIsLoggedIn(true)
  }

  const handleLogout = () => {
    localStorage.removeItem('cybertwin_token')
    localStorage.removeItem('cybertwin_user')
    setIsLoggedIn(false)
    setPage('dashboard')
    setSimResult(null)
  }

  const runSimulation = async (scenarioId) => {
    setLiveSimId(scenarioId)
    setSelectedScenario(scenarioId)
  }

  const onLiveComplete = (result) => {
    setSimResult(result)
    setLiveSimId(null)
    setHistory(prev => [...prev, { ...result, _timestamp: new Date().toISOString() }])
    setPage('dashboard')
  }

  if (!isLoggedIn) {
    return <Login onLogin={handleLogin} i18n={i18n} onLangChange={setLang} />
  }

  const hosts = environment ? Object.values(environment.hosts || {}) : []

  const pages = {
    dashboard: <Dashboard result={simResult} environment={environment} i18n={i18n} />,
    scenarios: <Scenarios scenarios={scenarios} onRun={runSimulation} loading={loading} />,
    builder: <ScenarioBuilder techniques={techniques} hosts={hosts} onRun={runSimulation} />,
    alerts: <Alerts alerts={simResult?.alerts} incidents={simResult?.incidents} />,
    timeline: <Timeline timeline={simResult?.timeline} scenario={simResult?.scenario} />,
    mitre: <MitreView coverage={simResult?.mitre_coverage} scores={simResult?.scores} />,
    logs: <Logs logs={simResult?.logs} stats={simResult?.logs_statistics} />,
    report: <Report report={simResult?.report} scores={simResult?.scores} />,
    network: <Network environment={environment} result={simResult} />,
    ai: <AIAnalysis analysis={simResult?.ai_analysis} />,
    'threat-intel': <ThreatIntel threatIntel={threatIntel} />,
    'threat-map': <ThreatMap result={simResult} scenarios={scenarios} />,
    'risk-matrix': <RiskMatrix result={simResult} scenarios={scenarios} />,
    maturity: <Maturity result={simResult} scores={simResult?.scores} />,
    analytics: <Analytics />,
    comparison: <Comparison history={history} />,
    'attack-tree': <AttackTree result={simResult} scenario={simResult?.scenario} i18n={i18n} />,
  }

  return (
    <div className="flex h-screen" style={{ backgroundColor: 'var(--bg-primary)' }}>
      <Sidebar page={page} setPage={setPage} hasResult={!!simResult} onLogout={handleLogout} i18n={i18n} onLangChange={setLang} />
      <main className="flex-1 overflow-y-auto p-6 flex flex-col min-h-screen">
        <Suspense fallback={<LoadingFallback />}>
          <div key={page} className="page-transition flex-1">
            {pages[page] || pages.dashboard}
          </div>
        </Suspense>

        {/* Footer */}
        <footer
          className="mt-auto py-4 px-6 text-center text-xs"
          style={{
            borderTop: '1px solid var(--border, #21262d)',
            color: 'var(--text-muted, #6e7681)',
          }}
        >
          <div className="flex items-center justify-between">
            <span>CyberTwin SOC v2.0 — {i18n.t('footer.platform')}</span>
            <span>{i18n.t('footer.copyright')}</span>
          </div>
        </footer>
      </main>

      {/* Live Simulation Overlay */}
      {liveSimId && (
        <LiveSimulation
          scenarioId={liveSimId}
          onComplete={onLiveComplete}
          onCancel={() => setLiveSimId(null)}
        />
      )}

      {/* Global Search Modal */}
      <SearchModal
        isOpen={searchOpen}
        onClose={() => setSearchOpen(false)}
        result={simResult}
        scenarios={scenarios}
        onNavigate={(p) => setPage(p)}
      />

      {/* Keyboard Shortcuts Help */}
      <ShortcutsHelp
        isOpen={shortcutsOpen}
        onClose={() => setShortcutsOpen(false)}
      />
    </div>
  )
}
