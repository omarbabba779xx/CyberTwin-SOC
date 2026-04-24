import React, { useState, useEffect } from 'react'
import {
  Shield, LayoutDashboard, Target, AlertTriangle, Clock, Grid3X3,
  FileText, Network, Brain, Radar, GitCompare, PenTool, Sun, Moon, LogOut,
  Globe, BarChart3, GitBranch, Cpu, BookOpen, Zap
} from 'lucide-react'
import { LANGUAGES } from '../i18n'

const NAV_SECTIONS = [
  {
    label: 'Overview',
    items: [
      { id: 'dashboard', label: 'Dashboard', labelKey: 'nav.dashboard', icon: LayoutDashboard },
      { id: 'scenarios', label: 'Scenarios', labelKey: 'nav.scenarios', icon: Target },
    ]
  },
  {
    label: 'Analysis',
    items: [
      { id: 'alerts', label: 'Alerts', labelKey: 'nav.alerts', icon: AlertTriangle },
      { id: 'timeline', label: 'Timeline', labelKey: 'nav.timeline', icon: Clock },
      { id: 'mitre', label: 'MITRE ATT&CK', labelKey: 'nav.mitre', icon: Grid3X3 },
      { id: 'logs', label: 'Log Explorer', labelKey: 'nav.logs', icon: FileText },
      { id: 'attack-tree', label: 'Attack Tree', labelKey: 'nav.attackTree', icon: GitBranch },
      { id: 'anomaly', label: 'Anomaly Detection', labelKey: 'nav.anomaly', icon: Cpu, tag: 'ML' },
      { id: 'maturity', label: 'Maturity', labelKey: 'nav.maturity', icon: Shield },
      { id: 'analytics', label: 'Analytics', labelKey: 'nav.analytics', icon: BarChart3 },
    ]
  },
  {
    label: 'Intelligence',
    items: [
      { id: 'network', label: 'Network Map', labelKey: 'nav.network', icon: Network },
      { id: 'ai', label: 'AI Analyst', labelKey: 'nav.ai', icon: Brain, tag: 'AI' },
      { id: 'threat-intel', label: 'Threat Intel', labelKey: 'nav.threatIntel', icon: Radar, tag: 'NEW' },
      { id: 'threat-map', label: 'Threat Map', labelKey: 'nav.threatMap', icon: Globe },
    ]
  },
  {
    label: 'Tools',
    items: [
      { id: 'benchmark', label: 'Benchmark', labelKey: 'nav.benchmark', icon: BookOpen, tag: 'NEW' },
      { id: 'risk-matrix', label: 'Risk Matrix', labelKey: 'nav.riskMatrix', icon: AlertTriangle },
      { id: 'report', label: 'Report', labelKey: 'nav.report', icon: FileText },
      { id: 'comparison', label: 'Compare', labelKey: 'nav.comparison', icon: GitCompare },
      { id: 'builder', label: 'Builder', labelKey: 'nav.builder', icon: PenTool },
    ]
  }
]

const alwaysEnabled = ['dashboard', 'scenarios', 'network', 'builder', 'comparison', 'threat-intel', 'threat-map', 'risk-matrix', 'maturity', 'analytics', 'benchmark']

export default function Sidebar({ page, setPage, hasResult, onLogout, i18n, onLangChange, llmStatus }) {
  const t = i18n?.t || ((k) => k)
  const currentLang = i18n?.lang || 'fr'

  const [isDark, setIsDark] = useState(() => {
    return !document.documentElement.classList.contains('light')
  })

  const toggleTheme = () => {
    document.documentElement.classList.toggle('light')
    const isNowDark = !document.documentElement.classList.contains('light')
    setIsDark(isNowDark)
    localStorage.setItem('theme', isNowDark ? 'dark' : 'light')
  }

  return (
    <aside
      className="flex flex-col"
      style={{
        width: 240,
        minWidth: 240,
        backgroundColor: 'var(--bg-sidebar, #0d1117)',
        borderRight: '1px solid var(--border, #21262d)',
        height: '100vh',
      }}
    >
      {/* Logo */}
      <div style={{ padding: '20px 16px 16px', borderBottom: '1px solid var(--border, #21262d)' }}>
        <div className="flex items-center gap-3">
          <div
            className="flex items-center justify-center"
            style={{
              width: 36,
              height: 36,
              borderRadius: '50%',
              backgroundColor: 'rgba(230, 57, 70, 0.15)',
              border: '1px solid rgba(230, 57, 70, 0.3)',
            }}
          >
            <Shield className="w-5 h-5" style={{ color: '#e63946' }} />
          </div>
          <div>
            <span
              className="font-bold text-base"
              style={{ color: 'var(--text-primary, #e6edf3)' }}
            >
              CyberTwin
            </span>
            <span
              className="font-bold text-base ml-1"
              style={{ color: '#e63946' }}
            >
              SOC
            </span>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-3 px-3 space-y-4">
        {NAV_SECTIONS.map((section) => (
          <div key={section.label}>
            <p
              style={{
                fontSize: 11,
                fontWeight: 600,
                color: 'var(--text-muted, #6e7681)',
                textTransform: 'uppercase',
                letterSpacing: '0.1em',
                padding: '0 8px',
                marginBottom: 6,
              }}
            >
              {section.label}
            </p>

            <div className="space-y-0.5">
              {section.items.map((item) => {
                const Icon = item.icon
                const active = page === item.id
                const disabled = !hasResult && !alwaysEnabled.includes(item.id)

                return (
                  <button
                    key={item.id}
                    onClick={() => !disabled && setPage(item.id)}
                    disabled={disabled}
                    className={`sidebar-link w-full flex items-center gap-3 ${active ? 'active' : ''}`}
                    style={disabled ? { opacity: 0.35, cursor: 'not-allowed' } : {}}
                  >
                    <Icon style={{ width: 18, height: 18, flexShrink: 0 }} />
                    <span className="flex-1 text-left">{item.labelKey ? t(item.labelKey) : item.label}</span>

                    {item.tag && (
                      <span
                        style={{
                          fontSize: 9,
                          fontWeight: 700,
                          padding: '1px 6px',
                          borderRadius: 9999,
                          backgroundColor: item.tag === 'AI'
                            ? 'rgba(69, 123, 157, 0.2)'
                            : 'rgba(230, 57, 70, 0.15)',
                          color: item.tag === 'AI' ? '#457b9d' : '#e63946',
                          border: `1px solid ${item.tag === 'AI'
                            ? 'rgba(69, 123, 157, 0.3)'
                            : 'rgba(230, 57, 70, 0.3)'}`,
                        }}
                      >
                        {item.tag}
                      </span>
                    )}
                  </button>
                )
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Bottom area */}
      <div style={{ padding: '12px 12px 16px', borderTop: '1px solid var(--border, #21262d)' }}>
        {/* Simulation status indicator */}
        <div className="flex items-center gap-2 px-2 mb-2">
          <div
            style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              backgroundColor: hasResult ? '#3fb950' : '#6e7681',
              boxShadow: hasResult ? '0 0 6px rgba(63, 185, 80, 0.4)' : 'none',
            }}
          />
          <span
            style={{
              fontSize: 12,
              fontWeight: 500,
              color: hasResult ? '#3fb950' : 'var(--text-muted, #6e7681)',
            }}
          >
            {hasResult ? 'Simulation Active' : 'No Simulation'}
          </span>
        </div>

        {/* LLM status indicator */}
        <div className="flex items-center gap-2 px-2 mb-3">
          <Zap
            style={{
              width: 12,
              height: 12,
              color: llmStatus === 'ollama'
                ? '#a5d8ff'
                : llmStatus === 'nlg'
                ? '#ffd166'
                : '#6e7681',
              flexShrink: 0,
            }}
          />
          <span
            style={{
              fontSize: 11,
              color: llmStatus === 'ollama'
                ? '#a5d8ff'
                : llmStatus === 'nlg'
                ? '#ffd166'
                : '#6e7681',
            }}
          >
            {llmStatus === 'ollama'
              ? 'Ollama LLM'
              : llmStatus === 'nlg'
              ? 'NLG Fallback'
              : 'AI: Standby'}
          </span>
        </div>

        {/* Language Toggle */}
        <div className="flex items-center gap-1 px-1 mb-2">
          {LANGUAGES.map((lang) => (
            <button
              key={lang.code}
              onClick={() => {
                localStorage.setItem('lang', lang.code)
                if (onLangChange) onLangChange(lang.code)
              }}
              className="flex items-center gap-1.5 flex-1 justify-center"
              style={{
                padding: '5px 8px',
                borderRadius: 6,
                fontSize: 12,
                fontWeight: currentLang === lang.code ? 700 : 500,
                color: currentLang === lang.code ? '#e6edf3' : '#6e7681',
                backgroundColor: currentLang === lang.code ? 'rgba(230, 57, 70, 0.15)' : 'transparent',
                border: currentLang === lang.code ? '1px solid rgba(230, 57, 70, 0.3)' : '1px solid transparent',
                cursor: 'pointer',
                transition: 'all 0.15s',
              }}
            >
              <span style={{ fontSize: 14 }}>{lang.flag}</span>
              <span>{lang.code.toUpperCase()}</span>
            </button>
          ))}
        </div>

        {/* Theme toggle */}
        <button
          onClick={toggleTheme}
          className="sidebar-link w-full flex items-center gap-3"
        >
          {isDark ? <Sun style={{ width: 16, height: 16 }} /> : <Moon style={{ width: 16, height: 16 }} />}
          <span>{isDark ? 'Light Mode' : 'Dark Mode'}</span>
        </button>

        {/* Logout */}
        {onLogout && (
          <button
            onClick={onLogout}
            className="w-full flex items-center gap-3"
            style={{
              padding: '8px 12px',
              borderRadius: 6,
              fontSize: 13,
              fontWeight: 500,
              color: 'var(--text-secondary, #8b949e)',
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.15s',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.color = '#f85149'
              e.currentTarget.style.backgroundColor = 'rgba(248, 81, 73, 0.1)'
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.color = 'var(--text-secondary, #8b949e)'
              e.currentTarget.style.backgroundColor = 'transparent'
            }}
          >
            <LogOut style={{ width: 16, height: 16 }} />
            <span>Logout</span>
          </button>
        )}
      </div>
    </aside>
  )
}
