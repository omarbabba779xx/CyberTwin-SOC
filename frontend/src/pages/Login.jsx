import React, { useState } from 'react'
import { Shield, User, Lock, Eye, EyeOff, Cpu, Search, BarChart3 } from 'lucide-react'
import { LANGUAGES } from '../i18n'
import { apiUrl } from '../utils/api'

export default function Login({ onLogin, i18n, onLangChange }) {
  const t = i18n?.t || ((k) => k)
  const currentLang = i18n?.lang || 'fr'
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const res = await fetch(apiUrl('/api/auth/login'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })

      if (res.ok) {
        const data = await res.json()
        if (!data.token) throw new Error('Missing token in login response')
        localStorage.setItem('cybertwin_token', data.token)
        localStorage.setItem('cybertwin_user', username)
        onLogin()
      } else {
        const data = await res.json().catch(() => ({}))
        setError(data.detail || t('login.error'))
      }
    } catch {
      if (import.meta.env.VITE_ENABLE_DEMO_LOGIN === 'true' && username === 'admin' && password === 'cybertwin2024') {
        localStorage.setItem('cybertwin_token', 'demo-token')
        localStorage.setItem('cybertwin_user', username)
        onLogin()
      } else {
        setError(t('login.error'))
      }
    } finally {
      setLoading(false)
    }
  }

  const features = [
    { icon: Cpu, title: 'Simulation', desc: 'Jumeau numerique temps reel' },
    { icon: Search, title: 'Detection', desc: 'Analyse des menaces avancees' },
    { icon: BarChart3, title: 'Analyse', desc: 'Rapports et metriques SOC' },
  ]

  return (
    <div className="flex h-screen w-screen overflow-hidden">
      {/* LEFT - Branding (60%) */}
      <div
        className="relative flex flex-col items-center justify-center px-16"
        style={{ width: '60%', backgroundColor: '#0d1117' }}
      >
        {/* Floating shapes */}
        <div className="floating-shapes">
          <div className="shape" />
          <div className="shape" />
          <div className="shape" />
          <div className="shape" />
          <div className="shape" />
        </div>

        {/* Subtle gradient overlay */}
        <div
          className="absolute inset-0"
          style={{
            background: 'radial-gradient(ellipse at 30% 50%, rgba(230, 57, 70, 0.04) 0%, transparent 70%)',
          }}
        />

        {/* Content */}
        <div className="relative z-10 text-center max-w-md">
          {/* Logo */}
          <div className="flex items-center justify-center gap-4 mb-8">
            <div
              className="flex items-center justify-center"
              style={{
                width: 64,
                height: 64,
                borderRadius: '50%',
                backgroundColor: 'rgba(230, 57, 70, 0.15)',
                border: '2px solid rgba(230, 57, 70, 0.3)',
              }}
            >
              <Shield style={{ width: 32, height: 32, color: '#e63946' }} />
            </div>
          </div>

          <h1
            className="text-5xl font-bold mb-1"
            style={{ color: '#e6edf3' }}
          >
            CyberTwin
          </h1>
          <p
            className="text-2xl font-bold tracking-widest mb-4"
            style={{ color: '#e63946' }}
          >
            SOC
          </p>

          {/* Tagline */}
          <p
            className="text-base leading-relaxed mb-12"
            style={{ color: '#8b949e' }}
          >
            {t('footer.platform')}
          </p>

          {/* Feature highlights */}
          <div className="space-y-3">
            {features.map((f, i) => (
              <div
                key={i}
                className="card flex items-center gap-4 text-left"
                style={{ padding: '12px 16px' }}
              >
                <div
                  className="flex items-center justify-center"
                  style={{
                    width: 36,
                    height: 36,
                    borderRadius: 8,
                    backgroundColor: 'rgba(230, 57, 70, 0.1)',
                  }}
                >
                  <f.icon style={{ width: 18, height: 18, color: '#e63946' }} />
                </div>
                <div>
                  <p
                    className="text-sm font-semibold"
                    style={{ color: '#e6edf3' }}
                  >
                    {f.title}
                  </p>
                  <p className="text-xs" style={{ color: '#6e7681' }}>
                    {f.desc}
                  </p>
                </div>
              </div>
            ))}
          </div>

          {/* Version badge */}
          <div className="mt-10">
            <span
              style={{
                fontSize: 11,
                padding: '4px 12px',
                borderRadius: 9999,
                backgroundColor: 'rgba(230, 57, 70, 0.1)',
                color: '#e63946',
                fontWeight: 600,
                border: '1px solid rgba(230, 57, 70, 0.25)',
              }}
            >
              v2.0
            </span>
          </div>
        </div>
      </div>

      {/* RIGHT - Login Form (40%) */}
      <div
        className="relative flex flex-col items-center justify-center px-16"
        style={{ width: '40%', backgroundColor: '#161b22' }}
      >
        {/* Top accent line */}
        <div
          className="absolute top-0 left-0 right-0"
          style={{ height: 2, backgroundColor: '#e63946' }}
        />

        {/* Language Toggle */}
        <div className="absolute top-4 right-4 flex items-center gap-1">
          {LANGUAGES.map((lang) => (
            <button
              key={lang.code}
              onClick={() => {
                localStorage.setItem('lang', lang.code)
                if (onLangChange) onLangChange(lang.code)
              }}
              className="flex items-center gap-1"
              style={{
                padding: '4px 8px',
                borderRadius: 6,
                fontSize: 11,
                fontWeight: currentLang === lang.code ? 700 : 500,
                color: currentLang === lang.code ? '#e6edf3' : '#6e7681',
                backgroundColor: currentLang === lang.code ? 'rgba(230, 57, 70, 0.15)' : 'transparent',
                border: currentLang === lang.code ? '1px solid rgba(230, 57, 70, 0.3)' : '1px solid transparent',
                cursor: 'pointer',
                transition: 'all 0.15s',
              }}
            >
              <span>{lang.flag}</span>
              <span>{lang.code.toUpperCase()}</span>
            </button>
          ))}
        </div>

        <div className="w-full max-w-sm">
          <h2
            className="text-2xl font-bold mb-2"
            style={{ color: '#e6edf3' }}
          >
            {t('login.title')}
          </h2>
          <p
            className="text-sm mb-8"
            style={{ color: '#8b949e' }}
          >
            Access your security workspace
          </p>

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Username */}
            <div>
              <label
                className="block text-xs font-medium mb-1.5"
                style={{ color: '#8b949e' }}
              >
                {t('login.username')}
              </label>
              <div className="relative">
                <User
                  className="absolute left-3 top-1/2 -translate-y-1/2"
                  style={{ width: 16, height: 16, color: '#6e7681' }}
                />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="admin"
                  className="input w-full"
                  style={{ paddingLeft: 40 }}
                  required
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label
                className="block text-xs font-medium mb-1.5"
                style={{ color: '#8b949e' }}
              >
                {t('login.password')}
              </label>
              <div className="relative">
                <Lock
                  className="absolute left-3 top-1/2 -translate-y-1/2"
                  style={{ width: 16, height: 16, color: '#6e7681' }}
                />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="cybertwin2024"
                  className="input w-full"
                  style={{ paddingLeft: 40, paddingRight: 40 }}
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2"
                  style={{
                    background: 'none',
                    border: 'none',
                    color: '#6e7681',
                    cursor: 'pointer',
                    padding: 0,
                  }}
                >
                  {showPassword
                    ? <EyeOff style={{ width: 16, height: 16 }} />
                    : <Eye style={{ width: 16, height: 16 }} />
                  }
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <div
                style={{
                  padding: '10px 14px',
                  borderRadius: 8,
                  backgroundColor: 'rgba(248, 81, 73, 0.1)',
                  border: '1px solid rgba(248, 81, 73, 0.25)',
                  color: '#f85149',
                  fontSize: 14,
                }}
              >
                {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full"
              style={{ padding: '10px 0', fontSize: 14 }}
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <svg className="animate-spin" style={{ width: 16, height: 16 }} viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Signing in...
                </span>
              ) : (
                t('login.submit')
              )}
            </button>
          </form>

          {/* Hint */}
          <p className="mt-6 text-center text-xs" style={{ color: '#6e7681' }}>
            {t('login.hint')}
          </p>

          {/* Footer */}
          <p className="mt-12 text-center" style={{ fontSize: 11, color: '#6e7681' }}>
            &copy; 2026 CyberTwin SOC
          </p>
        </div>
      </div>
    </div>
  )
}
