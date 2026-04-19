import React, { createContext, useContext, useState, useCallback, useEffect, useRef } from 'react'

/**
 * Toast Notification System
 *
 * Usage:
 *   Wrap your app with <ToastProvider>, then use the useToast() hook:
 *     const { success, error, warning, info } = useToast()
 *     success('Simulation complete!')
 */

const ToastContext = createContext(null)

const TOAST_COLORS = {
  success: '#3fb950',
  error: '#e63946',
  warning: '#f4a261',
  info: '#457b9d',
}

const TOAST_ICONS = {
  success: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
      <polyline points="22 4 12 14.01 9 11.01" />
    </svg>
  ),
  error: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <line x1="15" y1="9" x2="9" y2="15" />
      <line x1="9" y1="9" x2="15" y2="15" />
    </svg>
  ),
  warning: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  ),
  info: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="16" x2="12" y2="12" />
      <line x1="12" y1="8" x2="12.01" y2="8" />
    </svg>
  ),
}

const AUTO_DISMISS_MS = 5000

/* -------------------------------------------------------------------------- */
/* Single Toast                                                               */
/* -------------------------------------------------------------------------- */

function ToastItem({ id, type, message, onDismiss }) {
  const [isExiting, setIsExiting] = useState(false)
  const timerRef = useRef(null)

  useEffect(() => {
    timerRef.current = setTimeout(() => {
      setIsExiting(true)
      setTimeout(() => onDismiss(id), 300)
    }, AUTO_DISMISS_MS)
    return () => clearTimeout(timerRef.current)
  }, [id, onDismiss])

  const handleClose = () => {
    clearTimeout(timerRef.current)
    setIsExiting(true)
    setTimeout(() => onDismiss(id), 300)
  }

  const accentColor = TOAST_COLORS[type] || TOAST_COLORS.info

  return (
    <div
      style={{
        ...toastStyles.item,
        borderLeft: `4px solid ${accentColor}`,
        animation: isExiting ? 'toastSlideOut 0.3s ease forwards' : 'toastSlideIn 0.3s ease forwards',
      }}
    >
      <span style={{ color: accentColor, flexShrink: 0, display: 'flex' }}>
        {TOAST_ICONS[type]}
      </span>
      <span style={toastStyles.message}>{message}</span>
      <button style={toastStyles.closeBtn} onClick={handleClose} aria-label="Dismiss">
        &times;
      </button>
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* Provider                                                                   */
/* -------------------------------------------------------------------------- */

let _toastId = 0

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])

  const dismiss = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const addToast = useCallback((type, message) => {
    const id = ++_toastId
    setToasts((prev) => [...prev, { id, type, message }])
    return id
  }, [])

  const api = {
    success: (msg) => addToast('success', msg),
    error: (msg) => addToast('error', msg),
    warning: (msg) => addToast('warning', msg),
    info: (msg) => addToast('info', msg),
    dismiss,
  }

  return (
    <ToastContext.Provider value={api}>
      {children}
      {/* Inject keyframes once */}
      <style>{`
        @keyframes toastSlideIn {
          from { transform: translateX(120%); opacity: 0; }
          to   { transform: translateX(0);    opacity: 1; }
        }
        @keyframes toastSlideOut {
          from { transform: translateX(0);    opacity: 1; }
          to   { transform: translateX(120%); opacity: 0; }
        }
      `}</style>
      <div style={toastStyles.container}>
        {toasts.map((t) => (
          <ToastItem key={t.id} {...t} onDismiss={dismiss} />
        ))}
      </div>
    </ToastContext.Provider>
  )
}

/* -------------------------------------------------------------------------- */
/* Hook                                                                       */
/* -------------------------------------------------------------------------- */

export function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within a <ToastProvider>')
  return ctx
}

/* -------------------------------------------------------------------------- */
/* Styles                                                                     */
/* -------------------------------------------------------------------------- */

const toastStyles = {
  container: {
    position: 'fixed',
    top: '1.25rem',
    right: '1.25rem',
    zIndex: 99999,
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem',
    pointerEvents: 'none',
  },
  item: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    backgroundColor: '#161b22',
    border: '1px solid #30363d',
    borderRadius: '8px',
    padding: '0.85rem 1rem',
    minWidth: '300px',
    maxWidth: '440px',
    boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
    pointerEvents: 'auto',
  },
  message: {
    flex: 1,
    color: '#e6edf3',
    fontSize: '0.9rem',
    lineHeight: 1.4,
  },
  closeBtn: {
    background: 'none',
    border: 'none',
    color: '#8b949e',
    fontSize: '1.25rem',
    cursor: 'pointer',
    padding: '0 0.25rem',
    flexShrink: 0,
    lineHeight: 1,
  },
}
