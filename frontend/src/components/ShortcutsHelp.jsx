import React, { useEffect } from 'react'
import { X, Keyboard } from 'lucide-react'

const SHORTCUT_GROUPS = [
  {
    title: 'General',
    shortcuts: [
      { keys: ['Ctrl', 'K'], description: 'Open search' },
      { keys: ['?'], description: 'Show keyboard shortcuts' },
      { keys: ['Esc'], description: 'Close modal / panel' },
    ],
  },
  {
    title: 'Navigation',
    shortcuts: [
      { keys: ['Ctrl', '1'], description: 'Dashboard' },
      { keys: ['Ctrl', '2'], description: 'Scenarios' },
      { keys: ['Ctrl', '3'], description: 'Alerts' },
      { keys: ['Ctrl', '4'], description: 'Timeline' },
      { keys: ['Ctrl', '5'], description: 'MITRE ATT&CK' },
      { keys: ['Ctrl', '6'], description: 'Log Explorer' },
      { keys: ['Ctrl', '7'], description: 'Network Map' },
      { keys: ['Ctrl', '8'], description: 'AI Analyst' },
      { keys: ['Ctrl', '9'], description: 'Report' },
    ],
  },
]

export default function ShortcutsHelp({ isOpen, onClose }) {
  useEffect(() => {
    if (!isOpen) return
    const handler = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        onClose()
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [isOpen, onClose])

  if (!isOpen) return null

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 9998,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: 'rgba(13, 17, 23, 0.8)',
        backdropFilter: 'blur(4px)',
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: 520,
          backgroundColor: '#161b22',
          border: '1px solid #30363d',
          borderRadius: 12,
          boxShadow: '0 24px 48px rgba(0, 0, 0, 0.4)',
          overflow: 'hidden',
        }}
      >
        {/* Header */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '16px 20px',
            borderBottom: '1px solid #21262d',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Keyboard style={{ width: 20, height: 20, color: '#e63946' }} />
            <h2 style={{ fontSize: 16, fontWeight: 600, color: '#e6edf3', margin: 0 }}>
              Keyboard Shortcuts
            </h2>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              padding: 4,
              color: '#6e7681',
              display: 'flex',
              borderRadius: 6,
            }}
          >
            <X style={{ width: 18, height: 18 }} />
          </button>
        </div>

        {/* Shortcuts Grid */}
        <div style={{ padding: '16px 20px 20px' }}>
          {SHORTCUT_GROUPS.map((group, gi) => (
            <div key={gi} style={{ marginBottom: gi < SHORTCUT_GROUPS.length - 1 ? 20 : 0 }}>
              <h3
                style={{
                  fontSize: 11,
                  fontWeight: 600,
                  color: '#e63946',
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                  marginBottom: 10,
                }}
              >
                {group.title}
              </h3>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {group.shortcuts.map((shortcut, si) => (
                  <div
                    key={si}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '6px 10px',
                      borderRadius: 6,
                      backgroundColor: '#0d1117',
                      border: '1px solid #21262d',
                    }}
                  >
                    <span style={{ fontSize: 13, color: '#e6edf3' }}>
                      {shortcut.description}
                    </span>
                    <div style={{ display: 'flex', gap: 4 }}>
                      {shortcut.keys.map((key, ki) => (
                        <React.Fragment key={ki}>
                          {ki > 0 && (
                            <span style={{ color: '#6e7681', fontSize: 12, lineHeight: '24px' }}>+</span>
                          )}
                          <kbd
                            style={{
                              fontSize: 11,
                              fontWeight: 600,
                              padding: '3px 8px',
                              borderRadius: 4,
                              backgroundColor: '#21262d',
                              color: '#e6edf3',
                              border: '1px solid #30363d',
                              fontFamily: 'monospace',
                              minWidth: 24,
                              textAlign: 'center',
                              boxShadow: '0 1px 0 #30363d',
                            }}
                          >
                            {key}
                          </kbd>
                        </React.Fragment>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '10px 20px',
            borderTop: '1px solid #21262d',
            textAlign: 'center',
            fontSize: 11,
            color: '#6e7681',
          }}
        >
          Press <kbd style={footerKbd}>?</kbd> anytime to toggle this panel
        </div>
      </div>
    </div>
  )
}

const footerKbd = {
  fontSize: 10,
  padding: '1px 5px',
  borderRadius: 3,
  backgroundColor: '#21262d',
  color: '#8b949e',
  border: '1px solid #30363d',
  fontFamily: 'monospace',
  margin: '0 2px',
}
