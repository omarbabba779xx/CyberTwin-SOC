import React from 'react'

/**
 * ErrorBoundary - Catches React rendering errors and displays a fallback UI.
 * Uses CrowdStrike-inspired design (dark background, red accent #e63946).
 */
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null, errorInfo: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ errorInfo })
    console.error('[ErrorBoundary]', error, errorInfo)
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null, errorInfo: null })
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={styles.container}>
          <div style={styles.card}>
            <div style={styles.iconRow}>
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#e63946" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
            </div>
            <h2 style={styles.title}>Something went wrong</h2>
            <p style={styles.message}>
              An unexpected error occurred in the application. You can try again or contact the administrator if the problem persists.
            </p>
            {this.state.error && (
              <pre style={styles.errorDetail}>
                {this.state.error.toString()}
              </pre>
            )}
            <button style={styles.retryButton} onClick={this.handleRetry}>
              Retry
            </button>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

const styles = {
  container: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: '100vh',
    backgroundColor: '#0d1117',
    padding: '2rem',
  },
  card: {
    backgroundColor: '#161b22',
    border: '1px solid #30363d',
    borderTop: '3px solid #e63946',
    borderRadius: '8px',
    padding: '2.5rem',
    maxWidth: '520px',
    width: '100%',
    textAlign: 'center',
  },
  iconRow: {
    marginBottom: '1.25rem',
  },
  title: {
    color: '#e6edf3',
    fontSize: '1.5rem',
    fontWeight: 600,
    margin: '0 0 0.75rem 0',
  },
  message: {
    color: '#8b949e',
    fontSize: '0.95rem',
    lineHeight: 1.6,
    margin: '0 0 1.25rem 0',
  },
  errorDetail: {
    backgroundColor: '#0d1117',
    border: '1px solid #30363d',
    borderRadius: '6px',
    color: '#e63946',
    fontSize: '0.8rem',
    padding: '0.75rem 1rem',
    textAlign: 'left',
    overflowX: 'auto',
    marginBottom: '1.5rem',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-word',
  },
  retryButton: {
    backgroundColor: '#e63946',
    color: '#ffffff',
    border: 'none',
    borderRadius: '6px',
    padding: '0.6rem 2rem',
    fontSize: '0.95rem',
    fontWeight: 600,
    cursor: 'pointer',
    transition: 'background-color 0.2s',
  },
}

export default ErrorBoundary
