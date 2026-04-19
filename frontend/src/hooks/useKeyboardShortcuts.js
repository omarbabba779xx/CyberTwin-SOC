import { useEffect, useCallback } from 'react'

const PAGE_ORDER = [
  'dashboard',    // Ctrl+1
  'scenarios',    // Ctrl+2
  'alerts',       // Ctrl+3
  'timeline',     // Ctrl+4
  'mitre',        // Ctrl+5
  'logs',         // Ctrl+6
  'network',      // Ctrl+7
  'ai',           // Ctrl+8
  'report',       // Ctrl+9
]

export default function useKeyboardShortcuts({
  setPage,
  setSearchOpen,
  setShortcutsOpen,
  searchOpen,
  shortcutsOpen,
}) {
  const handleKeyDown = useCallback((e) => {
    // Don't trigger shortcuts when typing in inputs (unless it's Escape or Ctrl+K)
    const tag = e.target.tagName
    const isInput = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT'

    // Ctrl+K — open search
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault()
      setSearchOpen(prev => !prev)
      return
    }

    // Escape — close any open modal
    if (e.key === 'Escape') {
      if (searchOpen) {
        e.preventDefault()
        setSearchOpen(false)
        return
      }
      if (shortcutsOpen) {
        e.preventDefault()
        setShortcutsOpen(false)
        return
      }
      return
    }

    // Don't process remaining shortcuts if typing in an input or a modal is open
    if (isInput || searchOpen || shortcutsOpen) return

    // ? — show shortcuts help
    if (e.key === '?' && !e.ctrlKey && !e.metaKey && !e.altKey) {
      e.preventDefault()
      setShortcutsOpen(true)
      return
    }

    // Ctrl+1 through Ctrl+9 — navigate to pages
    if ((e.ctrlKey || e.metaKey) && e.key >= '1' && e.key <= '9') {
      e.preventDefault()
      const idx = parseInt(e.key) - 1
      if (idx < PAGE_ORDER.length) {
        setPage(PAGE_ORDER[idx])
      }
      return
    }
  }, [setPage, setSearchOpen, setShortcutsOpen, searchOpen, shortcutsOpen])

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [handleKeyDown])
}
