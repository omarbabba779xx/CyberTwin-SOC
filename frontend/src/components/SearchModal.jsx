import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react'
import { Search, X, AlertTriangle, FileText, Shield, Monitor, Hash, User, Globe, ArrowRight } from 'lucide-react'

const CATEGORY_CONFIG = {
  alerts: { label: 'Alerts', icon: AlertTriangle, color: '#f85149' },
  logs: { label: 'Logs', icon: FileText, color: '#58a6ff' },
  iocs: { label: 'IOCs', icon: Shield, color: '#e63946' },
  hosts: { label: 'Hosts', icon: Monitor, color: '#3fb950' },
}

// Extract IOC-like patterns from text
function extractIOCs(text) {
  if (!text || typeof text !== 'string') return []
  const patterns = []
  // IPs
  const ips = text.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g)
  if (ips) patterns.push(...ips.map(ip => ({ type: 'IP', value: ip })))
  // Domains
  const domains = text.match(/\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+\b/g)
  if (domains) patterns.push(...domains.map(d => ({ type: 'Domain', value: d })))
  // Hashes (MD5, SHA1, SHA256)
  const hashes = text.match(/\b[a-fA-F0-9]{32,64}\b/g)
  if (hashes) patterns.push(...hashes.map(h => ({ type: 'Hash', value: h })))
  return patterns
}

function buildSearchIndex(result, scenarios) {
  const items = []
  if (!result) return items

  // Index alerts
  if (result.alerts) {
    result.alerts.forEach((alert, i) => {
      const text = [
        alert.rule || alert.name || '',
        alert.severity || '',
        alert.source_ip || alert.src_ip || '',
        alert.dest_ip || alert.dst_ip || '',
        alert.description || '',
        alert.technique || '',
        alert.hostname || '',
        alert.username || alert.user || '',
      ].join(' ')
      items.push({
        id: `alert-${i}`,
        category: 'alerts',
        title: alert.rule || alert.name || `Alert #${i + 1}`,
        subtitle: `${alert.severity || 'unknown'} severity${alert.source_ip ? ` | ${alert.source_ip}` : ''}`,
        searchText: text.toLowerCase(),
        page: 'alerts',
        raw: alert,
      })
    })
  }

  // Index incidents
  if (result.incidents) {
    result.incidents.forEach((inc, i) => {
      const text = [
        inc.name || inc.title || '',
        inc.severity || '',
        inc.description || '',
        inc.category || '',
      ].join(' ')
      items.push({
        id: `incident-${i}`,
        category: 'alerts',
        title: inc.name || inc.title || `Incident #${i + 1}`,
        subtitle: `Incident | ${inc.severity || 'unknown'}`,
        searchText: text.toLowerCase(),
        page: 'alerts',
        raw: inc,
      })
    })
  }

  // Index logs
  if (result.logs) {
    result.logs.forEach((log, i) => {
      const text = [
        log.event_type || log.type || '',
        log.source_ip || log.src_ip || '',
        log.dest_ip || log.dst_ip || '',
        log.hostname || '',
        log.username || log.user || '',
        log.message || log.description || '',
        log.event_id?.toString() || '',
        log.process_name || '',
        log.command_line || '',
      ].join(' ')
      items.push({
        id: `log-${i}`,
        category: 'logs',
        title: log.event_type || log.type || `Log #${i + 1}`,
        subtitle: [
          log.source_ip || log.src_ip,
          log.hostname,
          log.event_id ? `Event ${log.event_id}` : null,
        ].filter(Boolean).join(' | ') || 'Log entry',
        searchText: text.toLowerCase(),
        page: 'logs',
        raw: log,
      })
    })
  }

  // Index IOCs from timeline, alerts, logs
  const iocSet = new Set()
  const allTexts = [
    ...(result.alerts || []).map(a => JSON.stringify(a)),
    ...(result.logs || []).map(l => JSON.stringify(l)),
    ...(result.timeline || []).map(t => JSON.stringify(t)),
  ]
  allTexts.forEach(text => {
    extractIOCs(text).forEach(ioc => {
      const key = `${ioc.type}:${ioc.value}`
      if (!iocSet.has(key)) {
        iocSet.add(key)
        items.push({
          id: `ioc-${key}`,
          category: 'iocs',
          title: ioc.value,
          subtitle: ioc.type,
          searchText: `${ioc.type} ${ioc.value}`.toLowerCase(),
          page: ioc.type === 'IP' ? 'network' : 'threat-intel',
          raw: ioc,
        })
      }
    })
  })

  // Index hosts from environment info in result
  const hosts = result.environment?.hosts || result.hosts || {}
  const hostList = Array.isArray(hosts) ? hosts : Object.values(hosts)
  hostList.forEach((host, i) => {
    const text = [
      host.hostname || host.name || '',
      host.ip || host.ip_address || '',
      host.os || '',
      host.role || '',
      host.services?.join(' ') || '',
    ].join(' ')
    items.push({
      id: `host-${i}`,
      category: 'hosts',
      title: host.hostname || host.name || `Host #${i + 1}`,
      subtitle: [host.ip || host.ip_address, host.os, host.role].filter(Boolean).join(' | '),
      searchText: text.toLowerCase(),
      page: 'network',
      raw: host,
    })
  })

  // Also index scenario info if available
  if (result.scenario) {
    const sc = result.scenario
    const text = [sc.name || '', sc.description || '', sc.category || ''].join(' ')
    items.push({
      id: 'scenario-current',
      category: 'alerts',
      title: sc.name || 'Current Scenario',
      subtitle: sc.description || sc.category || 'Active scenario',
      searchText: text.toLowerCase(),
      page: 'timeline',
      raw: sc,
    })
  }

  return items
}

function highlightMatch(text, query) {
  if (!query || !text) return text
  const idx = text.toLowerCase().indexOf(query.toLowerCase())
  if (idx === -1) return text
  return (
    <>
      {text.slice(0, idx)}
      <span style={{ color: '#e63946', fontWeight: 700 }}>{text.slice(idx, idx + query.length)}</span>
      {text.slice(idx + query.length)}
    </>
  )
}

export default function SearchModal({ isOpen, onClose, result, scenarios, onNavigate }) {
  const [query, setQuery] = useState('')
  const [selectedIndex, setSelectedIndex] = useState(0)
  const inputRef = useRef(null)
  const listRef = useRef(null)

  const searchIndex = useMemo(() => buildSearchIndex(result, scenarios), [result, scenarios])

  const filteredResults = useMemo(() => {
    if (!query.trim()) return []
    const q = query.toLowerCase().trim()
    return searchIndex
      .filter(item => item.searchText.includes(q))
      .slice(0, 50) // limit results
  }, [query, searchIndex])

  // Group results by category
  const groupedResults = useMemo(() => {
    const groups = {}
    filteredResults.forEach(item => {
      if (!groups[item.category]) groups[item.category] = []
      groups[item.category].push(item)
    })
    return groups
  }, [filteredResults])

  // Flat list for keyboard navigation
  const flatResults = useMemo(() => {
    const flat = []
    Object.keys(CATEGORY_CONFIG).forEach(cat => {
      if (groupedResults[cat]) {
        groupedResults[cat].forEach(item => flat.push(item))
      }
    })
    return flat
  }, [groupedResults])

  // Reset state when opening
  useEffect(() => {
    if (isOpen) {
      setQuery('')
      setSelectedIndex(0)
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [isOpen])

  // Scroll selected item into view
  useEffect(() => {
    if (listRef.current) {
      const selected = listRef.current.querySelector('[data-selected="true"]')
      if (selected) {
        selected.scrollIntoView({ block: 'nearest' })
      }
    }
  }, [selectedIndex])

  const handleSelect = useCallback((item) => {
    if (item && onNavigate) {
      onNavigate(item.page)
    }
    onClose()
  }, [onNavigate, onClose])

  const handleKeyDown = useCallback((e) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setSelectedIndex(prev => Math.min(prev + 1, flatResults.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setSelectedIndex(prev => Math.max(prev - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      if (flatResults[selectedIndex]) {
        handleSelect(flatResults[selectedIndex])
      }
    } else if (e.key === 'Escape') {
      e.preventDefault()
      onClose()
    }
  }, [flatResults, selectedIndex, handleSelect, onClose])

  // Reset selected index when results change
  useEffect(() => {
    setSelectedIndex(0)
  }, [query])

  if (!isOpen) return null

  let flatIndex = -1

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 9999,
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'center',
        paddingTop: '15vh',
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
          maxWidth: 640,
          backgroundColor: '#161b22',
          border: '1px solid #30363d',
          borderRadius: 12,
          boxShadow: '0 24px 48px rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(230, 57, 70, 0.1)',
          overflow: 'hidden',
        }}
      >
        {/* Search Input */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            padding: '14px 16px',
            borderBottom: '1px solid #21262d',
          }}
        >
          <Search style={{ width: 20, height: 20, color: '#6e7681', flexShrink: 0 }} />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Search IPs, domains, hashes, users, hosts, events..."
            style={{
              flex: 1,
              background: 'none',
              border: 'none',
              outline: 'none',
              fontSize: 16,
              color: '#e6edf3',
              fontFamily: 'inherit',
            }}
            autoComplete="off"
            spellCheck={false}
          />
          {query && (
            <button
              onClick={() => setQuery('')}
              style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                padding: 4,
                color: '#6e7681',
                display: 'flex',
              }}
            >
              <X style={{ width: 16, height: 16 }} />
            </button>
          )}
          <kbd
            style={{
              fontSize: 11,
              padding: '2px 6px',
              borderRadius: 4,
              backgroundColor: '#21262d',
              color: '#6e7681',
              border: '1px solid #30363d',
              fontFamily: 'monospace',
            }}
          >
            ESC
          </kbd>
        </div>

        {/* Results */}
        <div
          ref={listRef}
          style={{
            maxHeight: 420,
            overflowY: 'auto',
            padding: '8px 0',
          }}
        >
          {query.trim() && flatResults.length === 0 && (
            <div
              style={{
                padding: '32px 16px',
                textAlign: 'center',
                color: '#6e7681',
              }}
            >
              <Search style={{ width: 32, height: 32, margin: '0 auto 12px', opacity: 0.4 }} />
              <p style={{ fontSize: 14, marginBottom: 4 }}>No results for "{query}"</p>
              <p style={{ fontSize: 12 }}>Try searching for IPs, hostnames, alert names, or event types</p>
            </div>
          )}

          {!query.trim() && (
            <div
              style={{
                padding: '32px 16px',
                textAlign: 'center',
                color: '#6e7681',
              }}
            >
              <p style={{ fontSize: 14, marginBottom: 8 }}>Search across simulation data</p>
              <div style={{ display: 'flex', gap: 8, justifyContent: 'center', flexWrap: 'wrap' }}>
                {[
                  { icon: Globe, label: 'IPs & Domains' },
                  { icon: Hash, label: 'Hashes' },
                  { icon: User, label: 'Users' },
                  { icon: Monitor, label: 'Hosts' },
                ].map(hint => (
                  <span
                    key={hint.label}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 4,
                      fontSize: 11,
                      padding: '4px 10px',
                      borderRadius: 16,
                      backgroundColor: '#21262d',
                      color: '#8b949e',
                      border: '1px solid #30363d',
                    }}
                  >
                    <hint.icon style={{ width: 12, height: 12 }} />
                    {hint.label}
                  </span>
                ))}
              </div>
            </div>
          )}

          {Object.keys(CATEGORY_CONFIG).map(cat => {
            const items = groupedResults[cat]
            if (!items || items.length === 0) return null
            const config = CATEGORY_CONFIG[cat]
            const Icon = config.icon

            return (
              <div key={cat} style={{ marginBottom: 4 }}>
                {/* Category header */}
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    padding: '8px 16px 4px',
                    fontSize: 11,
                    fontWeight: 600,
                    color: config.color,
                    textTransform: 'uppercase',
                    letterSpacing: '0.05em',
                  }}
                >
                  <Icon style={{ width: 12, height: 12 }} />
                  {config.label}
                  <span style={{ color: '#6e7681', fontWeight: 400 }}>({items.length})</span>
                </div>

                {/* Items */}
                {items.map(item => {
                  flatIndex++
                  const isSelected = flatIndex === selectedIndex
                  const currentFlatIndex = flatIndex

                  return (
                    <button
                      key={item.id}
                      data-selected={isSelected}
                      onClick={() => handleSelect(item)}
                      onMouseEnter={() => setSelectedIndex(currentFlatIndex)}
                      style={{
                        width: '100%',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 10,
                        padding: '8px 16px',
                        background: isSelected ? 'rgba(230, 57, 70, 0.1)' : 'transparent',
                        border: 'none',
                        borderLeft: isSelected ? '2px solid #e63946' : '2px solid transparent',
                        cursor: 'pointer',
                        textAlign: 'left',
                        transition: 'background 0.1s',
                      }}
                    >
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div
                          style={{
                            fontSize: 13,
                            fontWeight: 500,
                            color: '#e6edf3',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {highlightMatch(item.title, query)}
                        </div>
                        <div
                          style={{
                            fontSize: 11,
                            color: '#6e7681',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                            marginTop: 1,
                          }}
                        >
                          {highlightMatch(item.subtitle, query)}
                        </div>
                      </div>
                      {isSelected && (
                        <ArrowRight style={{ width: 14, height: 14, color: '#e63946', flexShrink: 0 }} />
                      )}
                    </button>
                  )
                })}
              </div>
            )
          })}
        </div>

        {/* Footer */}
        {flatResults.length > 0 && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '8px 16px',
              borderTop: '1px solid #21262d',
              fontSize: 11,
              color: '#6e7681',
            }}
          >
            <div style={{ display: 'flex', gap: 12 }}>
              <span>
                <kbd style={kbdStyle}>↑↓</kbd> navigate
              </span>
              <span>
                <kbd style={kbdStyle}>↵</kbd> open
              </span>
              <span>
                <kbd style={kbdStyle}>esc</kbd> close
              </span>
            </div>
            <span>{flatResults.length} result{flatResults.length !== 1 ? 's' : ''}</span>
          </div>
        )}
      </div>
    </div>
  )
}

const kbdStyle = {
  fontSize: 10,
  padding: '1px 5px',
  borderRadius: 3,
  backgroundColor: '#21262d',
  color: '#8b949e',
  border: '1px solid #30363d',
  fontFamily: 'monospace',
  marginRight: 3,
}
