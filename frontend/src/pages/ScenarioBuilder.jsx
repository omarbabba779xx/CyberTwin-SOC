import React, { useState, useMemo } from 'react'
import { PenTool, Plus, Trash2, ChevronDown, ChevronRight, Search, Play, Save, GripVertical, Check, AlertCircle } from 'lucide-react'

const tacticColors = {
  'reconnaissance': '#f4a261', 'resource-development': '#457b9d', 'initial-access': '#e63946',
  'execution': '#ef4444', 'persistence': '#457b9d', 'privilege-escalation': '#f97316',
  'defense-evasion': '#457b9d', 'credential-access': '#ec4899', 'discovery': '#14b8a6',
  'lateral-movement': '#f59e0b', 'collection': '#e63946', 'command-and-control': '#64748b',
  'exfiltration': '#eab308', 'impact': '#dc2626',
}

export default function ScenarioBuilder({ techniques = [], hosts = [], onRun }) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [severity, setSeverity] = useState('high')
  const [category, setCategory] = useState('custom')
  const [phases, setPhases] = useState([])
  const [search, setSearch] = useState('')
  const [expandedTactic, setExpandedTactic] = useState(null)
  const [saved, setSaved] = useState(false)

  // Group techniques by tactic
  const grouped = useMemo(() => {
    const groups = {}
    Object.entries(techniques).forEach(([id, tech]) => {
      const tactic = tech.tactic || 'Unknown'
      if (!groups[tactic]) groups[tactic] = []
      groups[tactic].push({ id, ...tech })
    })
    return groups
  }, [techniques])

  // Filter techniques
  const filteredGroups = useMemo(() => {
    if (!search) return grouped
    const q = search.toLowerCase()
    const result = {}
    Object.entries(grouped).forEach(([tactic, techs]) => {
      const filtered = techs.filter(t =>
        t.id.toLowerCase().includes(q) || t.name?.toLowerCase().includes(q) || tactic.toLowerCase().includes(q)
      )
      if (filtered.length > 0) result[tactic] = filtered
    })
    return result
  }, [grouped, search])

  const addPhase = (technique) => {
    setPhases(prev => [...prev, {
      id: Date.now(),
      technique_id: technique.id,
      technique_name: technique.name,
      tactic: technique.tactic,
      target_host: hosts[0]?.id || '',
      description: '',
      stealth_level: 'medium',
    }])
  }

  const removePhase = (id) => setPhases(prev => prev.filter(p => p.id !== id))

  const updatePhase = (id, field, value) => {
    setPhases(prev => prev.map(p => p.id === id ? { ...p, [field]: value } : p))
  }

  const movePhase = (index, direction) => {
    const newPhases = [...phases]
    const newIndex = index + direction
    if (newIndex < 0 || newIndex >= newPhases.length) return
    ;[newPhases[index], newPhases[newIndex]] = [newPhases[newIndex], newPhases[index]]
    setPhases(newPhases)
  }

  const saveScenario = async () => {
    const scenario = {
      id: `sc-custom-${Date.now()}`,
      name: name || 'Custom Scenario',
      description,
      severity,
      category,
      phases: phases.map((p, i) => ({
        phase: i + 1,
        name: p.technique_name,
        technique_id: p.technique_id,
        technique_name: p.technique_name,
        tactic: p.tactic,
        target_host: p.target_host,
        description: p.description,
        stealth_level: p.stealth_level,
        expected_logs: [{ event_type: 'generic', count: 5 }],
      })),
    }
    try {
      await fetch('http://localhost:8000/api/scenarios/custom', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scenario),
      })
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (e) {
      console.error('Save failed:', e)
    }
  }

  const isValid = name.length > 0 && phases.length > 0

  return (
    <div className="flex gap-6 h-[calc(100vh-48px)]">
      {/* Left: Technique Palette */}
      <div className="w-80 bg-[#161b22] border border-[#21262d] rounded-xl flex flex-col shrink-0">
        <div className="p-4 border-b border-[#21262d]">
          <h3 className="font-semibold text-sm text-gray-300 mb-3 flex items-center gap-2">
            <PenTool size={16} className="text-[#e63946]" />
            MITRE ATT&CK Techniques
          </h3>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search techniques..."
              className="w-full pl-9 pr-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-xs text-gray-300 focus:outline-none focus:border-[#e63946]" />
          </div>
        </div>
        <div className="flex-1 overflow-y-auto p-2">
          {Object.entries(filteredGroups).map(([tactic, techs]) => {
            const isExpanded = expandedTactic === tactic
            const color = tacticColors[tactic.toLowerCase().replace(/\s+/g, '-')] || '#64748b'
            return (
              <div key={tactic} className="mb-1">
                <button onClick={() => setExpandedTactic(isExpanded ? null : tactic)}
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-gray-800 transition text-left">
                  {isExpanded ? <ChevronDown size={14} className="text-gray-500" /> : <ChevronRight size={14} className="text-gray-500" />}
                  <span className="w-2 h-2 rounded-full" style={{ background: color }} />
                  <span className="text-xs font-semibold text-gray-300 flex-1">{tactic}</span>
                  <span className="text-xs text-gray-600">{techs.length}</span>
                </button>
                {isExpanded && (
                  <div className="ml-4 space-y-1 mb-2">
                    {techs.map(t => (
                      <button key={t.id} onClick={() => addPhase(t)}
                        className="w-full text-left px-3 py-2 rounded-lg bg-gray-800/50 hover:bg-gray-800 transition group"
                        style={{ borderLeft: `3px solid ${color}` }}>
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-mono text-[#e63946]">{t.id}</span>
                          <Plus size={12} className="text-gray-600 group-hover:text-[#e63946] transition" />
                        </div>
                        <p className="text-xs text-gray-400 mt-0.5">{t.name}</p>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* Center: Scenario Canvas */}
      <div className="flex-1 flex flex-col min-w-0">
        <div className="mb-4">
          <h1 className="text-2xl font-bold flex items-center gap-3">
            <PenTool className="text-[#e63946]" />
            Scenario Builder
          </h1>
          <p className="text-gray-400 text-sm mt-1">Create custom attack scenarios by selecting MITRE ATT&CK techniques</p>
        </div>

        {/* Phases */}
        <div className="flex-1 overflow-y-auto space-y-3 pr-2">
          {phases.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-gray-600 border-2 border-dashed border-[#21262d] rounded-xl">
              <Plus size={32} className="mb-2" />
              <p className="text-sm">Click techniques from the palette to add phases</p>
            </div>
          ) : (
            phases.map((phase, i) => {
              const color = tacticColors[phase.tactic?.toLowerCase().replace(/\s+/g, '-')] || '#64748b'
              return (
                <div key={phase.id} className="relative">
                  {/* Connecting line */}
                  {i < phases.length - 1 && (
                    <div className="absolute left-5 top-full w-0.5 h-3 bg-gray-700" style={{ zIndex: 0 }} />
                  )}
                  <div className="bg-[#161b22] border border-[#21262d] rounded-xl p-4 hover:border-[#30363d] transition"
                    style={{ borderLeftWidth: 4, borderLeftColor: color }}>
                    <div className="flex items-start gap-3">
                      {/* Phase number */}
                      <div className="w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold shrink-0"
                        style={{ background: `${color}22`, color, border: `2px solid ${color}` }}>
                        {i + 1}
                      </div>

                      <div className="flex-1 min-w-0 space-y-2">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs px-2 py-0.5 rounded" style={{ background: `${color}22`, color }}>{phase.technique_id}</span>
                          <span className="font-semibold text-sm text-gray-200">{phase.technique_name}</span>
                          <span className="text-xs text-gray-500">{phase.tactic}</span>
                        </div>

                        <div className="grid grid-cols-2 gap-2">
                          <div>
                            <label className="text-xs text-gray-500">Target Host</label>
                            <select value={phase.target_host} onChange={e => updatePhase(phase.id, 'target_host', e.target.value)}
                              className="w-full mt-1 bg-gray-800 border border-gray-700 rounded-lg px-2 py-1.5 text-xs text-gray-300 focus:border-[#e63946]">
                              {hosts.map(h => <option key={h.id} value={h.id}>{h.hostname} ({h.ip})</option>)}
                            </select>
                          </div>
                          <div>
                            <label className="text-xs text-gray-500">Stealth Level</label>
                            <select value={phase.stealth_level} onChange={e => updatePhase(phase.id, 'stealth_level', e.target.value)}
                              className="w-full mt-1 bg-gray-800 border border-gray-700 rounded-lg px-2 py-1.5 text-xs text-gray-300 focus:border-[#e63946]">
                              <option value="low">Low</option>
                              <option value="medium">Medium</option>
                              <option value="high">High</option>
                            </select>
                          </div>
                        </div>

                        <textarea
                          value={phase.description}
                          onChange={e => updatePhase(phase.id, 'description', e.target.value)}
                          placeholder="Describe this attack phase..."
                          className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-xs text-gray-300 focus:border-[#e63946] resize-none"
                          rows={2}
                        />
                      </div>

                      {/* Controls */}
                      <div className="flex flex-col gap-1 shrink-0">
                        <button onClick={() => movePhase(i, -1)} disabled={i === 0}
                          className="p-1 rounded hover:bg-gray-800 text-gray-500 hover:text-gray-300 disabled:opacity-30 text-xs">▲</button>
                        <button onClick={() => movePhase(i, 1)} disabled={i === phases.length - 1}
                          className="p-1 rounded hover:bg-gray-800 text-gray-500 hover:text-gray-300 disabled:opacity-30 text-xs">▼</button>
                        <button onClick={() => removePhase(phase.id)}
                          className="p-1 rounded hover:bg-red-600/20 text-gray-500 hover:text-red-400">
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )
            })
          )}
        </div>
      </div>

      {/* Right: Settings */}
      <div className="w-72 bg-[#161b22] border border-[#21262d] rounded-xl p-5 flex flex-col shrink-0">
        <h3 className="font-semibold text-sm text-gray-300 mb-4">Scenario Settings</h3>
        <div className="space-y-4 flex-1">
          <div>
            <label className="text-xs text-gray-500 font-semibold">Name *</label>
            <input value={name} onChange={e => setName(e.target.value)}
              placeholder="e.g., APT29 Phishing Campaign"
              className="w-full mt-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-[#e63946]" />
          </div>
          <div>
            <label className="text-xs text-gray-500 font-semibold">Description</label>
            <textarea value={description} onChange={e => setDescription(e.target.value)}
              placeholder="Describe the attack scenario..."
              className="w-full mt-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-[#e63946] resize-none"
              rows={3} />
          </div>
          <div>
            <label className="text-xs text-gray-500 font-semibold">Severity</label>
            <select value={severity} onChange={e => setSeverity(e.target.value)}
              className="w-full mt-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-300 focus:border-[#e63946]">
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <div>
            <label className="text-xs text-gray-500 font-semibold">Category</label>
            <select value={category} onChange={e => setCategory(e.target.value)}
              className="w-full mt-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-300 focus:border-[#e63946]">
              <option value="custom">Custom</option>
              <option value="phishing">Phishing</option>
              <option value="brute_force">Brute Force</option>
              <option value="lateral_movement">Lateral Movement</option>
              <option value="exfiltration">Exfiltration</option>
            </select>
          </div>

          {/* Summary */}
          <div className="bg-gray-800/50 rounded-lg p-3">
            <p className="text-xs text-gray-500 font-semibold uppercase mb-2">Summary</p>
            <div className="space-y-1 text-xs">
              <div className="flex justify-between"><span className="text-gray-500">Phases:</span><span className="text-gray-300">{phases.length}</span></div>
              <div className="flex justify-between"><span className="text-gray-500">Techniques:</span><span className="text-[#e63946]">{new Set(phases.map(p => p.technique_id)).size}</span></div>
              <div className="flex justify-between"><span className="text-gray-500">Tactics:</span><span className="text-[#e63946]">{new Set(phases.map(p => p.tactic)).size}</span></div>
            </div>
          </div>

          {!isValid && (
            <div className="flex items-center gap-2 text-xs text-yellow-400 bg-yellow-600/10 border border-yellow-600/20 rounded-lg p-2">
              <AlertCircle size={14} />
              <span>Add a name and at least one phase</span>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="space-y-2 pt-4 border-t border-[#21262d]">
          <button onClick={saveScenario} disabled={!isValid}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-[#457b9d] hover:bg-[#457b9d]/80 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg text-sm font-semibold transition">
            {saved ? <><Check size={16} /> Saved!</> : <><Save size={16} /> Save Scenario</>}
          </button>
          <button onClick={() => onRun && onRun(`sc-custom-${Date.now()}`)} disabled={!isValid}
            className="btn-primary w-full flex items-center justify-center gap-2 px-4 py-2.5 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg text-sm font-semibold transition">
            <Play size={16} /> Launch Simulation
          </button>
        </div>
      </div>
    </div>
  )
}
