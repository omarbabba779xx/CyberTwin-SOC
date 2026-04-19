import React, { useState } from 'react'
import {
  Radar, Globe, Hash, Link, Mail, Shield, Bug, Wrench,
  Copy, Check, ExternalLink, AlertTriangle, Users, BookOpen
} from 'lucide-react'

const IOC_TABS = [
  { id: 'ip_addresses', label: 'IP Addresses', icon: Globe, color: 'red' },
  { id: 'domains', label: 'Domains', icon: Globe, color: 'amber' },
  { id: 'file_hashes', label: 'File Hashes', icon: Hash, color: 'crimson' },
  { id: 'urls', label: 'URLs', icon: Link, color: 'steel' },
  { id: 'cves', label: 'CVEs', icon: Bug, color: 'steel' },
  { id: 'tools', label: 'Tools', icon: Wrench, color: 'teal' },
  { id: 'email_addresses', label: 'Emails', icon: Mail, color: 'pink' },
]

const COLOR_MAP = {
  red: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', badge: 'bg-red-500/20 text-red-400' },
  orange: { bg: 'bg-orange-500/10', border: 'border-orange-500/30', text: 'text-orange-400', badge: 'bg-orange-500/20 text-orange-400' },
  amber: { bg: 'bg-[#f4a261]/10', border: 'border-[#f4a261]/30', text: 'text-[#f4a261]', badge: 'bg-[#f4a261]/20 text-[#f4a261]' },
  crimson: { bg: 'bg-[#e63946]/10', border: 'border-[#e63946]/30', text: 'text-[#e63946]', badge: 'bg-[#e63946]/20 text-[#e63946]' },
  steel: { bg: 'bg-[#457b9d]/10', border: 'border-[#457b9d]/30', text: 'text-[#457b9d]', badge: 'bg-[#457b9d]/20 text-[#457b9d]' },
  teal: { bg: 'bg-[#2a9d8f]/10', border: 'border-[#2a9d8f]/30', text: 'text-[#2a9d8f]', badge: 'bg-[#2a9d8f]/20 text-[#2a9d8f]' },
  yellow: { bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', text: 'text-yellow-400', badge: 'bg-yellow-500/20 text-yellow-400' },
  pink: { bg: 'bg-pink-500/10', border: 'border-pink-500/30', text: 'text-pink-400', badge: 'bg-pink-500/20 text-pink-400' },
}

const ORIGIN_FLAGS = {
  'Russia': '\u{1F1F7}\u{1F1FA}',
  'Germany': '\u{1F1E9}\u{1F1EA}',
  'Internal': '\u{1F3E2}',
  'Russia (GRU Unit 26165)': '\u{1F1F7}\u{1F1FA}',
}

const MOTIVATION_COLORS = {
  'Espionage': 'bg-red-500/20 text-red-400',
  'Financial (Cryptojacking)': 'bg-yellow-500/20 text-yellow-400',
  'Financial gain / Revenge / Corporate espionage': 'bg-orange-500/20 text-orange-400',
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = () => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }
  return (
    <button onClick={handleCopy} className="p-1 hover:bg-gray-700 rounded transition" title="Copy to clipboard">
      {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5 text-gray-500" />}
    </button>
  )
}

function StatCard({ icon: Icon, label, value, color }) {
  return (
    <div className="card p-5">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs text-[#8b949e] uppercase tracking-wider">{label}</p>
          <p className="text-2xl font-bold mt-1">{value}</p>
        </div>
        <div className={`p-3 rounded-lg ${COLOR_MAP[color]?.bg || 'bg-[#161b22]'}`}>
          <Icon className={`w-5 h-5 ${COLOR_MAP[color]?.text || 'text-[#8b949e]'}`} />
        </div>
      </div>
    </div>
  )
}

function ThreatActorCard({ actor }) {
  const flag = ORIGIN_FLAGS[actor.origin] || ''
  const motivationColor = MOTIVATION_COLORS[actor.motivation] || 'bg-gray-700 text-gray-300'

  return (
    <div className="card p-5 hover:border-red-500/30 transition">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <div className="p-2 bg-red-500/10 rounded-lg">
            <Users className="w-5 h-5 text-red-400" />
          </div>
          <div>
            <h3 className="font-bold text-white text-lg">{actor.name}</h3>
            <p className="text-xs text-gray-500">{flag} {actor.origin}</p>
          </div>
        </div>
        {actor.active_since && (
          <span className="text-xs text-gray-500 bg-gray-800 px-2 py-1 rounded">
            Active since {actor.active_since}
          </span>
        )}
      </div>

      {actor.aliases && actor.aliases.length > 0 && (
        <div className="mb-3">
          <p className="text-xs text-gray-500 mb-1">Aliases</p>
          <div className="flex flex-wrap gap-1.5">
            {actor.aliases.map((alias, i) => (
              <span key={i} className="text-xs bg-gray-800 text-gray-300 px-2 py-0.5 rounded-full border border-gray-700">
                {alias}
              </span>
            ))}
          </div>
        </div>
      )}

      <div>
        <span className={`text-xs px-2 py-1 rounded-full font-medium ${motivationColor}`}>
          {actor.motivation}
        </span>
      </div>
    </div>
  )
}

function IOCList({ items, type, color }) {
  const colors = COLOR_MAP[color] || COLOR_MAP.steel

  if (!items || items.length === 0) {
    return <p className="text-sm text-gray-500 italic">No indicators found in this category.</p>
  }

  return (
    <div className="space-y-1.5">
      {items.map((item, i) => (
        <div key={i} className={`flex items-center justify-between ${colors.bg} border ${colors.border} rounded-lg px-4 py-2.5`}>
          <span className={`font-mono text-sm ${colors.text} ${type === 'file_hashes' ? 'truncate max-w-[400px]' : ''}`} title={item}>
            {type === 'file_hashes' ? `${item.slice(0, 16)}...${item.slice(-8)}` : item}
          </span>
          <div className="flex items-center gap-2 ml-3 flex-shrink-0">
            {type === 'cves' && (
              <a
                href={`https://nvd.nist.gov/vuln/detail/${item}`}
                target="_blank"
                rel="noopener noreferrer"
                className="p-1 hover:bg-gray-700 rounded transition"
                title="View on NVD"
              >
                <ExternalLink className="w-3.5 h-3.5 text-gray-500 hover:text-yellow-400" />
              </a>
            )}
            <CopyButton text={item} />
          </div>
        </div>
      ))}
    </div>
  )
}

export default function ThreatIntel({ threatIntel }) {
  const [activeTab, setActiveTab] = useState('ip_addresses')

  if (!threatIntel) {
    return (
      <div className="flex flex-col items-center justify-center h-96 text-gray-500">
        <Radar className="w-12 h-12 mb-3 text-gray-700" />
        <p>Loading threat intelligence data...</p>
      </div>
    )
  }

  const { threat_actors = [], iocs = {}, references = [] } = threatIntel

  const totalIOCs = Object.values(iocs).reduce((sum, arr) => sum + (arr?.length || 0), 0)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-2 bg-gradient-to-br from-red-600 to-orange-600 rounded-lg shadow-lg shadow-red-600/20">
          <Radar className="w-6 h-6 text-white" />
        </div>
        <div>
          <h1 className="text-2xl font-bold">Threat Intelligence Feed</h1>
          <p className="text-gray-400 text-sm">Real-world IOCs extracted from attack scenarios</p>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={AlertTriangle} label="Total IOCs" value={totalIOCs} color="red" />
        <StatCard icon={Users} label="Threat Actors" value={threat_actors.length} color="orange" />
        <StatCard icon={Bug} label="CVEs" value={iocs.cves?.length || 0} color="yellow" />
        <StatCard icon={BookOpen} label="References" value={references.length} color="steel" />
      </div>

      {/* Threat Actors */}
      {threat_actors.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
            <Shield className="w-5 h-5 text-red-400" />
            Threat Actors
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {threat_actors.map((actor, i) => (
              <ThreatActorCard key={i} actor={actor} />
            ))}
          </div>
        </div>
      )}

      {/* IOC Categories - Tabbed */}
      <div className="card overflow-hidden">
        <div className="border-b border-[#21262d] px-4">
          <div className="flex gap-1 overflow-x-auto py-2">
            {IOC_TABS.map(tab => {
              const Icon = tab.icon
              const count = iocs[tab.id]?.length || 0
              const isActive = activeTab === tab.id
              const colors = COLOR_MAP[tab.color]
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition whitespace-nowrap ${
                    isActive
                      ? `${colors.bg} ${colors.text} border ${colors.border}`
                      : 'text-gray-400 hover:text-white hover:bg-gray-800'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {tab.label}
                  <span className={`text-xs px-1.5 py-0.5 rounded-full ${isActive ? colors.badge : 'bg-gray-800 text-gray-500'}`}>
                    {count}
                  </span>
                </button>
              )
            })}
          </div>
        </div>

        <div className="p-5">
          {IOC_TABS.map(tab => (
            activeTab === tab.id && (
              <IOCList key={tab.id} items={iocs[tab.id]} type={tab.id} color={tab.color} />
            )
          ))}
        </div>
      </div>

      {/* References */}
      {references.length > 0 && (
        <div className="card p-5">
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
            <BookOpen className="w-5 h-5 text-[#457b9d]" />
            References & Advisories
          </h2>
          <div className="space-y-2">
            {references.map((ref, i) => (
              <a
                key={i}
                href={ref}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 text-sm text-[#457b9d] hover:text-[#457b9d] transition bg-[#457b9d]/5 border border-[#457b9d]/10 rounded-lg px-4 py-2.5 hover:border-[#457b9d]/30"
              >
                <ExternalLink className="w-4 h-4 flex-shrink-0" />
                <span className="truncate">{ref}</span>
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
