import React, { useMemo, useState, useEffect } from 'react'
import { ComposableMap, Geographies, Geography, Marker, Line, ZoomableGroup } from 'react-simple-maps'
import { Globe, Activity, MapPin, Crosshair } from 'lucide-react'
import { ThreatMapSkeleton } from '../components/Skeleton'

const GEO_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json"

const ACTORS = [
  { name: 'APT29 / Cozy Bear', alias: 'Nobelium / SVR', country: 'Russie', flag: '🇷🇺', coordinates: [37.62, 55.75], color: '#e63946', scenario: 'sc-phishing-001', desc: 'Service de renseignement extérieur russe (SVR). Espionnage étatique ciblant gouvernements et infrastructures critiques.' },
  { name: 'APT28 / Fancy Bear', alias: 'Sofacy / GRU', country: 'Russie', flag: '🇷🇺', coordinates: [30.32, 59.93], color: '#f4a261', scenario: 'sc-lateral-001', desc: 'Unité 26165 du GRU. Cyber warfare et opérations d\'influence.' },
  { name: 'TeamTNT', alias: 'Cryptojacking Group', country: 'Allemagne', flag: '🇩🇪', coordinates: [13.40, 52.52], color: '#457b9d', scenario: 'sc-bruteforce-001', desc: 'Groupe cybercriminel spécialisé dans le cryptojacking et le cloud.' },
  { name: 'Insider Threat', alias: 'Menace Interne', country: 'France', flag: '🇫🇷', coordinates: [2.35, 48.86], color: '#2a9d8f', scenario: 'sc-exfil-001', desc: 'Employé malveillant basé sur le cas Tesla/CERT Insider Threat Center.' },
]

const TARGET = { coordinates: [2.35, 46.60], name: 'CyberTwin Network' }

export default function ThreatMap({ result, scenarios }) {
  const activeScenario = result?.scenario?.id
  const [hoveredActor, setHoveredActor] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const timer = setTimeout(() => setLoading(false), 700)
    return () => clearTimeout(timer)
  }, [])

  const stats = useMemo(() => ({
    totalAttacks: result ? (result.alerts?.length || 0) : 0,
    activeThreats: ACTORS.filter(a => a.scenario === activeScenario).length || ACTORS.length,
    countries: [...new Set(ACTORS.map(a => a.country))].length,
  }), [result, activeScenario])

  if (loading) return <ThreatMapSkeleton />

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div style={{ width: 40, height: 40, borderRadius: 10, backgroundColor: 'rgba(230,57,70,0.12)', border: '1px solid rgba(230,57,70,0.25)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Globe style={{ width: 22, height: 22, color: '#e63946' }} />
        </div>
        <div>
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>Global Threat Map</h1>
          <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>Visualisation géographique des origines d'attaque et acteurs de menace</p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'TOTAL ALERTS', value: stats.totalAttacks, icon: Activity, color: '#e63946' },
          { label: 'ACTIVE THREATS', value: stats.activeThreats, icon: Crosshair, color: '#f4a261' },
          { label: 'COUNTRIES', value: stats.countries, icon: MapPin, color: '#457b9d' },
        ].map(s => (
          <div key={s.label} className="card" style={{ padding: 16 }}>
            <div className="flex items-center gap-3">
              <s.icon style={{ width: 18, height: 18, color: s.color }} />
              <div>
                <p style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>{s.label}</p>
                <p className="stat-value" style={{ fontSize: 22, color: s.color }}>{s.value}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Map + Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* World Map */}
        <div className="lg:col-span-3 card" style={{ padding: 0, overflow: 'hidden', position: 'relative' }}>
          <ComposableMap
            projection="geoMercator"
            projectionConfig={{ center: [20, 40], scale: 350 }}
            style={{ width: '100%', height: 500, backgroundColor: '#080c14' }}
          >
            <ZoomableGroup>
              {/* Real world countries */}
              <Geographies geography={GEO_URL}>
                {({ geographies }) =>
                  geographies.map((geo) => (
                    <Geography
                      key={geo.rpiKey || geo.id || geo.properties?.name}
                      geography={geo}
                      fill="#141c28"
                      stroke="#1e2a3a"
                      strokeWidth={0.5}
                      style={{
                        default: { outline: 'none' },
                        hover: { fill: '#1a2538', outline: 'none' },
                        pressed: { outline: 'none' },
                      }}
                    />
                  ))
                }
              </Geographies>

              {/* Attack lines from actors to target */}
              {ACTORS.map(actor => {
                const isActive = actor.scenario === activeScenario
                return (
                  <Line
                    key={`line-${actor.name}`}
                    from={actor.coordinates}
                    to={TARGET.coordinates}
                    stroke={isActive ? '#e63946' : 'rgba(230,57,70,0.2)'}
                    strokeWidth={isActive ? 2 : 0.8}
                    strokeLinecap="round"
                    strokeDasharray={isActive ? "6 4" : "3 4"}
                    className={isActive ? 'attack-line-active' : 'attack-line'}
                  />
                )
              })}

              {/* Target marker (our network) */}
              <Marker coordinates={TARGET.coordinates}>
                <circle r={8} fill="#3fb950" opacity={0.15} />
                <circle r={5} fill="#3fb950" opacity={0.25}>
                  <animate attributeName="r" values="5;12;5" dur="3s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.25;0;0.25" dur="3s" repeatCount="indefinite" />
                </circle>
                <circle r={4} fill="#3fb950" />
                <circle r={2} fill="#fff" opacity={0.6} />
                <text textAnchor="middle" y={16} fill="#3fb950" fontSize={10} fontWeight="700" fontFamily="Inter, sans-serif">
                  CyberTwin Network
                </text>
              </Marker>

              {/* Threat actor markers */}
              {ACTORS.map(actor => {
                const isActive = actor.scenario === activeScenario
                const isHovered = hoveredActor === actor.name
                return (
                  <Marker
                    key={actor.name}
                    coordinates={actor.coordinates}
                    onMouseEnter={() => setHoveredActor(actor.name)}
                    onMouseLeave={() => setHoveredActor(null)}
                    style={{ cursor: 'pointer' }}
                  >
                    {/* Pulse rings */}
                    <circle r={isActive ? 15 : 10} fill={actor.color} opacity={0}>
                      <animate attributeName="r" values={isActive ? "6;20;6" : "4;14;4"} dur={isActive ? "1.5s" : "2.5s"} repeatCount="indefinite" />
                      <animate attributeName="opacity" values="0.5;0;0.5" dur={isActive ? "1.5s" : "2.5s"} repeatCount="indefinite" />
                    </circle>
                    {isActive && (
                      <circle r={6} fill="#e63946" opacity={0}>
                        <animate attributeName="r" values="6;25;6" dur="2s" repeatCount="indefinite" begin="0.5s" />
                        <animate attributeName="opacity" values="0.3;0;0.3" dur="2s" repeatCount="indefinite" begin="0.5s" />
                      </circle>
                    )}
                    {/* Main dot */}
                    <circle r={isActive ? 6 : 4} fill={isActive ? '#e63946' : actor.color} stroke={isHovered ? '#fff' : 'none'} strokeWidth={1.5} />
                    <circle r={isActive ? 2.5 : 1.5} fill="#fff" opacity={0.8} />
                    {/* Label */}
                    <text textAnchor="middle" y={-12} fill={isActive ? '#e63946' : actor.color} fontSize={11} fontWeight="700" fontFamily="Inter, sans-serif">
                      {actor.name.split('/')[0].trim()}
                    </text>
                    <text textAnchor="middle" y={-2} fill="#8b949e" fontSize={8} fontFamily="Inter, sans-serif">
                      {actor.flag} {actor.country}
                    </text>
                  </Marker>
                )
              })}
            </ZoomableGroup>
          </ComposableMap>

          {/* CSS for attack line animation */}
          <style>{`
            .attack-line-active { animation: dashAnim 1s linear infinite; }
            .attack-line { animation: dashAnim 3s linear infinite; }
            @keyframes dashAnim { to { stroke-dashoffset: -20; } }
          `}</style>
        </div>

        {/* Right panel */}
        <div className="card" style={{ padding: 16 }}>
          <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16 }}>
            Acteurs de Menace
          </h3>
          <div className="space-y-3">
            {ACTORS.map(actor => {
              const isActive = actor.scenario === activeScenario
              const isHovered = hoveredActor === actor.name
              return (
                <div
                  key={actor.name}
                  onMouseEnter={() => setHoveredActor(actor.name)}
                  onMouseLeave={() => setHoveredActor(null)}
                  style={{
                    padding: 12, borderRadius: 8, cursor: 'pointer', transition: 'all 0.2s',
                    backgroundColor: isActive ? 'rgba(230,57,70,0.08)' : isHovered ? 'rgba(255,255,255,0.04)' : 'rgba(255,255,255,0.02)',
                    border: `1px solid ${isActive ? 'rgba(230,57,70,0.3)' : 'var(--border)'}`,
                    borderLeft: `3px solid ${actor.color}`,
                  }}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span style={{ fontSize: 16 }}>{actor.flag}</span>
                    <div>
                      <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', display: 'block' }}>
                        {actor.name}
                      </span>
                      <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{actor.alias}</span>
                    </div>
                  </div>
                  <p style={{ fontSize: 11, color: 'var(--text-secondary)', paddingLeft: 24, marginTop: 4, lineHeight: 1.4 }}>
                    {actor.desc}
                  </p>
                  {isActive && (
                    <div style={{ paddingLeft: 24, marginTop: 6 }}>
                      <span className="badge-critical" style={{ fontSize: 9 }}>● SIMULATION ACTIVE</span>
                    </div>
                  )}
                </div>
              )
            })}
          </div>

          {/* Legend */}
          <div style={{ marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border)' }}>
            <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Légende</p>
            <div className="space-y-2">
              {[
                { color: '#3fb950', label: 'Réseau CyberTwin (cible)' },
                { color: '#e63946', label: 'Acteur de menace actif' },
                { color: '#457b9d', label: 'Acteur de menace inactif' },
              ].map(l => (
                <div key={l.label} className="flex items-center gap-2">
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: l.color, flexShrink: 0 }} />
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{l.label}</span>
                </div>
              ))}
              <div className="flex items-center gap-2">
                <div style={{ width: 20, height: 0, borderTop: '1.5px dashed rgba(230,57,70,0.5)', flexShrink: 0 }} />
                <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Vecteur d'attaque</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
