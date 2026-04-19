import React, { useState, useCallback, useMemo, useEffect } from 'react'
import ReactFlow, { MiniMap, Controls, Background, useNodesState, useEdgesState, Handle, Position, MarkerType } from 'reactflow'
import 'reactflow/dist/style.css'
import { Server, Monitor, Shield, Globe, X, Wifi, AlertTriangle } from 'lucide-react'

/* ─── Custom Node: Host ─── */
const HostNode = ({ data }) => {
  const icons = { workstation: Monitor, server: Server, firewall: Shield }
  const Icon = icons[data.type] || Server
  const critColors = {
    critical: { border: '#ef4444', bg: 'rgba(239,68,68,0.15)', text: '#fca5a5' },
    high: { border: '#f97316', bg: 'rgba(249,115,22,0.15)', text: '#fdba74' },
    medium: { border: '#eab308', bg: 'rgba(234,179,8,0.15)', text: '#fde047' },
    low: { border: '#22c55e', bg: 'rgba(34,197,94,0.15)', text: '#86efac' },
  }
  const c = critColors[data.criticality] || critColors.medium
  const isCompromised = data.compromised

  return (
    <div style={{
      background: 'rgba(15,23,42,0.95)',
      border: `2px solid ${isCompromised ? '#ef4444' : c.border}`,
      borderRadius: 12,
      padding: '12px 16px',
      minWidth: 180,
      boxShadow: isCompromised
        ? '0 0 20px rgba(239,68,68,0.5), 0 0 40px rgba(239,68,68,0.2)'
        : `0 0 15px ${c.border}33`,
      position: 'relative',
    }}>
      <Handle type="target" position={Position.Top} style={{ background: '#e63946', width: 8, height: 8 }} />
      <Handle type="source" position={Position.Bottom} style={{ background: '#e63946', width: 8, height: 8 }} />
      {isCompromised && (
        <div style={{
          position: 'absolute', top: -8, right: -8,
          background: '#ef4444', borderRadius: '50%',
          width: 20, height: 20, display: 'flex', alignItems: 'center', justifyContent: 'center',
          animation: 'pulse-glow 2s infinite',
        }}>
          <AlertTriangle size={12} color="white" />
        </div>
      )}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <div style={{ padding: 6, background: c.bg, borderRadius: 8 }}>
          <Icon size={18} color={c.border} />
        </div>
        <div>
          <div style={{ fontWeight: 700, fontSize: 13, color: '#e2e8f0' }}>{data.hostname}</div>
          <div style={{ fontSize: 11, color: '#94a3b8', fontFamily: 'monospace' }}>{data.ip}</div>
        </div>
      </div>
      <div style={{ fontSize: 11, color: '#64748b', marginBottom: 4 }}>{data.os}</div>
      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
        <span style={{
          fontSize: 10, padding: '2px 6px', borderRadius: 4,
          background: c.bg, color: c.text, fontWeight: 600, textTransform: 'uppercase'
        }}>{data.criticality}</span>
        {(data.services || []).slice(0, 3).map(s => (
          <span key={s} style={{
            fontSize: 10, padding: '2px 6px', borderRadius: 4,
            background: 'rgba(244,162,97,0.1)', color: '#f4a261'
          }}>{s}</span>
        ))}
      </div>
    </div>
  )
}

/* ─── Custom Node: Segment Group ─── */
const SegmentNode = ({ data }) => (
  <div style={{
    background: `${data.color}08`,
    border: `1px dashed ${data.color}44`,
    borderRadius: 16,
    padding: '16px 20px',
    minWidth: data.width || 400,
    minHeight: data.height || 200,
    pointerEvents: 'none',
  }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
      <Wifi size={14} color={data.color} />
      <span style={{ fontWeight: 700, fontSize: 14, color: data.color }}>{data.label}</span>
    </div>
    <div style={{ fontSize: 11, color: '#64748b' }}>
      {data.subnet} {data.vlan ? `• VLAN ${data.vlan}` : ''}
    </div>
  </div>
)

/* ─── Custom Node: Central Firewall/Gateway ─── */
const GatewayNode = ({ data }) => (
  <div style={{
    background: 'rgba(15,23,42,0.95)',
    border: '2px solid #457b9d',
    borderRadius: '50%',
    width: 80, height: 80,
    display: 'flex', flexDirection: 'column',
    alignItems: 'center', justifyContent: 'center',
    boxShadow: '0 0 30px rgba(99,102,241,0.3)',
  }}>
    <Handle type="target" position={Position.Top} style={{ background: '#457b9d', width: 8, height: 8 }} />
    <Handle type="source" position={Position.Bottom} style={{ background: '#457b9d', width: 8, height: 8 }} />
    <Handle type="target" position={Position.Left} id="left" style={{ background: '#457b9d', width: 8, height: 8 }} />
    <Handle type="source" position={Position.Right} id="right" style={{ background: '#457b9d', width: 8, height: 8 }} />
    <Shield size={24} color="#457b9d" />
    <span style={{ fontSize: 10, color: '#457b9d', fontWeight: 600, marginTop: 2 }}>Gateway</span>
  </div>
)

const nodeTypes = { host: HostNode, segment: SegmentNode, gateway: GatewayNode }

/* ─── Detail Panel ─── */
const DetailPanel = ({ host, onClose }) => (
  <div style={{
    position: 'absolute', right: 0, top: 0, bottom: 0, width: 340,
    background: 'rgba(15,23,42,0.98)', borderLeft: '1px solid #1e293b',
    padding: 24, overflowY: 'auto', zIndex: 100,
    animation: 'slide-in 0.3s ease',
  }}>
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
      <h3 style={{ fontSize: 18, fontWeight: 700, color: '#e2e8f0' }}>{host.hostname}</h3>
      <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer' }}>
        <X size={20} color="#64748b" />
      </button>
    </div>
    {[
      ['IP Address', host.ip],
      ['DNS Name', host.dns_name],
      ['MAC Address', host.mac],
      ['Operating System', host.os],
      ['Type', host.type],
      ['Role', host.role],
      ['Criticality', host.criticality],
      ['Patch Level', host.patch_level],
    ].map(([label, val]) => val && (
      <div key={label} style={{ marginBottom: 12 }}>
        <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', fontWeight: 600 }}>{label}</div>
        <div style={{ fontSize: 14, color: '#e2e8f0', fontFamily: label === 'IP Address' ? 'monospace' : 'inherit' }}>{val}</div>
      </div>
    ))}
    {host.services?.length > 0 && (
      <div style={{ marginBottom: 12 }}>
        <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', fontWeight: 600, marginBottom: 6 }}>Services</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
          {host.services.map(s => (
            <span key={s} style={{ fontSize: 11, padding: '3px 8px', borderRadius: 6, background: 'rgba(244,162,97,0.15)', color: '#f4a261' }}>{s}</span>
          ))}
        </div>
      </div>
    )}
    {host.open_ports?.length > 0 && (
      <div style={{ marginBottom: 12 }}>
        <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', fontWeight: 600, marginBottom: 6 }}>Open Ports</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
          {host.open_ports.map(p => (
            <span key={p} style={{ fontSize: 11, padding: '3px 8px', borderRadius: 6, background: 'rgba(69,123,157,0.15)', color: '#457b9d', fontFamily: 'monospace' }}>{p}</span>
          ))}
        </div>
      </div>
    )}
    {host.installed_software?.length > 0 && (
      <div>
        <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', fontWeight: 600, marginBottom: 6 }}>Software</div>
        {host.installed_software.map(sw => (
          <div key={sw} style={{ fontSize: 12, color: '#94a3b8', padding: '2px 0' }}>• {sw}</div>
        ))}
      </div>
    )}
  </div>
)

/* ─── Main Component ─── */
export default function Network({ environment, result }) {
  const [selectedHost, setSelectedHost] = useState(null)

  // Determine compromised hosts from simulation result
  const compromisedHosts = useMemo(() => {
    if (!result) return new Set()
    const set = new Set()
    ;(result.alerts || []).forEach(a => { if (a.affected_host) set.add(a.affected_host) })
    ;(result.timeline || []).filter(e => e.is_malicious).forEach(e => { if (e.src_host) set.add(e.src_host) })
    return set
  }, [result])

  // Build nodes and edges from environment data
  const { initialNodes, initialEdges } = useMemo(() => {
    if (!environment) return { initialNodes: [], initialEdges: [] }

    const hosts = Object.values(environment.hosts || {})
    const segments = environment.segments || []
    const segColors = ['#e63946', '#457b9d', '#f59e0b']
    const nodes = []
    const edges = []

    // Layout: segments left/center/right, gateway in center
    const segPositions = [
      { x: 50, y: 50 },
      { x: 500, y: 50 },
      { x: 950, y: 50 },
    ]

    segments.forEach((seg, si) => {
      const segHosts = hosts.filter(h => seg.hosts?.includes(h.id))
      const cols = Math.min(segHosts.length, 2)
      const segW = cols * 220 + 40
      const segH = Math.ceil(segHosts.length / cols) * 160 + 60

      // Segment background
      nodes.push({
        id: `seg-${si}`,
        type: 'segment',
        position: segPositions[si] || { x: si * 450, y: 50 },
        data: { label: seg.name, subnet: seg.subnet, vlan: seg.vlan_id, color: segColors[si], width: segW, height: segH },
        draggable: false,
        selectable: false,
        style: { zIndex: 0 },
      })

      // Host nodes inside segment
      segHosts.forEach((host, hi) => {
        const col = hi % cols
        const row = Math.floor(hi / cols)
        const pos = segPositions[si] || { x: si * 450, y: 50 }
        nodes.push({
          id: host.id,
          type: 'host',
          position: { x: pos.x + 20 + col * 220, y: pos.y + 50 + row * 150 },
          data: { ...host, compromised: compromisedHosts.has(host.hostname) || compromisedHosts.has(host.id) },
          style: { zIndex: 10 },
        })

        // Connect host to gateway
        edges.push({
          id: `e-${host.id}-gw`,
          source: host.id,
          target: 'gateway',
          animated: compromisedHosts.has(host.hostname) || compromisedHosts.has(host.id),
          style: {
            stroke: (compromisedHosts.has(host.hostname) || compromisedHosts.has(host.id))
              ? '#ef4444' : segColors[si],
            strokeWidth: compromisedHosts.has(host.hostname) ? 3 : 1.5,
            strokeDasharray: compromisedHosts.has(host.hostname) ? '8 4' : 'none',
          },
          markerEnd: { type: MarkerType.ArrowClosed, color: segColors[si] },
        })
      })
    })

    // Gateway node in center
    const gwY = Math.max(...segments.map((seg, si) => {
      const segHosts = hosts.filter(h => seg.hosts?.includes(h.id))
      return (segPositions[si]?.y || 50) + Math.ceil(segHosts.length / 2) * 160 + 100
    }), 400)

    nodes.push({
      id: 'gateway',
      type: 'gateway',
      position: { x: 600, y: gwY },
      data: { label: 'Gateway' },
      style: { zIndex: 5 },
    })

    // Internet node
    nodes.push({
      id: 'internet',
      type: 'gateway',
      position: { x: 600, y: gwY + 150 },
      data: { label: 'Internet' },
      style: { zIndex: 5 },
    })
    edges.push({
      id: 'e-gw-inet',
      source: 'gateway',
      target: 'internet',
      style: { stroke: '#64748b', strokeWidth: 2 },
      animated: true,
    })

    return { initialNodes: nodes, initialEdges: edges }
  }, [environment, compromisedHosts])

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges)

  useEffect(() => {
    setNodes(initialNodes)
    setEdges(initialEdges)
  }, [initialNodes, initialEdges])

  const onNodeClick = useCallback((event, node) => {
    if (node.type === 'host') {
      const hosts = Object.values(environment?.hosts || {})
      const host = hosts.find(h => h.id === node.id) || node.data
      setSelectedHost(host)
    }
  }, [environment])

  if (!environment) {
    return (
      <div className="flex flex-col items-center justify-center h-96 text-gray-500">
        <Server className="w-12 h-12 mb-3 text-gray-700 animate-pulse" />
        <p>Loading network topology...</p>
      </div>
    )
  }

  return (
    <div className="relative" style={{ height: 'calc(100vh - 48px)' }}>
      {/* CSS animations */}
      <style>{`
        @keyframes pulse-glow { 0%,100% { opacity: 1; box-shadow: 0 0 5px #ef4444; } 50% { opacity: 0.6; box-shadow: 0 0 20px #ef4444; } }
        @keyframes slide-in { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        .react-flow__minimap { background: #0f172a !important; border: 1px solid #1e293b !important; border-radius: 8px !important; }
        .react-flow__controls { border-radius: 8px !important; overflow: hidden; border: 1px solid #1e293b !important; }
        .react-flow__controls-button { background: #1e293b !important; border-bottom: 1px solid #334155 !important; color: #94a3b8 !important; }
        .react-flow__controls-button:hover { background: #334155 !important; }
      `}</style>

      {/* Header */}
      <div className="absolute top-4 left-4 z-50 bg-gray-900/90 backdrop-blur rounded-lg border border-gray-800 px-4 py-3">
        <div className="flex items-center gap-3">
          <Globe className="w-5 h-5 text-[#e63946]" />
          <div>
            <h2 className="font-bold text-sm text-white">Network Topology</h2>
            <p className="text-xs text-gray-400">{environment.network?.name} — {environment.network?.subnet}</p>
          </div>
        </div>
        {result && (
          <div className="flex items-center gap-2 mt-2 text-xs">
            <span className="flex items-center gap-1 text-red-400">
              <span className="w-2 h-2 bg-red-500 rounded-full animate-pulse" /> Attack path active
            </span>
            <span className="text-gray-600">|</span>
            <span className="text-gray-400">{compromisedHosts.size} hosts compromised</span>
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="absolute bottom-4 left-4 z-50 bg-gray-900/90 backdrop-blur rounded-lg border border-gray-800 px-4 py-3">
        <div className="text-xs font-semibold text-gray-400 mb-2">LEGEND</div>
        <div className="space-y-1 text-xs">
          {[
            ['#ef4444', 'Critical'], ['#f97316', 'High'], ['#eab308', 'Medium'], ['#22c55e', 'Low']
          ].map(([color, label]) => (
            <div key={label} className="flex items-center gap-2">
              <span style={{ width: 10, height: 10, borderRadius: 3, background: color, display: 'inline-block' }} />
              <span className="text-gray-400">{label} Criticality</span>
            </div>
          ))}
          <div className="flex items-center gap-2 mt-1 pt-1 border-t border-gray-800">
            <span style={{ width: 10, height: 3, background: '#ef4444', display: 'inline-block', borderRadius: 2 }} />
            <span className="text-red-400">Attack path</span>
          </div>
        </div>
      </div>

      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        style={{ background: '#070b14' }}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#1e293b" gap={30} size={1} />
        <Controls position="top-right" />
        <MiniMap
          nodeColor={(n) => {
            if (n.type === 'gateway') return '#457b9d'
            if (n.data?.compromised) return '#ef4444'
            return '#e63946'
          }}
          maskColor="rgba(0,0,0,0.8)"
          position="bottom-right"
        />
      </ReactFlow>

      {selectedHost && <DetailPanel host={selectedHost} onClose={() => setSelectedHost(null)} />}
    </div>
  )
}
