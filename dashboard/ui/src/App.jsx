import React, { useState, useEffect, useCallback, useRef } from 'react'
import GraphView from './components/GraphView'
import MetricsStrip from './components/MetricsStrip'
import NodeSidebar from './components/NodeSidebar'

const POLL_MS = 5000

export default function App() {
  const [graphData, setGraphData] = useState({ nodes: [], links: [] })
  const [metrics, setMetrics]     = useState({})
  const [selected, setSelected]   = useState(null)
  const [lastPoll, setLastPoll]   = useState(null)
  const [status, setStatus]       = useState('connecting')

  // Keyed by node id — holds live node objects that d3 mutates with x/y/vx/vy.
  // Reusing the same objects across polls keeps node positions stable.
  const liveNodes = useRef(new Map())

  const fetchGraph = useCallback(async () => {
    try {
      const res  = await fetch('/api/graph')
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()

      const nodes = data.nodes.map(n => {
        const incoming = { ...n, val: Math.max(2, (n.grain || 0.1) * 12) }
        const live = liveNodes.current.get(n.id)
        if (live) {
          // Update data fields; d3 simulation state (x, y, vx, vy) stays on the object
          Object.assign(live, incoming)
          return live
        }
        liveNodes.current.set(n.id, incoming)
        return incoming
      })

      setGraphData({
        nodes,
        links: data.edges.map(e => ({
          source:     e.source,
          target:     e.target,
          label:      e.relation,
          confidence: e.confidence,
        })),
      })
      setMetrics({
        type_counts: data.type_counts || {},
        total_nodes: data.total_nodes,
        total_edges: data.total_edges,
      })
      setLastPoll(new Date())
      setStatus('live')
    } catch {
      setStatus('error')
    }
  }, [])

  useEffect(() => {
    fetchGraph()
    const id = setInterval(fetchGraph, POLL_MS)
    return () => clearInterval(id)
  }, [fetchGraph])

  return (
    <div className="app">
      <header className="header">
        <div className="header-brand">
          <span className="header-logo">◈</span>
          <span className="header-name">ARGUS</span>
          <span className="header-sub">Autonomous Reasoning Graph for Unified Security</span>
        </div>
        <div className={`status-pill status-${status}`}>
          <span className="status-dot" />
          {status}
        </div>
      </header>

      <MetricsStrip metrics={metrics} lastPoll={lastPoll} />

      <div className="workspace">
        <GraphView
          graphData={graphData}
          selected={selected}
          onSelect={setSelected}
        />
        {selected && (
          <NodeSidebar nodeId={selected.id} onClose={() => setSelected(null)} />
        )}
      </div>
    </div>
  )
}
