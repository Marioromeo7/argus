import React, { useRef, useCallback, useImperativeHandle, forwardRef } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import GraphChat from './GraphChat'

const TYPE_COLOR = {
  vulnerability: '#e05252',
  technique:     '#4f9cf9',
  tactic:        '#a78bfa',
  engagement:    '#f59e0b',
  mitigation:    '#34d399',
  memory:        '#22d3ee',
  unknown:       '#6b7280',
}

const GraphView = forwardRef(function GraphView(
  { graphData, selected, onSelect, onNavigated }, ref
) {
  const fgRef = useRef()

  // ARGUS-SCANNER: resolves against the live graphData (which carries d3's
  // x/y) by id, so callers can pass either a bare {id,label,type} ref (from
  // /api/llm/navigate or /api/chat's grounded_node) or an already-live node
  // -- either way this finds the real positioned node before panning.
  //
  // /api/graph only renders the 800 most-recently-updated nodes (a
  // performance cap, not a bug) out of ~3672 real nodes -- but chat/search
  // can ground in any of them. A node outside that rendered subset has no
  // x/y to pan to at all. Silently doing nothing there is indistinguishable
  // from a broken feature, so fall back to opening its detail sidebar
  // (which fetches by id directly, independent of what's rendered) instead
  // of dropping the result on the floor.
  const navigateToNode = useCallback((nodeRef) => {
    if (!nodeRef || !fgRef.current) return
    const live = graphData.nodes.find(n => n.id === nodeRef.id)
    if (live) {
      fgRef.current.centerAt(live.x, live.y, 800)  // smooth pan 800ms
      fgRef.current.zoom(6, 800)                     // zoom to level 6
      onNavigated && onNavigated(live)
    } else {
      onNavigated && onNavigated(nodeRef)
    }
  }, [graphData, onNavigated])

  // ARGUS-SCANNER: exposes navigateTo() so App.jsx can pan/zoom to a node
  // the LLM search picked, without GraphView needing to know why.
  useImperativeHandle(ref, () => ({ navigateTo: navigateToNode }), [navigateToNode])

  const paintNode = useCallback((node, ctx, scale) => {
    const r          = Math.max(3, node.val || 4)
    const color      = TYPE_COLOR[node.type] ?? TYPE_COLOR.unknown
    const isSelected = selected?.id === node.id

    if (isSelected) {
      ctx.beginPath()
      ctx.arc(node.x, node.y, r + 5, 0, 2 * Math.PI)
      ctx.fillStyle = color + '33'
      ctx.fill()
      ctx.beginPath()
      ctx.arc(node.x, node.y, r + 2, 0, 2 * Math.PI)
      ctx.strokeStyle = color
      ctx.lineWidth   = 1.5
      ctx.stroke()
    }

    ctx.beginPath()
    ctx.arc(node.x, node.y, r, 0, 2 * Math.PI)
    ctx.fillStyle = color
    ctx.fill()

    if (scale >= 1.8 || isSelected) {
      const label = node.id.length > 18 ? node.id.slice(0, 16) + '…' : node.id
      const fs    = Math.max(7, 9 / scale)
      ctx.font        = `${fs}px 'JetBrains Mono', monospace`
      ctx.fillStyle   = 'rgba(220,220,240,0.9)'
      ctx.textAlign   = 'center'
      ctx.textBaseline = 'top'
      ctx.fillText(label, node.x, node.y + r + 2)
    }
  }, [selected])

  const nodeLabel = useCallback(
    node => `${node.id}\n${node.type} · grain ${(node.grain ?? 0).toFixed(2)}`,
    []
  )

  const linkColor = useCallback(
    link => `rgba(120,130,180,${Math.max(0.15, (link.confidence ?? 0.5) * 0.6)})`,
    []
  )

  const handleNodeClick = useCallback(node => {
    onSelect(selected?.id === node.id ? null : node)
  }, [selected, onSelect])

  return (
    <div className="graph-wrap">
      <ForceGraph2D
        ref={fgRef}
        graphData={graphData}
        nodeId="id"
        nodeLabel={nodeLabel}
        nodeCanvasObject={paintNode}
        nodeCanvasObjectMode={() => 'replace'}
        linkColor={linkColor}
        linkWidth={link => Math.max(0.5, (link.confidence ?? 0.5) * 1.5)}
        linkDirectionalArrowLength={4}
        linkDirectionalArrowRelPos={1}
        linkLabel={link => link.label}
        onNodeClick={handleNodeClick}
        backgroundColor="#080814"
        cooldownTime={4000}
        d3AlphaDecay={0.015}
        d3VelocityDecay={0.25}
      />

      <div className="legend">
        {Object.entries(TYPE_COLOR).filter(([k]) => k !== 'unknown').map(([type, color]) => (
          <div className="legend-item" key={type}>
            <span className="legend-dot" style={{ background: color }} />
            <span>{type}</span>
          </div>
        ))}
      </div>

      <GraphChat onGrounded={navigateToNode} />
    </div>
  )
})

export default GraphView
