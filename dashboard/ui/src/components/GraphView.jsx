import React, { useRef, useCallback } from 'react'
import ForceGraph2D from 'react-force-graph-2d'

const TYPE_COLOR = {
  vulnerability: '#e05252',
  technique:     '#4f9cf9',
  tactic:        '#a78bfa',
  engagement:    '#f59e0b',
  mitigation:    '#34d399',
  memory:        '#22d3ee',
  unknown:       '#6b7280',
}

export default function GraphView({ graphData, selected, onSelect }) {
  const fgRef = useRef()

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
    </div>
  )
}
