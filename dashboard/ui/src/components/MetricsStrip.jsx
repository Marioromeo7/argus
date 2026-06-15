import React from 'react'

const TYPE_COLOR = {
  vulnerability: '#e05252',
  technique:     '#4f9cf9',
  tactic:        '#a78bfa',
  engagement:    '#f59e0b',
  mitigation:    '#34d399',
  memory:        '#22d3ee',
}

export default function MetricsStrip({ metrics, lastPoll }) {
  const { type_counts = {}, total_nodes = 0, total_edges = 0 } = metrics

  return (
    <div className="metrics-strip">
      <div className="metric">
        <span className="metric-n">{total_nodes.toLocaleString()}</span>
        <span className="metric-l">nodes</span>
      </div>
      <div className="metric">
        <span className="metric-n">{total_edges.toLocaleString()}</span>
        <span className="metric-l">edges</span>
      </div>

      <div className="strip-divider" />

      {Object.entries(type_counts).map(([type, count]) => (
        <div className="metric" key={type}>
          <span
            className="type-dot"
            style={{ background: TYPE_COLOR[type] ?? '#6b7280' }}
          />
          <span className="metric-n">{count}</span>
          <span className="metric-l">{type}</span>
        </div>
      ))}

      <div className="strip-divider" />

      <div className="metric metric-clock">
        <span className="metric-l">
          {lastPoll
            ? `↻ ${lastPoll.toLocaleTimeString()}`
            : 'connecting…'}
        </span>
      </div>
    </div>
  )
}
