import React, { useState, useEffect } from 'react'

export default function NodeSidebar({ nodeId, onClose }) {
  const [detail, setDetail] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    setDetail(null)
    fetch(`/api/node/${encodeURIComponent(nodeId)}`)
      .then(r => r.json())
      .then(d => { setDetail(d); setLoading(false) })
      .catch(() => setLoading(false))
  }, [nodeId])

  return (
    <aside className="sidebar">
      <div className="sidebar-head">
        <div>
          <div className="sidebar-id">{nodeId}</div>
          {detail && <div className="sidebar-type">{detail.node_type}</div>}
        </div>
        <button className="close-btn" onClick={onClose}>✕</button>
      </div>

      <div className="sidebar-body">
        {loading && <div className="sidebar-muted">loading…</div>}

        {detail && !loading && (
          <>
            <Section title="Grain Confidence">
              <GrainBar value={detail.grain_confidence ?? 0} />
            </Section>

            {detail.properties && Object.keys(detail.properties).length > 0 && (
              <Section title="Properties">
                {Object.entries(detail.properties)
                  .filter(([, v]) => v !== null && v !== '' && v !== undefined)
                  .slice(0, 8)
                  .map(([k, v]) => (
                    <Row key={k} label={k} value={String(v).slice(0, 160)} />
                  ))}
              </Section>
            )}

            {detail.open_questions?.length > 0 && (
              <Section title="Open Questions">
                {detail.open_questions.map((q, i) => (
                  <div className="question" key={i}>? {q}</div>
                ))}
              </Section>
            )}

            {detail.neighbors?.length > 0 && (
              <Section title={`Neighbors (${detail.neighbors.length})`}>
                {detail.neighbors.map((n, i) => (
                  <div className="neighbor" key={i}>
                    <span className="neighbor-rel">{n.relation}</span>
                    <span className="neighbor-id">{n.id}</span>
                  </div>
                ))}
              </Section>
            )}

            {detail.challenger_log?.length > 0 && (
              <Section title={`Challenger Log (${detail.challenger_log.length})`}>
                {detail.challenger_log.slice(-3).map((entry, i) => (
                  <div className="log-entry" key={i}>
                    <span className={`log-verdict ${entry.accepted ? 'accepted' : 'rejected'}`}>
                      {entry.accepted ? '✓' : '✗'}
                    </span>
                    <span className="log-text">{entry.proposal || entry.question || JSON.stringify(entry)}</span>
                  </div>
                ))}
              </Section>
            )}

            <div className="sidebar-footer">
              <span>{detail.source}</span>
              <span>{detail.last_updated?.slice(0, 19)}</span>
            </div>
          </>
        )}
      </div>
    </aside>
  )
}

function Section({ title, children }) {
  return (
    <div className="section">
      <div className="section-title">{title}</div>
      {children}
    </div>
  )
}

function Row({ label, value }) {
  return (
    <div className="prop-row">
      <span className="prop-key">{label}</span>
      <span className="prop-val">{value}</span>
    </div>
  )
}

function GrainBar({ value }) {
  const pct = Math.round((value ?? 0) * 100)
  const color = pct > 70 ? '#34d399' : pct > 40 ? '#f59e0b' : '#e05252'
  return (
    <div className="grain-row">
      <div className="grain-track">
        <div className="grain-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="grain-pct">{(value ?? 0).toFixed(3)}</span>
    </div>
  )
}
