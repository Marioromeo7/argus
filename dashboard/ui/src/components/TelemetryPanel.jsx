// ARGUS-SCANNER: Telemetry panel. Polls /api/telemetry every 10s.
import React, { useState, useEffect } from 'react'

export default function TelemetryPanel() {
  const [data, setData] = useState(null)
  const [open, setOpen] = useState(false)

  useEffect(() => {
    async function poll() {
      try {
        const res = await fetch('/api/telemetry')
        if (res.ok) setData(await res.json())
      } catch {}
    }
    poll()
    const id = setInterval(poll, 10_000)
    return () => clearInterval(id)
  }, [])

  if (!data || !data.summary || data.entries.length === 0) return null
  const { summary, entries } = data

  return (
    <div className={`telemetry-panel ${open ? 'open' : ''}`}>
      <div className="telemetry-header" onClick={() => setOpen(o => !o)}>
        <span>⬡ Telemetry</span>
        <span className="telemetry-costs">
          GPT-4o equiv: ${summary.est_cost_gpt4o?.toFixed(4)}
          &nbsp;·&nbsp;Claude equiv: ${summary.est_cost_claude?.toFixed(4)}
          &nbsp;·&nbsp;{summary.total_calls} calls
          &nbsp;·&nbsp;{summary.total_time_s}s
        </span>
        <span>{open ? '▲' : '▼'}</span>
      </div>
      {open && (
        <div className="telemetry-log">
          {[...entries].reverse().map((e, i) => (
            <div key={i} className="telemetry-entry">
              <span className="tel-caller">{e.caller}</span>
              <span className="tel-model">{e.model}</span>
              <span className="tel-tokens">{e.tokens_in}→{e.tokens_out} tok</span>
              <span className="tel-time">{e.inference_time_s}s</span>
              <span className="tel-cost">${e.est_cost_gpt4o?.toFixed(5)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
