// ARGUS-SCANNER: Conversational graph assistant, overlaid inside the graph
// view. Unlike the header's LLMSearch (single-shot, always one lookup),
// this holds a conversation and lets Qwen decide per-turn whether to
// ground its reply in a real node -- when it does, the graph pans to it.
import React, { useState, useRef, useEffect } from 'react'

export default function GraphChat({ onGrounded }) {
  const [open,     setOpen]     = useState(false)
  const [input,    setInput]    = useState('')
  const [messages, setMessages] = useState([])
  const [loading,  setLoading]  = useState(false)
  const [error,    setError]    = useState(null)
  const logRef = useRef(null)

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [messages, loading])

  async function handleSend(e) {
    e.preventDefault()
    const text = input.trim()
    if (!text || loading) return

    const nextMessages = [...messages, { role: 'user', content: text }]
    setMessages(nextMessages)
    setInput('')
    setLoading(true)
    setError(null)

    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages: nextMessages }),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => null)
        throw new Error(body?.detail || `Chat failed (${res.status})`)
      }
      const data = await res.json()
      setMessages(m => [...m, { role: 'assistant', content: data.reply, grounded: data.grounded_node }])
      if (data.grounded_node) onGrounded && onGrounded(data.grounded_node)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  if (!open) {
    return (
      <button className="graph-chat-toggle" onClick={() => setOpen(true)}>
        ◈ Ask ARGUS
      </button>
    )
  }

  return (
    <div className="graph-chat">
      <div className="graph-chat-head">
        <span>◈ Ask ARGUS</span>
        <button className="close-btn" onClick={() => setOpen(false)}>✕</button>
      </div>

      <div className="graph-chat-log" ref={logRef}>
        {messages.length === 0 && !loading && (
          <div className="graph-chat-hint">
            Ask about a CVE, technique, or tactic — e.g. "what is log4shell"
            or "explain lateral movement". Exact IDs resolve fast; open-ended
            questions need a real model call and can take a few minutes on
            this hardware.
          </div>
        )}
        {messages.map((m, i) => (
          <div key={i} className={`graph-chat-msg graph-chat-msg-${m.role}`}>
            <div className="graph-chat-bubble">{m.content}</div>
            {m.grounded && (
              <div className="graph-chat-grounded">grounded in {m.grounded.id}</div>
            )}
          </div>
        ))}
        {loading && (
          <div className="graph-chat-msg graph-chat-msg-assistant">
            <div className="graph-chat-bubble graph-chat-thinking">
              thinking… this can take a few minutes on this hardware
            </div>
          </div>
        )}
        {error && <div className="graph-chat-error">{error}</div>}
      </div>

      <form className="graph-chat-input-row" onSubmit={handleSend}>
        <input
          className="graph-chat-input"
          type="text"
          placeholder="Ask a question…"
          value={input}
          onChange={e => setInput(e.target.value)}
          disabled={loading}
        />
        <button className="graph-chat-send" type="submit" disabled={loading}>
          {loading ? '…' : '↵'}
        </button>
      </form>
    </div>
  )
}
