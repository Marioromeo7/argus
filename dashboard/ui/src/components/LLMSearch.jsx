// ARGUS-SCANNER: LLM graph navigation — user types a query, graph pans to node.
import React, { useState } from 'react'

export default function LLMSearch({ onNavigate }) {
  const [query,   setQuery]   = useState('')
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState(null)

  async function handleSearch(e) {
    e.preventDefault()
    if (!query.trim()) return
    setLoading(true); setError(null)
    try {
      const res = await fetch(`/api/llm/navigate?query=${encodeURIComponent(query)}`)
      if (!res.ok) {
        const body = await res.json().catch(() => null)
        throw new Error(body?.detail || `Search failed (${res.status})`)
      }
      onNavigate(await res.json())
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <form className="llm-search" onSubmit={handleSearch}>
      <input className="llm-search-input" type="text"
        placeholder="Navigate graph… e.g. 'log4shell' or 'lateral movement'"
        value={query} onChange={e => setQuery(e.target.value)} disabled={loading} />
      <button className="llm-search-btn" type="submit" disabled={loading}>
        {loading ? '…' : '↵'}
      </button>
      {loading && (
        <span className="llm-search-error">
          Searching — exact/keyword matches are instant; queries needing the
          LLM to disambiguate can take a few minutes on this hardware.
        </span>
      )}
      {error && <span className="llm-search-error">{error}</span>}
    </form>
  )
}
