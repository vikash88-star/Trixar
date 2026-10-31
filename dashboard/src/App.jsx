import { useEffect, useState } from 'react'
import Heatmap from './Heatmap'

const API = 'http://localhost:8000'

const scoreColor = (s) =>
  s >= 75 ? 'bg-red-600' : s >= 55 ? 'bg-orange-500' : s >= 35 ? 'bg-yellow-500' : 'bg-green-600'

const statusBadge = {
  true_positive: { text: 'Confirmed threat', cls: 'bg-red-700' },
  false_positive: { text: 'Marked false positive', cls: 'bg-slate-600' },
}

export default function App() {
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState([])
  const [filter, setFilter] = useState(null)

  const load = async () => {
    try {
      const [a, t] = await Promise.all([
        fetch(`${API}/alerts?limit=200`).then(r => r.json()),
        fetch(`${API}/stats/techniques`).then(r => r.json()),
      ])
      setAlerts(a)
      setStats(t)
    } catch (err) {
      console.error('Could not reach the Trixar API:', err)
    }
  }

  useEffect(() => {
    load()
    const ws = new WebSocket('ws://localhost:8000/ws')
    ws.onmessage = (e) => {
      const m = JSON.parse(e.data)
      if (m.type === 'new_alert') load()
      if (m.type === 'ai_summary')
        setAlerts(prev => prev.map(a => (a.id === m.alert_id ? { ...a, ai_summary: m.summary } : a)))
    }
    const timer = setInterval(load, 10000)
    return () => { ws.close(); clearInterval(timer) }
  }, [])

  const setLabel = async (id, status) => {
    // optimistic update: change the UI immediately
    setAlerts(prev => prev.map(a => (a.id === id ? { ...a, status } : a)))
    try {
      await fetch(`${API}/alerts/${id}/label`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      })
    } catch (err) {
      console.error('Label save failed:', err)
      load()   // fall back to the server's real state
    }
  }

  const shown = filter ? alerts.filter(a => a.technique_id === filter) : alerts

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <h1 className="text-2xl font-bold mb-4">Trixar: SOC Triage</h1>

      <h2 className="font-semibold mb-2">ATT&amp;CK heatmap (click a technique to filter)</h2>
      <Heatmap stats={stats} selected={filter} onSelect={setFilter} />

      <div className="flex items-center gap-3 my-4">
        <h2 className="font-semibold">Triage queue ({shown.length})</h2>
        {filter && (
          <button onClick={() => setFilter(null)} className="text-sm bg-slate-700 px-2 py-1 rounded">
            Clear filter: {filter} ✕
          </button>
        )}
      </div>

      <div className="space-y-3">
        {shown.map(a => {
          const badge = statusBadge[a.status]
          return (
            <div key={a.id} className="bg-slate-800 rounded p-4">
              <div className="flex items-center gap-3">
                <span className={`${scoreColor(a.priority_score)} px-2 py-1 rounded font-bold`}>
                  {a.priority_score != null ? a.priority_score.toFixed(0) : '?'}
                </span>
                <span className="font-medium">{a.rule_desc}</span>
                {a.technique_id && (
                  <span className="text-xs bg-indigo-700 px-2 py-1 rounded">{a.technique_id}</span>
                )}
                {badge && (
                  <span className={`text-xs ${badge.cls} px-2 py-1 rounded`}>{badge.text}</span>
                )}
                {a.fp_probability != null && (
                  <span className="text-xs text-slate-400 ml-auto">
                    false-positive chance: {(a.fp_probability * 100).toFixed(0)}%
                  </span>
                )}
              </div>

              <p className="text-sm text-slate-300 mt-2 whitespace-pre-line">
                {a.ai_summary ?? 'AI summary pending...'}
              </p>

              <div className="flex gap-2 mt-3">
                <button
                  onClick={() => setLabel(a.id, 'true_positive')}
                  className={`text-xs px-3 py-1 rounded border ${
                    a.status === 'true_positive' ? 'bg-red-700 border-red-700' : 'border-slate-600 hover:bg-slate-700'
                  }`}>
                  Confirm threat
                </button>
                <button
                  onClick={() => setLabel(a.id, 'false_positive')}
                  className={`text-xs px-3 py-1 rounded border ${
                    a.status === 'false_positive' ? 'bg-slate-600 border-slate-600' : 'border-slate-600 hover:bg-slate-700'
                  }`}>
                  Mark false positive
                </button>
                {a.status && a.status !== 'new' && (
                  <button
                    onClick={() => setLabel(a.id, 'new')}
                    className="text-xs px-3 py-1 rounded border border-slate-700 text-slate-400 hover:bg-slate-700">
                    Clear label
                  </button>
                )}
              </div>
            </div>
          )
        })}
        {shown.length === 0 && <p className="text-slate-400">No alerts yet.</p>}
      </div>
    </div>
  )
}
