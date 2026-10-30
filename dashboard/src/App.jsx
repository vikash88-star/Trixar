import { useEffect, useState } from 'react'
import Heatmap from './Heatmap'

const API = 'http://localhost:8000'

const scoreColor = (s) =>
  s >= 75 ? 'bg-red-600' : s >= 55 ? 'bg-orange-500' : s >= 35 ? 'bg-yellow-500' : 'bg-green-600'

export default function App() {
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState([])
  const [filter, setFilter] = useState(null)   // selected technique ID

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
    // fp_probability is filled in about 2 s after the alert, so refresh once in a while
    const timer = setInterval(load, 10000)
    return () => { ws.close(); clearInterval(timer) }
  }, [])

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
        {shown.map(a => (
          <div key={a.id} className="bg-slate-800 rounded p-4">
            <div className="flex items-center gap-3">
              <span className={`${scoreColor(a.priority_score)} px-2 py-1 rounded font-bold`}>
                {a.priority_score != null ? a.priority_score.toFixed(0) : '?'}
              </span>
              <span className="font-medium">{a.rule_desc}</span>
              {a.technique_id && (
                <span className="text-xs bg-indigo-700 px-2 py-1 rounded">{a.technique_id}</span>
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
          </div>
        ))}
        {shown.length === 0 && <p className="text-slate-400">No alerts yet.</p>}
      </div>
    </div>
  )
}
