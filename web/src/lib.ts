import { useEffect, useState } from 'react'

export type Rank = { name: string; allowed: number; blocked: number; tokens: number }
export type Point = { t: number; requests: number; blocked: number }
export type Stats = {
  totals: { requests: number; tools: number; blocked: number; users: number; sessions: number; tokens: number }
  series: Point[]
  users: Rank[]
  tools: Rank[]
  rules: Rank[]
  models: Rank[]
}
export type Event = {
  id: string; ts: number; user: string; session: string; kind: string; tool: string
  decision: string; rule: string; detail: string; model: string; tokens_in: number; tokens_out: number
}
export type Member = { id: number; name: string; created: number; last_seen: number; token?: string }
export type Rule = { name: string; pattern: string }
export type Policy = { deny_paths: Rule[] | null; deny_commands: Rule[] | null; secrets: Rule[] | null; allow_mcp: Rule[] | null; log_content: boolean }

export const num = new Intl.NumberFormat()
export const compact = new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 })
export const timeFmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' })
export const dayFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' })
export const fullFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })

export function ago(ts: number) {
  if (!ts) return 'Never'
  const m = Math.floor((Date.now() / 1000 - ts) / 60)
  return m < 1 ? 'Just now' : m < 60 ? `${m}m ago` : m < 1440 ? `${Math.floor(m / 60)}h ago` : `${Math.floor(m / 1440)}d ago`
}

export const SIGNED_OUT = 'gate:signed-out'

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(path, init)
  // An expired session anywhere sends the whole app back to the sign-in form.
  if (r.status === 401 && path !== '/api/login') window.dispatchEvent(new Event(SIGNED_OUT))
  if (!r.ok) throw new Error((await r.text()).trim() || r.statusText)
  return r.status === 204 ? (undefined as T) : r.json()
}

export const post = <T = void>(path: string, body?: unknown) =>
  api<T>(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body ?? {}) })

// Polls a URL. The previous data stays on screen while the next load is in flight.
export function useApi<T>(path: string, version = 0) {
  const [data, setData] = useState<T>()
  const [error, setError] = useState('')
  useEffect(() => {
    let live = true
    const load = () =>
      api<T>(path).then(
        (d) => live && (setData(d), setError('')),
        (e: Error) => live && setError(e.message),
      )
    load()
    const id = setInterval(load, 15000)
    return () => {
      live = false
      clearInterval(id)
    }
  }, [path, version])
  return { data, error }
}
