import { useState, type FormEvent, type ReactNode } from 'react'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { ago, api, compact, dayFmt, fullFmt, num, post, timeFmt, useApi, type Event, type Member, type Point, type Policy, type Rank, type Rule, type Stats } from './lib'
import { btnPrimary, btnQuiet, Card, Decision, Empty, Icon, input, Legend, Notice, th } from './ui'

function Spark({ values, color }: { values: number[]; color: string }) {
  const max = Math.max(1, ...values)
  const points = values.map((v, i) => `${(i / Math.max(1, values.length - 1)) * 100},${27 - (v / max) * 25}`).join(' ')
  return (
    <svg viewBox="0 0 100 28" preserveAspectRatio="none" className="h-8 w-24" aria-hidden>
      <polyline points={points} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
    </svg>
  )
}

function Tile({ label, value, sub, spark }: { label: string; value: string; sub?: string; spark?: ReactNode }) {
  return (
    <div className="rounded-xl border border-line bg-surface p-5">
      <div className="text-sm text-ink2">{label}</div>
      <div className="mt-2 flex items-end justify-between gap-2">
        <div className="text-3xl font-semibold tracking-tight">{value}</div>
        {spark}
      </div>
      <div className="mt-1.5 h-4 text-xs text-muted">{sub}</div>
    </div>
  )
}

// One series per chart, so the title names it and no legend is needed.
function Trend({ title, data, field, color, hours }: { title: string; data: Point[]; field: 'requests' | 'blocked'; color: string; hours: number }) {
  const tick = (t: number) => (hours <= 24 ? timeFmt : dayFmt).format(t * 1000)
  const label = (t: number) => (hours <= 168 ? fullFmt : dayFmt).format(t * 1000)
  const total = data.reduce((sum, p) => sum + p[field], 0)
  return (
    <Card title={title} aside={<span className="text-sm tabular-nums text-ink2">{num.format(total)} total</span>}>
      <ResponsiveContainer width="100%" height={220}>
        <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
          <CartesianGrid vertical={false} stroke="var(--grid)" />
          <XAxis dataKey="t" tickFormatter={tick} minTickGap={48} tickLine={false} axisLine={{ stroke: 'var(--axis)' }} tick={{ fill: 'var(--muted)', fontSize: 12 }} />
          <YAxis allowDecimals={false} width={40} tickFormatter={(v: number) => compact.format(v)} tickLine={false} axisLine={false} tick={{ fill: 'var(--muted)', fontSize: 12 }} />
          <Tooltip
            cursor={{ stroke: 'var(--axis)' }}
            content={({ active, payload, label: t }) =>
              active && payload?.length ? (
                <div className="rounded-lg border border-line bg-surface px-3 py-2 text-xs shadow-lg">
                  <div className="text-sm font-semibold tabular-nums">{num.format(Number(payload[0].value))}</div>
                  <div className="text-ink2">{label(Number(t))}</div>
                </div>
              ) : null
            }
          />
          <Area dataKey={field} type="linear" stroke={color} strokeWidth={2} fill={color} fillOpacity={0.1} dot={false}
            activeDot={{ r: 4, stroke: 'var(--surface)', strokeWidth: 2 }} isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
      <details className="mt-3 text-xs text-ink2">
        <summary className="cursor-pointer select-none">View as table</summary>
        <div className="mt-2 max-h-48 overflow-y-auto">
          <table className="w-full tabular-nums">
            <tbody>
              {data.filter((p) => p[field] > 0).map((p) => (
                <tr key={p.t} className="border-t border-line">
                  <td className="py-1">{label(p.t)}</td>
                  <td className="py-1 text-right">{num.format(p[field])}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </Card>
  )
}

// Ranked horizontal bars. segs returns [allowed-colored, blocked-colored] amounts for a row.
function Ranked({ title, rows, segs, legend, empty, mono }: { title: string; rows: Rank[]; segs: (r: Rank) => [number, number]; legend?: boolean; empty: string; mono?: boolean }) {
  const max = Math.max(1, ...rows.map((r) => segs(r)[0] + segs(r)[1]))
  return (
    <Card title={title} aside={legend && <Legend />}>
      {rows.length === 0 && <Empty>{empty}</Empty>}
      <ul className="-mx-2 space-y-1">
        {rows.map((r) => {
          const [a, b] = segs(r)
          const tip = legend ? `${r.name}: ${num.format(a)} allowed, ${num.format(b)} blocked` : `${r.name}: ${num.format(a + b)}`
          return (
            <li key={r.name} title={tip} className="rounded-lg px-2 py-1.5 hover:bg-sunken">
              <div className="flex justify-between gap-3 text-sm">
                <span className={`truncate ${mono ? 'font-mono text-[13px]' : ''}`}>{r.name}</span>
                <span className="tabular-nums text-ink2">{compact.format(a + b)}</span>
              </div>
              <div className="mt-1.5 flex h-2 gap-0.5">
                {a > 0 && <div className={`bg-s1 ${b > 0 ? '' : 'rounded-r'}`} style={{ width: `${(a / max) * 100}%` }} />}
                {b > 0 && <div className="rounded-r bg-s2" style={{ width: `${(b / max) * 100}%` }} />}
              </div>
            </li>
          )
        })}
      </ul>
    </Card>
  )
}

export function Overview({ hours }: { hours: number }) {
  const { data, error } = useApi<Stats>(`/api/stats?hours=${hours}`)
  if (error) return <Notice>Could not load stats: {error}</Notice>
  if (!data) return null
  const t = data.totals
  const calls = t.requests + t.blocked
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-5">
        <Tile label="Model requests" value={compact.format(t.requests)} sub={`${compact.format(t.tokens)} tokens`}
          spark={<Spark values={data.series.map((p) => p.requests)} color="var(--s1)" />} />
        <Tile label="Blocked" value={compact.format(t.blocked)} sub={calls ? `${((t.blocked / calls) * 100).toFixed(1)}% of requests` : ''}
          spark={<Spark values={data.series.map((p) => p.blocked)} color="var(--s2)" />} />
        <Tile label="Tool calls" value={compact.format(t.tools)} sub="run by agents" />
        <Tile label="Active users" value={num.format(t.users)} sub="sent at least one request" />
        <Tile label="Sessions" value={num.format(t.sessions)} sub="Claude Code conversations" />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Trend title="Model requests" data={data.series} field="requests" color="var(--s1)" hours={hours} />
        <Trend title="Blocked requests" data={data.series} field="blocked" color="var(--s2)" hours={hours} />
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Ranked title="Top users" rows={data.users} segs={(r) => [r.allowed, r.blocked]} legend empty="No activity yet" />
        <Ranked title="Top tools" rows={data.tools} segs={(r) => [r.allowed, r.blocked]} legend empty="No tool calls yet" mono />
        <Ranked title="Rules that blocked" rows={data.rules} segs={(r) => [0, r.blocked]} empty="Nothing blocked" mono />
        <Ranked title="Tokens by model" rows={data.models} segs={(r) => [r.tokens, 0]} empty="No requests yet" mono />
      </div>
    </div>
  )
}

const KIND: Record<string, string> = { tool: 'Tool', prompt: 'Prompt', request: 'Request' }

export function Events({ hours }: { hours: number }) {
  const [show, setShow] = useState('all')
  const [q, setQ] = useState('')
  const { data, error } = useApi<Event[]>(`/api/events?hours=${hours}&show=${show}&q=${encodeURIComponent(q)}`)
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-3">
        <select className={input} value={show} onChange={(e) => setShow(e.target.value)} aria-label="Event type">
          <option value="all">All events</option>
          <option value="blocked">Blocked</option>
          <option value="tool">Tool calls</option>
          <option value="prompt">Prompts</option>
          <option value="request">Model requests</option>
        </select>
        <label className="relative">
          <Icon name="search" className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted" />
          <input className={`${input} w-80 max-w-full pl-9`} type="search" placeholder="Search user, tool, rule, detail, session" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
      </div>
      {error && <Notice>Could not load events: {error}</Notice>}
      <div className="overflow-x-auto rounded-xl border border-line bg-surface">
        <table className="w-full text-sm">
          <thead className="border-b border-line">
            <tr>
              <th className={th}>Time</th><th className={th}>User</th><th className={th}>Session</th><th className={th}>Event</th>
              <th className={th}>Detail</th><th className={th}>Decision</th><th className={`${th} text-right`}>Tokens</th>
            </tr>
          </thead>
          <tbody>
            {data?.map((e) => (
              <tr key={e.id} className="border-b border-line align-top last:border-0 hover:bg-sunken">
                <td className="whitespace-nowrap px-4 py-2.5 tabular-nums text-ink2" title={new Date(e.ts * 1000).toISOString()}>{fullFmt.format(e.ts * 1000)}</td>
                <td className="whitespace-nowrap px-4 py-2.5">{e.user}</td>
                <td className="whitespace-nowrap px-4 py-2.5">
                  {e.session && (
                    <button className="font-mono text-xs text-ink2 underline-offset-2 hover:text-ink hover:underline" title="Show only this session" onClick={() => setQ(e.session)}>{e.session}</button>
                  )}
                </td>
                <td className="whitespace-nowrap px-4 py-2.5">
                  <span className="mr-2 rounded border border-line px-1.5 py-0.5 text-xs text-ink2">{KIND[e.kind] ?? e.kind}</span>
                  <span className="font-mono text-[13px]">{e.tool || (e.kind === 'request' ? e.model : '')}</span>
                </td>
                <td className="max-w-md break-words px-4 py-2.5 font-mono text-xs text-ink2">{e.detail}</td>
                <td className="px-4 py-2.5"><Decision blocked={e.decision === 'block'} rule={e.rule} /></td>
                <td className="px-4 py-2.5 text-right tabular-nums text-ink2">{e.tokens_in + e.tokens_out ? num.format(e.tokens_in + e.tokens_out) : ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {data?.length === 0 && <Empty>No events match</Empty>}
      </div>
      {data?.length === 200 && <p className="text-xs text-muted">Showing the latest 200. Narrow the range or search to see older events.</p>}
    </div>
  )
}

export function Members() {
  const [version, setVersion] = useState(0)
  const { data, error } = useApi<Member[]>('/api/members', version)
  const [name, setName] = useState('')
  const [created, setCreated] = useState<Member>()
  const [failure, setFailure] = useState('')
  const [copied, setCopied] = useState(false)

  async function add(e: FormEvent) {
    e.preventDefault()
    try {
      setCreated(await post<Member>('/api/members', { name }))
      setName('')
      setFailure('')
      setCopied(false)
      setVersion((v) => v + 1)
    } catch (err) {
      setFailure((err as Error).message)
    }
  }
  async function remove(m: Member) {
    if (!confirm(`Remove ${m.name}? Their Claude Code will stop working through Gatehouse.`)) return
    await api(`/api/members/${m.id}`, { method: 'DELETE' })
    setVersion((v) => v + 1)
  }
  // skipWebFetchPreflight: that check calls api.anthropic.com directly, which the network blocks.
  const snippet = created && JSON.stringify({ env: { ANTHROPIC_BASE_URL: `${location.origin}/m/${created.token}` }, skipWebFetchPreflight: true }, null, 2)

  return (
    <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
      <Card title="Connect a team member">
        <p className="mb-4 text-sm text-ink2">
          Each person keeps signing in to Claude Code with their own Claude account. Gatehouse gives them a personal address to send it through.
        </p>
        <form onSubmit={add} className="flex gap-2">
          <input className={`${input} min-w-0 flex-1`} placeholder="name@company.com" value={name} onChange={(e) => setName(e.target.value)} required maxLength={100} aria-label="Member name or email" />
          <button className={btnPrimary}>Add member</button>
        </form>
        {failure && <div className="mt-3"><Notice>{failure}</Notice></div>}
        {snippet && (
          <div className="mt-5 border-t border-line pt-5 text-sm">
            <p className="font-medium">Send this to {created.name}</p>
            <p className="mt-1 text-ink2">It goes in <code className="font-mono text-xs">~/.claude/settings.json</code>. It is shown only once.</p>
            <pre className="mt-3 overflow-x-auto rounded-lg bg-sunken p-3 font-mono text-xs leading-relaxed">{snippet}</pre>
            <button className={`${btnQuiet} mt-3`} onClick={() => navigator.clipboard.writeText(snippet).then(() => setCopied(true))}>
              <Icon name={copied ? 'check' : 'copy'} />{copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        )}
      </Card>
      <div className="overflow-x-auto rounded-xl border border-line bg-surface">
        {error && <div className="p-4"><Notice>Could not load members: {error}</Notice></div>}
        <table className="w-full text-sm">
          <thead className="border-b border-line">
            <tr><th className={th}>Member</th><th className={th}>Added</th><th className={th}>Last seen</th><th className={th} /></tr>
          </thead>
          <tbody>
            {data?.map((m) => (
              <tr key={m.id} className="border-b border-line last:border-0 hover:bg-sunken">
                <td className="px-4 py-2.5">
                  <span className="flex items-center gap-2.5">
                    <span className="grid size-7 place-items-center rounded-full bg-sunken text-xs font-medium uppercase text-ink2">{m.name.slice(0, 1)}</span>
                    {m.name}
                  </span>
                </td>
                <td className="px-4 py-2.5 text-ink2">{dayFmt.format(m.created * 1000)}</td>
                <td className="px-4 py-2.5 text-ink2">{ago(m.last_seen)}</td>
                <td className="px-4 py-2.5 text-right"><button className="text-ink2 underline-offset-2 hover:text-ink hover:underline" onClick={() => remove(m)}>Remove</button></td>
              </tr>
            ))}
          </tbody>
        </table>
        {data?.length === 0 && <Empty>No members yet. Add the first one to get its connection settings.</Empty>}
      </div>
    </div>
  )
}

function Rules({ title, note, rules }: { title: string; note: string; rules: Rule[] | null }) {
  return (
    <Card title={title} aside={rules && <span className="rounded-full bg-sunken px-2 py-0.5 text-xs tabular-nums text-ink2">{rules.length}</span>}>
      <p className="mb-3 text-sm text-ink2">{note}</p>
      {rules === null ? <Empty>Not restricted</Empty> : rules.length === 0 && <Empty>None</Empty>}
      <ul>
        {rules?.map((r) => (
          <li key={r.name} className="border-t border-line py-2.5">
            <div className="text-sm font-medium">{r.name}</div>
            <code className="mt-1 block break-all font-mono text-xs text-ink2">{r.pattern}</code>
          </li>
        ))}
      </ul>
    </Card>
  )
}

export function PolicyView() {
  const { data, error } = useApi<Policy>('/api/policy')
  if (error) return <Notice>Could not load policy: {error}</Notice>
  if (!data) return null
  return (
    <div className="grid items-start gap-4 lg:grid-cols-2">
      <Rules title="Denied paths" note="A request is blocked if the agent read, edited or listed a matching path." rules={data.deny_paths ?? []} />
      <Rules title="Denied commands" note="A request is blocked if the agent ran a matching shell command." rules={data.deny_commands ?? []} />
      <Rules title="Secrets" note="A request is blocked if any part of the conversation matches." rules={data.secrets ?? []} />
      <Rules title="Approved MCP tools" note="Requests that carry any other MCP tool are blocked." rules={data.allow_mcp} />
      <p className="text-xs text-muted lg:col-span-2">
        Prompt text is {data.log_content ? 'stored in full' : 'not stored, only its length'}. Policy is read from the server's policy file at startup.
      </p>
    </div>
  )
}
