import { useEffect, useState, type FormEvent } from 'react'
import { api, post, SIGNED_OUT } from './lib'
import { Events, Members, Overview, PolicyView } from './pages'
import { btnPrimary, Icon, input, Mark, Notice, type IconName } from './ui'

const PAGES = [
  { id: 'overview', label: 'Overview', blurb: 'Claude Code activity across the team', ranged: true },
  { id: 'events', label: 'Events', blurb: 'Every prompt, tool call and blocked request', ranged: true },
  { id: 'members', label: 'Members', blurb: 'People whose Claude Code runs through Gate', ranged: false },
  { id: 'policy', label: 'Policy', blurb: 'Rules enforced on every request', ranged: false },
] as const satisfies readonly { id: IconName; label: string; blurb: string; ranged: boolean }[]
type PageId = (typeof PAGES)[number]['id']

const RANGES = [[24, '24h'], [168, '7d'], [720, '30d'], [2160, '90d']] as const

function SignIn({ onDone }: { onDone: (user: string) => void }) {
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    const form = new FormData(e.currentTarget)
    setBusy(true)
    try {
      onDone((await post<{ user: string }>('/api/login', { user: form.get('user'), password: form.get('password') })).user)
    } catch (err) {
      setError((err as Error).message)
      setBusy(false)
    }
  }
  return (
    <main className="relative grid min-h-screen place-items-center px-4">
      <div className="backdrop absolute inset-0" aria-hidden />
      <form onSubmit={submit} className="relative w-full max-w-sm rounded-2xl border border-line bg-surface p-8 shadow-xl shadow-black/5">
        <Mark className="size-10" />
        <h1 className="mt-5 text-xl font-semibold tracking-tight">Sign in to Gate</h1>
        <p className="mt-1 text-sm text-ink2">Policy and audit for your team's Claude Code.</p>
        <label className="mt-6 block text-sm font-medium" htmlFor="user">Username</label>
        <input id="user" name="user" className={`${input} mt-1.5 w-full`} autoComplete="username" autoFocus required />
        <label className="mt-4 block text-sm font-medium" htmlFor="password">Password</label>
        <input id="password" name="password" type="password" className={`${input} mt-1.5 w-full`} autoComplete="current-password" required />
        {error && <div className="mt-4"><Notice>{error}</Notice></div>}
        <button className={`${btnPrimary} mt-6 w-full`} disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
      </form>
    </main>
  )
}

export default function App() {
  const [user, setUser] = useState<string | null>() // undefined while the session check is in flight
  // The page lives in the URL hash so a view can be linked or reloaded.
  const [page, setPageState] = useState<PageId>(() => PAGES.find((p) => '#' + p.id === location.hash)?.id ?? 'overview')
  const [hours, setHours] = useState(24)

  useEffect(() => {
    api<{ user: string }>('/api/session').then((r) => setUser(r.user), () => setUser(null))
    const signedOut = () => setUser(null)
    window.addEventListener(SIGNED_OUT, signedOut)
    return () => window.removeEventListener(SIGNED_OUT, signedOut)
  }, [])

  if (user === undefined) return null
  if (user === null) return <SignIn onDone={setUser} />

  const current = PAGES.find((p) => p.id === page)!
  const setPage = (id: PageId) => (setPageState(id), (location.hash = id))
  const signOut = () => post('/api/logout').finally(() => setUser(null))

  return (
    <div className="md:flex">
      <aside className="flex items-center gap-1 overflow-x-auto border-b border-line bg-surface px-3 py-2 md:sticky md:top-0 md:h-screen md:w-56 md:shrink-0 md:flex-col md:items-stretch md:border-b-0 md:border-r md:py-4">
        <div className="flex items-center gap-2.5 px-2 md:mb-5">
          <Mark />
          <span className="hidden text-[15px] font-semibold tracking-tight md:block">Gate</span>
        </div>
        <nav className="flex gap-1 md:flex-col">
          {PAGES.map((p) => (
            <button key={p.id} onClick={() => setPage(p.id)} aria-current={page === p.id ? 'page' : undefined}
              className={`flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition-colors ${page === p.id ? 'bg-sunken font-medium text-ink' : 'text-ink2 hover:bg-sunken hover:text-ink'}`}>
              <Icon name={p.id} /><span className={page === p.id ? '' : 'hidden sm:inline'}>{p.label}</span>
            </button>
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-2 md:ml-0 md:mt-auto md:border-t md:border-line md:pt-3">
          <span className="hidden min-w-0 flex-1 truncate px-2 text-sm text-ink2 md:block">{user}</span>
          <button onClick={signOut} title="Sign out" aria-label="Sign out" className="rounded-lg p-2 text-ink2 hover:bg-sunken hover:text-ink">
            <Icon name="signout" />
          </button>
        </div>
      </aside>
      <main className="min-w-0 flex-1">
        <header className="flex flex-wrap items-end justify-between gap-4 px-5 pb-5 pt-6 md:px-8">
          <div>
            <h1 className="text-xl font-semibold tracking-tight">{current.label}</h1>
            <p className="mt-0.5 text-sm text-ink2">{current.blurb}</p>
          </div>
          {current.ranged && (
            <div className="flex rounded-lg border border-line bg-surface p-0.5" role="group" aria-label="Time range">
              {RANGES.map(([h, label]) => (
                <button key={h} onClick={() => setHours(h)} aria-pressed={hours === h}
                  className={`rounded-md px-3 py-1 text-sm tabular-nums transition-colors ${hours === h ? 'bg-ink text-surface' : 'text-ink2 hover:text-ink'}`}>
                  {label}
                </button>
              ))}
            </div>
          )}
        </header>
        <div className="px-5 pb-10 md:px-8">
          {page === 'overview' && <Overview hours={hours} />}
          {page === 'events' && <Events hours={hours} />}
          {page === 'members' && <Members />}
          {page === 'policy' && <PolicyView />}
        </div>
      </main>
    </div>
  )
}
