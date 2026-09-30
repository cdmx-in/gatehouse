import type { ReactNode } from 'react'

const ICONS = {
  overview: <path d="M3 13V8M8 13V3M13 13V6" />,
  events: <path d="M3 4h10M3 8h10M3 12h6" />,
  members: <><circle cx="8" cy="5.5" r="2.5" /><path d="M3 13.5a5 5 0 0 1 10 0" /></>,
  policy: <path d="M8 2l5 2v4c0 3-2.2 5-5 6-2.8-1-5-3-5-6V4z" />,
  signout: <path d="M6 3H3v10h3M10 5l3 3-3 3M13 8H6" />,
  gate: <path d="M4 13V7a4 4 0 0 1 8 0v6" />,
  check: <path d="M3.5 8.5l3 3 6-7" />,
  block: <><circle cx="8" cy="8" r="5.5" /><path d="M4.2 4.2l7.6 7.6" /></>,
  search: <><circle cx="7" cy="7" r="4" /><path d="M10 10l3.5 3.5" /></>,
  copy: <><rect x="5.5" y="5.5" width="8" height="8" rx="1.5" /><path d="M3 10.5V3.5a1 1 0 0 1 1-1h7" /></>,
  alert: <><circle cx="8" cy="8" r="5.5" /><path d="M8 5v3.5M8 11v.01" /></>,
}
export type IconName = keyof typeof ICONS

export function Icon({ name, className = 'size-4' }: { name: IconName; className?: string }) {
  return (
    <svg viewBox="0 0 16 16" className={`shrink-0 ${className}`} fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      {ICONS[name]}
    </svg>
  )
}

export function Mark({ className = 'size-7' }: { className?: string }) {
  return (
    <span className={`grid place-items-center rounded-lg bg-ink text-surface ${className}`}>
      <Icon name="gate" className="size-[62%]" />
    </span>
  )
}

export const input = 'h-9 rounded-lg border border-line bg-surface px-3 text-sm placeholder:text-muted'
export const btn = 'inline-flex h-9 items-center justify-center gap-2 rounded-lg px-3.5 text-sm font-medium transition-colors disabled:opacity-50'
export const btnPrimary = `${btn} bg-ink text-surface hover:opacity-90`
export const btnQuiet = `${btn} border border-line bg-surface hover:bg-sunken`
export const th = 'px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-muted'

export function Card({ title, aside, children, className = '' }: { title?: string; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`min-w-0 rounded-xl border border-line bg-surface p-5 ${className}`}>
      {title && (
        <div className="mb-4 flex items-center justify-between gap-3">
          <h2 className="text-sm font-semibold">{title}</h2>
          {aside}
        </div>
      )}
      {children}
    </section>
  )
}

export function Legend() {
  return (
    <div className="flex gap-3 text-xs text-ink2">
      <span className="flex items-center gap-1.5"><i className="size-2.5 rounded-[3px] bg-s1" />Allowed</span>
      <span className="flex items-center gap-1.5"><i className="size-2.5 rounded-[3px] bg-s2" />Blocked</span>
    </div>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-8 text-center text-sm text-muted">{children}</p>
}

export function Notice({ children }: { children: ReactNode }) {
  return (
    <p role="alert" className="flex items-start gap-2 rounded-lg border border-line bg-sunken px-3 py-2 text-sm">
      <Icon name="alert" className="mt-0.5 size-4 text-s2" />
      <span>{children}</span>
    </p>
  )
}

// The icon carries the color; the label stays in text ink so it reads in any theme.
export function Decision({ blocked, rule }: { blocked: boolean; rule?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
      <Icon name={blocked ? 'block' : 'check'} className={`size-3.5 ${blocked ? 'text-s2' : 'text-s1'}`} />
      {blocked ? 'Blocked' : 'Allowed'}
      {rule && <code className="rounded bg-sunken px-1.5 py-0.5 font-mono text-xs text-ink2">{rule}</code>}
    </span>
  )
}
