import type { ComponentChildren } from 'preact';
import { useId, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { checkMasterPassword, HINT_TEXT, MIN_PASSWORD_LENGTH, normalizeUsername, strengthLabel } from '../crypto/index.ts';
import { errMsg } from './errors.ts';

/** Item and secret fields must never be autocorrected, auto-capitalised or sent to a spellchecker service. */
/** `autocorrect` is a boolean DOM property in Chromium (assigning 'off' would turn it ON), so it is set as an attribute. */
const autocorrectOff = (el: Element | null) => el?.setAttribute('autocorrect', 'off');
export const NO_AUTOFIX = { spellcheck: false, autocapitalize: 'off', autocomplete: 'off', ref: autocorrectOff } as object;

// Hand-drawn 24x24 stroke icons (no icon font, no network, nothing for the CSP to block).
const ICONS = {
  plus: 'M12 5v14M5 12h14',
  lock: 'M6 11h12v10H6zM8 11V8a4 4 0 0 1 8 0v3',
  search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20 20l-4-4',
  copy: 'M9 9h11v11H9zM5 15H4V4h11v1',
  eye: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z',
  eyeOff: 'M3 3l18 18M10.6 5.1Q11.3 5 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4.2M6.6 6.6A17 17 0 0 0 2 12s3.5 7 10 7q2.9 0 5.3-1.6M9.9 9.9a3 3 0 0 0 4.2 4.2',
  check: 'M5 12.5l4.5 4.5L19 7.5',
  x: 'M6 6l12 12M18 6L6 18',
  down: 'M6 9l6 6 6-6',
  back: 'M15 6l-6 6 6 6',
  menu: 'M4 6h16M4 12h16M4 18h16',
  user: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0',
  users: 'M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM2 21a7 7 0 0 1 14 0M16 3.5a4 4 0 0 1 0 7.5M22 21a7 7 0 0 0-4.5-6.5',
  share: 'M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM2 21a7 7 0 0 1 14 0M19 8v6M16 11h6',
  grid: 'M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z',
  settings: 'M4 7h9M17 7h3M4 17h3M11 17h9M15 5v4M9 15v4',
  trash: 'M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3',
  edit: 'M4 20h4L19 9l-4-4L4 16zM14 6l4 4',
  refresh: 'M20 11a8 8 0 0 0-14.9-3M4 4v4h4M4 13a8 8 0 0 0 14.9 3M20 20v-4h-4',
  alert: 'M12 3l10 18H2zM12 10v4M12 17.5v.1',
  info: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 11v6M12 7.5v.1',
  key: 'M10.5 12.5a4.5 4.5 0 1 1-6.4 6.4 4.5 4.5 0 0 1 6.4-6.4zM10.5 12.5L21 2M17 6l3 3M14 9l2 2',
  server: 'M4 4h16v6H4zM4 14h16v6H4zM8 7h.1M8 17h.1',
  download: 'M12 4v11M7 10l5 5 5-5M4 20h16',
  inbox: 'M4 6h16v12H4zM4 7l8 6 8-6',
  shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM9 12l2 2 4-4',
  logout: 'M9 4H5v16h4M16 8l4 4-4 4M20 12H9',
  sparkle: 'M12 3l2 5.5 5.5 2-5.5 2L12 18l-2-5.5-5.5-2 5.5-2z',
  dot: 'M12 10a2 2 0 1 0 0 4 2 2 0 0 0 0-4z',
  external: 'M14 4h6v6M20 4l-9 9M18 14v6H4V6h6',
} as const;
export type IconName = keyof typeof ICONS;

export function Icon(p: { name: IconName }) {
  return (
    <svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path d={ICONS[p.name]} />
    </svg>
  );
}

/**
 * A busy flag and an error text around async actions. `run` clears the error, shows the busy state while `fn` runs and turns a throw into
 * the error text (`fmt` can override errMsg); it resolves to whether `fn` finished without throwing.
 */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const run = async (fn: () => Promise<unknown>, fmt: (e: unknown) => string = errMsg): Promise<boolean> => {
    setBusy(true);
    setError('');
    try {
      await fn();
      return true;
    } catch (e) {
      setError(fmt(e));
      return false;
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, setError, run };
}

/** A coloured initial (decorative; the name is always shown as text next to it). */
export function Avatar(p: { name: string; big?: boolean }) {
  let h = 0;
  for (const c of p.name) h = (h * 31 + c.codePointAt(0)!) >>> 0;
  const ch = (/[\p{L}\p{N}]/u.exec(p.name)?.[0] ?? '?').toUpperCase();
  return (
    <span class={`avatar av${h % 8}${p.big ? ' big' : ''}`} aria-hidden="true">
      {ch}
    </span>
  );
}

interface MenuItem {
  label: string;
  icon: IconName;
  onSelect: () => void;
}

/**
 * A button that opens a menu (`items`; arrow keys move between them) or a small
 * explanatory panel (`children`). Escape, Tab or a click outside closes it and
 * focus returns to the button.
 */
export function Popup(p: { class: string; label?: string; button: ComponentChildren; head?: ComponentChildren; items?: MenuItem[]; children?: ComponentChildren }) {
  const [open, setOpen] = useState(false);
  const wrap = useRef<HTMLDivElement>(null);
  const btn = useRef<HTMLButtonElement>(null);
  const id = useId();
  const menu = !!p.items;
  const close = () => {
    setOpen(false);
    btn.current?.focus();
  };
  const items = () => [...(wrap.current?.querySelectorAll<HTMLElement>('[role=menuitem]') ?? [])];
  // a layout effect, so the very next keypress after opening is already handled
  useLayoutEffect(() => {
    if (!open) return;
    items()[0]?.focus();
    const down = (e: PointerEvent) => !wrap.current?.contains(e.target as Node) && close();
    const key = (e: KeyboardEvent) => e.key === 'Escape' && (e.preventDefault(), close());
    document.addEventListener('pointerdown', down);
    document.addEventListener('keydown', key);
    return () => {
      document.removeEventListener('pointerdown', down);
      document.removeEventListener('keydown', key);
    };
  }, [open]);
  return (
    <div class="menu-wrap" ref={wrap}>
      <button
        ref={btn}
        type="button"
        class={p.class}
        aria-label={p.label}
        aria-haspopup={menu ? 'menu' : undefined}
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen(!open)}
        onKeyDown={(e) => menu && !open && e.key === 'ArrowDown' && (e.preventDefault(), setOpen(true))}
      >
        {p.button}
      </button>
      <div
        class={menu ? 'menu' : 'popover'}
        id={id}
        hidden={!open}
        role={menu ? 'menu' : undefined}
        aria-label={menu ? p.label : undefined}
        onKeyDown={(e) => {
          if (!menu) return;
          const l = items();
          const i = l.indexOf(document.activeElement as HTMLElement);
          const j = { ArrowDown: i + 1, ArrowUp: i - 1, Home: 0, End: -1 }[e.key];
          if (j === undefined) return void (e.key === 'Tab' && setOpen(false));
          e.preventDefault();
          l[(j + l.length) % l.length]?.focus();
        }}
      >
        {p.head && <div class="menu-head">{p.head}</div>}
        {p.items?.map((it) => (
          <button
            type="button"
            role="menuitem"
            tabIndex={-1}
            onClick={() => {
              close();
              it.onSelect();
            }}
          >
            <Icon name={it.icon} />
            {it.label}
          </button>
        ))}
        {p.children}
      </div>
    </div>
  );
}

/**
 * Says `msg` through a live region. While a modal dialog is open everything
 * outside it is hidden from assistive technology, so the region inside the
 * topmost open dialog is used; it is picked when the text is written, after a
 * dialog that is closing right now has gone.
 */
export function announce(msg: string, assertive = false) {
  const cls = assertive ? 'live-a' : 'live-p';
  setTimeout(() => {
    const inDialogs = document.querySelectorAll<HTMLElement>(`dialog[open] > .${cls}`);
    const el = inDialogs[inDialogs.length - 1] ?? document.getElementById(cls);
    if (!el) return;
    el.textContent = '';
    setTimeout(() => (el.textContent = msg), 60);
  }, 30);
}

/** The pair of empty live regions `announce` writes into. */
export const LiveRegions = (p: { ids?: boolean }) => (
  <>
    <div class="sr-only live-p" id={p.ids ? 'live-p' : undefined} role="status" />
    <div class="sr-only live-a" id={p.ids ? 'live-a' : undefined} role="alert" />
  </>
);

const TABBABLE = 'a[href], button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), summary, [tabindex="0"]';

/**
 * Modal dialog on the native <dialog>: the page behind is inert, Tab stays
 * inside, Escape closes (unless `dismissable` is false), and focus goes back to
 * whatever opened it.
 */
export function Modal(p: { title: ComponentChildren; onClose: () => void; children: ComponentChildren; footer?: ComponentChildren; wide?: boolean; dismissable?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null);
  const closing = useRef(false);
  const id = useId();
  const dismissable = p.dismissable ?? true;
  // opened before the browser paints, so no keypress can reach a dialog that is not modal yet
  useLayoutEffect(() => {
    const d = ref.current!;
    const back = document.activeElement as HTMLElement | null;
    if (!d.open) d.showModal();
    return () => {
      closing.current = true;
      if (d.open) d.close();
      // After every dialog closing in this render is gone: back to the opener, or, if it
      // went away too (a deleted entry, an accepted share) and focus was lost, the list heading.
      queueMicrotask(() => {
        if (back?.isConnected && back.getClientRects().length) back.focus();
        else if (document.activeElement === document.body) document.getElementById('list-title')?.focus();
      });
    };
  }, []);
  return (
    <dialog
      ref={ref}
      class={p.wide ? 'modal wide' : 'modal'}
      aria-labelledby={id}
      onCancel={(e) => {
        e.preventDefault();
        if (dismissable) p.onClose();
      }}
      onClose={() => {
        // Chromium may close a dialog itself after a repeated Escape; keep state in step.
        if (closing.current) return;
        if (dismissable) p.onClose();
        else ref.current?.showModal();
      }}
      onMouseDown={(e) => {
        if (dismissable && e.target === ref.current) p.onClose();
      }}
      onKeyDown={(e) => {
        // keep Tab inside this dialog (the browser would move on to its own toolbar)
        const d = ref.current!;
        if (e.key !== 'Tab' || (e.target as Element).closest('dialog') !== d) return;
        const all = [...d.querySelectorAll<HTMLElement>(TABBABLE)].filter((el) => el.closest('dialog') === d && el.getClientRects().length > 0);
        const [first, last] = [all[0], all[all.length - 1]];
        if (!first || !last) return;
        if (e.shiftKey ? document.activeElement === first : document.activeElement === last) {
          e.preventDefault();
          (e.shiftKey ? last : first).focus();
        }
      }}
    >
      <LiveRegions />
      <div class="modal-head">
        <h2 id={id}>{p.title}</h2>
        <button type="button" class="icon-btn" aria-label="Close" onClick={p.onClose}>
          <Icon name="x" />
        </button>
      </div>
      <div class="modal-body">{p.children}</div>
      {p.footer && <div class="modal-foot">{p.footer}</div>}
    </dialog>
  );
}

interface FieldProps {
  label: ComponentChildren;
  hint?: ComponentChildren;
  /** shown under the field and tied to it with aria-invalid/aria-describedby */
  error?: string;
  value: string;
  onInput: (v: string) => void;
  id?: string;
  type?: 'text' | 'password' | 'url';
  autocomplete?: string;
  required?: boolean;
  placeholder?: string;
  autofocus?: boolean;
  disabled?: boolean;
  inputMode?: 'url' | 'text';
  mono?: boolean;
  /** extra ids that describe the input (for example a rules list rendered elsewhere) */
  describedBy?: string;
  /** buttons rendered next to the input */
  after?: ComponentChildren;
}

/** Labelled input. type="password" gets a show/hide toggle and a Caps Lock warning. */
export function TextField(p: FieldProps) {
  const auto = useId();
  const id = p.id ?? auto;
  const [shown, setShown] = useState(false);
  const [caps, setCaps] = useState(false);
  const secret = p.type === 'password';
  const desc = [p.error && id + 'e', p.hint && id + 'h', caps && id + 'c', p.describedBy].filter(Boolean).join(' ') || undefined;
  return (
    <div class="field">
      <label for={id}>{p.label}</label>
      <div class="input-row">
        <input
          id={id}
          class={p.mono || (secret && shown) ? 'mono' : undefined}
          type={(secret && shown ? 'text' : (p.type ?? 'text')) as 'text'}
          value={p.value}
          onInput={(e) => p.onInput(e.currentTarget.value)}
          onKeyUp={secret ? (e) => setCaps(e.getModifierState('CapsLock')) : undefined}
          onBlur={() => setCaps(false)}
          autocomplete={p.autocomplete ?? 'off'}
          required={p.required}
          placeholder={p.placeholder}
          autofocus={p.autofocus}
          disabled={p.disabled}
          inputMode={p.inputMode}
          spellcheck={false}
          autocapitalize="off"
          ref={autocorrectOff}
          aria-invalid={p.error ? true : undefined}
          aria-describedby={desc}
        />
        {secret && (
          <button type="button" class="btn icon-only" aria-label="Show password" aria-pressed={shown} aria-controls={id} disabled={p.disabled} onClick={() => setShown(!shown)}>
            <Icon name={shown ? 'eyeOff' : 'eye'} />
          </button>
        )}
        {p.after}
      </div>
      {caps && (
        <p class="hint warn-text" id={id + 'c'}>
          Caps Lock is on.
        </p>
      )}
      {p.error && (
        <p class="field-error" id={id + 'e'}>
          <Icon name="alert" />
          {p.error}
        </p>
      )}
      {p.hint && (
        <p class="hint" id={id + 'h'}>
          {p.hint}
        </p>
      )}
    </div>
  );
}

export function TextArea(p: { label: string; value: string; onInput: (v: string) => void; rows?: number; disabled?: boolean }) {
  const id = useId();
  return (
    <div class="field">
      <label for={id}>{p.label}</label>
      <textarea id={id} rows={p.rows ?? 4} value={p.value} disabled={p.disabled} {...NO_AUTOFIX} onInput={(e) => p.onInput(e.currentTarget.value)} />
    </div>
  );
}

export function Check(p: { label: ComponentChildren; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; strong?: boolean }) {
  const id = useId();
  return (
    <div class={p.strong ? 'check strong' : 'check'}>
      <input id={id} type="checkbox" checked={p.checked} disabled={p.disabled} onChange={(e) => p.onChange(e.currentTarget.checked)} />
      <label for={id}>{p.label}</label>
    </div>
  );
}

/** Segmented choice (pressed buttons in a labelled group). */
export function Seg<T extends string>(p: { label: string; options: [T, string][]; value: T; onChange: (v: T) => void }) {
  return (
    <div class="seg" role="group" aria-label={p.label}>
      {p.options.map(([v, l]) => (
        <button type="button" aria-pressed={p.value === v} onClick={() => p.onChange(v)}>
          {l}
        </button>
      ))}
    </div>
  );
}

const BANNER_ICON = { info: 'info', warn: 'alert', error: 'alert', ok: 'check' } as const;

/** Only errors interrupt a screen reader (role=alert); other banners are read in place. */
export function Banner(p: { kind?: 'info' | 'warn' | 'error' | 'ok'; children: ComponentChildren; action?: ComponentChildren }) {
  const kind = p.kind ?? 'info';
  return (
    <div class={`banner ${kind}`} role={kind === 'error' ? 'alert' : undefined}>
      <Icon name={BANNER_ICON[kind]} />
      <div class="banner-text">{p.children}</div>
      {p.action && <div class="banner-action">{p.action}</div>}
    </div>
  );
}

/** A centred "nothing here yet" panel that says what to do next. */
export function Empty(p: { icon: IconName; title: string; children?: ComponentChildren; action?: ComponentChildren }) {
  return (
    <div class="empty">
      <span class="empty-icon">
        <Icon name={p.icon} />
      </span>
      <h2>{p.title}</h2>
      {p.children && <p>{p.children}</p>}
      {p.action && <div class="btn-row center">{p.action}</div>}
    </div>
  );
}

export function Spinner(p: { label: string }) {
  return (
    <span class="spinner-row" role="status">
      <span class="spinner" aria-hidden="true" />
      {p.label}
    </span>
  );
}

export function Progress(p: { done: number; total: number; label: string }) {
  return (
    <div class="progress-row" role="status">
      <label>
        {p.label}
        <progress max={p.total} value={p.done} />
      </label>
    </div>
  );
}

const LEVELS = ['too weak', 'weak', 'fair', 'good', 'strong'];

/** Strength estimate, shown as text AND a bar (not colour alone). */
export function StrengthMeter(p: { password: string }) {
  if (!p.password) return null;
  const s = strengthLabel(p.password).label;
  return (
    <div class={`strength s${LEVELS.indexOf(s)}`}>
      <div class="strength-bar" aria-hidden="true">
        <span />
      </div>
      <span class="strength-text">
        Strength: <strong>{s}</strong>
        {LEVELS.indexOf(s) < 2 && ' — a longer passphrase of several unrelated words is stronger'}
      </span>
    </div>
  );
}

const RULE_OF: Record<string, number> = { too_short: 0, contains_username: 1, repeated: 2, sequence: 2, common: 2 };
const PATTERN: Record<string, string> = { repeated: 'this one repeats a short pattern', sequence: 'this one is a simple run of characters', common: 'this one is on a list of very common passwords' };

/**
 * The master-password rules, visible BEFORE anyone types (they mirror
 * checkMasterPassword, which stays the single source of truth for the gate).
 */
export function PasswordRules(p: { id: string; password: string; username: string }) {
  const v = p.password ? checkMasterPassword(p.password, p.username) : null;
  const fail = v ? RULE_OF[v.code]! : p.password ? 3 : -1;
  const n = [...p.password.normalize('NFKC')].length;
  const rules = [
    <>At least {MIN_PASSWORD_LENGTH} characters{n > 0 && n < MIN_PASSWORD_LENGTH && <span class="muted"> ({n} so far)</span>}</>,
    'Does not contain your username',
    <>Not a common password or a simple pattern{fail === 2 ? <span class="muted"> ({PATTERN[v!.code]})</span> : ' such as “aaaa” or “abcd”'}</>,
  ];
  return (
    <div class="rules" id={p.id}>
      <p class="rules-title">Your master password needs:</p>
      <ul>
        {rules.map((r, i) => {
          const st = fail === -1 || i > fail || (i === 0 && fail === 0) ? 'todo' : i === fail ? 'bad' : 'ok';
          return (
            <li class={st}>
              <Icon name={st === 'ok' ? 'check' : st === 'bad' ? 'x' : 'dot'} />
              <span>
                {r}
                <span class="sr-only">{st === 'ok' ? ' (done)' : st === 'bad' ? ' (not met)' : ''}</span>
              </span>
            </li>
          );
        })}
      </ul>
      <p class="hint">Tip: {HINT_TEXT}</p>
      <StrengthMeter password={p.password} />
      <p class="sr-only" aria-live="polite">
        {p.password ? (v ? (v.code === 'too_short' ? 'Too short so far.' : v.reason) : 'The password meets the requirements.') : ''}
      </p>
    </div>
  );
}

/** Why a username would be refused, in words (normalizeUsername throws plain Errors). */
export function usernameProblem(u: string): string {
  if (!u.trim()) return '';
  try {
    normalizeUsername(u);
    return '';
  } catch {
    return 'Use 1–32 letters a–z, digits, dots, dashes or underscores, starting with a letter or digit.';
  }
}

/** Tabs with arrow-key navigation (roving tabindex) and a labelled tab panel. */
export function Tabs<T extends string>(p: { label: string; tabs: [T, string][]; current: T; onChange: (t: T) => void; children: ComponentChildren }) {
  const id = useId();
  const list = useRef<HTMLDivElement>(null);
  const cur = Math.max(0, p.tabs.findIndex(([t]) => t === p.current));
  const go = (i: number) => {
    const n = p.tabs.length;
    const j = (i + n) % n;
    p.onChange(p.tabs[j]![0]);
    (list.current?.children[j] as HTMLElement | undefined)?.focus();
  };
  return (
    <>
      <div
        class="tabs"
        role="tablist"
        aria-label={p.label}
        ref={list}
        onKeyDown={(e) => {
          const k = { ArrowRight: cur + 1, ArrowLeft: cur - 1, Home: 0, End: p.tabs.length - 1 }[e.key];
          if (k === undefined) return;
          e.preventDefault();
          go(k);
        }}
      >
        {p.tabs.map(([t, label], i) => (
          <button type="button" role="tab" id={`${id}-${i}`} aria-controls={`${id}-p`} aria-selected={i === cur} tabIndex={i === cur ? 0 : -1} class="tab" onClick={() => p.onChange(t)}>
            {label}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`${id}-p`} aria-labelledby={`${id}-${cur}`} class="tabpanel">
        {p.children}
      </div>
    </>
  );
}

/** A fingerprint (or invite code) split into its groups, so two people can read it out to each other; lines break only between groups. */
export function Fingerprint(p: { value: string; big?: boolean; class?: string }) {
  return (
    <span class={p.class ?? (p.big ? 'fp big' : 'fp')}>
      {p.value.split('-').map((g, i, all) => (
        <span class="fp-g">
          {g}
          {i < all.length - 1 && <span class="fp-sep">-</span>}
        </span>
      ))}
    </span>
  );
}

/** One row of a people / invites / servers list: `avatar`, the main lines as children, and `actions` on the right. */
export function MemberRow(p: { avatar: ComponentChildren; actions?: ComponentChildren; children: ComponentChildren }) {
  return (
    <li class="member">
      {p.avatar}
      <div class="member-main">{p.children}</div>
      {p.actions}
    </li>
  );
}

/** A person with their tags and fingerprint; `children` go under the fingerprint. */
export function PersonRow(p: { name: string; tags: ComponentChildren; fingerprint: string; actions?: ComponentChildren; children?: ComponentChildren }) {
  return (
    <MemberRow avatar={<Avatar name={p.name} />} actions={p.actions}>
      <div class="member-name">
        <strong>{p.name}</strong>
        {p.tags}
      </div>
      <Fingerprint value={p.fingerprint} />
      {p.children}
    </MemberRow>
  );
}

/** A fingerprint in its labelled box (the large form shown while two people compare). */
export function FingerprintBox(p: { label: string; value: string }) {
  return (
    <div class="fp-box">
      <div class="fp-label">{p.label}</div>
      <Fingerprint value={p.value} big />
    </div>
  );
}

export function fmtTime(ms: number): string {
  if (!ms) return '—';
  return new Date(ms).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

export const plural = (n: number, one: string, many = one + 's') => `${n} ${n === 1 ? one : many}`;
