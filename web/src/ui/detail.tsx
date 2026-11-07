import { useEffect, useState } from 'preact/hooks';
import type { CustomField, Item } from '../crypto/index.ts';
import type { ItemView, VaultView } from '../vault/index.ts';
import { useApp } from './ctx.ts';
import { Avatar, fmtTime, Icon } from './kit.tsx';

function safeHref(u: string): string | null {
  try {
    const url = new URL(u.includes('://') ? u : 'https://' + u);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null;
  } catch {
    return null;
  }
}

/** A revealed password with digits and symbols told apart (shape AND colour), easier to read out or type. */
function Chars(p: { value: string }) {
  return (
    <>
      {[...p.value].map((c) => (/[0-9]/.test(c) ? <span class="ch-d">{c}</span> : /[^\p{L}\s]/u.test(c) ? <span class="ch-s">{c}</span> : c))}
    </>
  );
}

function Row(p: { label: string; value: string; secret?: boolean; mono?: boolean; multiline?: boolean; link?: boolean }) {
  const { copy } = useApp();
  const [shown, setShown] = useState(false);
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 2000);
    return () => clearTimeout(t);
  }, [copied]);
  const href = p.link ? safeHref(p.value) : null;
  return (
    <div class="detail-row">
      <div class="detail-label">{p.label}</div>
      <div class="detail-value">
        <span class={`${p.mono || p.secret ? 'mono ' : ''}${p.multiline ? 'pre ' : ''}value`}>
          {p.secret && !shown ? (
            <>
              <span aria-hidden="true">••••••••••••</span>
              <span class="sr-only">hidden</span>
            </>
          ) : href ? (
            <a href={href} target="_blank" rel="noopener noreferrer">
              {p.value}
              <Icon name="external" />
              <span class="sr-only"> (opens in a new tab)</span>
            </a>
          ) : p.secret ? (
            <Chars value={p.value} />
          ) : (
            p.value
          )}
        </span>
        <span class="row-actions">
          {p.secret && (
            <button type="button" class="btn small" aria-label={`${shown ? 'Hide' : 'Reveal'} ${p.label}`} onClick={() => setShown(!shown)}>
              <Icon name={shown ? 'eyeOff' : 'eye'} />
              <span class="lbl">{shown ? 'Hide' : 'Reveal'}</span>
            </button>
          )}
          <button
            type="button"
            class={copied ? 'btn small copied' : 'btn small'}
            aria-label={`Copy ${p.label}`}
            onClick={() => {
              copy(p.value, p.label);
              setCopied(true);
            }}
          >
            <Icon name={copied ? 'check' : 'copy'} />
            <span class="lbl">{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </span>
      </div>
    </div>
  );
}

function History(p: { item: Item }) {
  const [open, setOpen] = useState(false);
  if (p.item.password_history.length === 0) return null;
  return (
    <section class="history">
      <button type="button" class="link" aria-expanded={open} onClick={() => setOpen(!open)}>
        Earlier passwords ({p.item.password_history.length})
      </button>
      {open && (
        <ul>
          {p.item.password_history.map((h) => (
            <li>
              <Row label={`Password used until ${fmtTime(h.changed_at)}`} value={h.password} secret />
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function EntryDetail(p: {
  vault: VaultView;
  view: ItemView;
  /** why this entry cannot be changed right now (null when it can) */
  why: string | null;
  onEdit: () => void;
  onDelete: () => void;
  onBack: () => void;
}) {
  const it = p.view.item;
  // Reveal state lives in each Row; remounting on selection change hides everything again.
  const [, setK] = useState(0);
  useEffect(() => setK((k) => k + 1), [p.view.id]);
  const back = (
    <button type="button" class="btn small ghost back" onClick={p.onBack}>
      <Icon name="back" />
      Back
    </button>
  );
  const why = p.why && (
    <p class="note">
      <Icon name="info" />
      <span>{p.why} You can still view and copy everything.</span>
    </p>
  );
  if (!it) {
    return (
      <article class="detail">
        {back}
        <h2 id="detail-title" tabIndex={-1}>
          Unreadable entry
        </h2>
        <p>{p.view.error} It was probably written by a newer version of the app, or damaged. It is kept as it is on the server and carried over unchanged when the vault's key is replaced; backups skip it.</p>
        {why}
        <div class="btn-row">
          <button type="button" class="btn danger" onClick={p.onDelete} disabled={!!p.why}>
            <Icon name="trash" />
            Delete this entry
          </button>
        </div>
      </article>
    );
  }
  return (
    <article class="detail" key={p.view.id}>
      {back}
      <header class="detail-head">
        <Avatar name={it.name} big />
        <div class="detail-title">
          <h2 id="detail-title" tabIndex={-1}>
            {it.name}
          </h2>
          <p class="muted">
            {it.type === 'note' ? 'Secure note' : 'Login'} in {p.vault.name}
          </p>
        </div>
        <div class="btn-row">
          <button type="button" class="btn" onClick={p.onEdit} disabled={!!p.why}>
            <Icon name="edit" />
            Edit
          </button>
          <button type="button" class="btn danger" onClick={p.onDelete} disabled={!!p.why}>
            <Icon name="trash" />
            Delete
          </button>
        </div>
      </header>
      {why}
      <div class="detail-card">
        {it.type === 'login' && (
          <>
            {it.username && <Row label="Username" value={it.username} />}
            {it.password && <Row label="Password" value={it.password} secret />}
            {it.urls.map((u, i) => <Row label={it.urls.length > 1 ? `Website ${i + 1}` : 'Website'} value={u} link />)}
            {it.totp && <Row label="One-time code key" value={it.totp} secret />}
          </>
        )}
        {it.notes && <Row label="Notes" value={it.notes} multiline />}
        {it.fields.map((f: CustomField) => <Row label={f.name || 'Field'} value={f.value} secret={f.hidden} />)}
        {it.tags.length > 0 && (
          <div class="detail-row">
            <div class="detail-label">Tags</div>
            <div class="tags">{it.tags.map((t) => <span class="tag">{t}</span>)}</div>
          </div>
        )}
        {it.type === 'login' && !it.username && !it.password && !it.urls.length && !it.notes && !it.fields.length && <p class="muted">This entry has no details yet. Choose Edit to add them.</p>}
      </div>
      <History item={it} />
      <p class="muted small-text">
        Changed {fmtTime(it.updated_at || p.view.updatedAt)} · created {fmtTime(it.created_at)}
      </p>
    </article>
  );
}
