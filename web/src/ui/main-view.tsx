import { useEffect, useMemo, useState } from 'preact/hooks';
import { ConflictError, type ItemView, type VaultView } from '../vault/index.ts';
import { ConflictDialog, ConfirmDialog, NewVaultDialog, VaultDialog } from './vault-dialogs.tsx';
import { Avatar, Banner, Check, Empty, Icon, plural, Popup, type IconName } from './kit.tsx';
import { AccountDialog } from './account.tsx';
import { ContactsDialog, PendingShareDialog } from './trust-dialogs.tsx';
import { AdminDialog } from './admin.tsx';
import { useApp, useSessionTick } from './ctx.ts';
import { EntryDetail } from './detail.tsx';
import { EntryEditor, type EditorTarget } from './editor.tsx';
import { errMsg } from './errors.ts';
import { majority, StatusIndicator, vaultBlock, writeBlock } from './status.tsx';

type Dialog =
  | { kind: 'vault'; id: string; tab?: 'general' | 'members' }
  | { kind: 'newVault' }
  | { kind: 'account'; tab?: 'backup' }
  | { kind: 'contacts' }
  | { kind: 'recovery' }
  | { kind: 'pending'; id: string }
  | { kind: 'admin' }
  | { kind: 'signout' }
  | { kind: 'conflict'; err: ConflictError }
  | { kind: 'delete'; vaultId: string; itemId: string };

interface Row {
  vault: VaultView;
  view: ItemView;
}

// Search text and sort key per decrypted entry, computed once per ItemView (views are reused across syncs while an entry is unchanged).
const haystacks = new WeakMap<ItemView, string>();
const collator = new Intl.Collator();
function matches(r: Row, words: string[]): boolean {
  const it = r.view.item;
  if (!it) return false;
  let hay = haystacks.get(r.view);
  if (hay === undefined) haystacks.set(r.view, (hay = [it.name, it.username, ...it.urls, ...it.tags].join('\n').toLowerCase()));
  return words.every((w) => hay.includes(w));
}

const LOCK_TEXT: Record<string, string> = {
  undecryptable: 'could not be opened with your keys',
  older_epoch: 'is offered with an older key than this device has already seen. That is expected only after the administrator restored the servers from a backup, so it was not opened',
  key_mismatch: "cannot be opened because its sender's key changed unexpectedly",
  continuity: 'was offered with a different key than this device accepted before, so it was not opened',
  roster_missing_me: 'does not list you with your own key in its member list, so it was not opened',
};

const others = (v: VaultView) => v.members.filter((m) => !m.isSelf).map((m) => m.username);
const names = (l: string[]) => (l.length <= 3 ? l.join(', ').replace(/, ([^,]*)$/, ' and $1') : `${l.slice(0, 2).join(', ')} and ${l.length - 2} others`);

function vaultMeta(v: VaultView): string {
  if (v.state === 'locked') return 'Cannot be opened';
  const who = v.personal ? 'Only you' : v.members.length > 1 ? `Shared · ${plural(v.members.length, 'person', 'people')}` : 'Only you so far';
  return v.role === 'viewer' ? `${who} · view only` : who;
}
const vaultIcon = (v: VaultView): IconName => (v.state === 'locked' ? 'lock' : v.personal ? 'user' : 'users');

export function MainView() {
  const { session, toast, lock, signOut } = useApp();
  useSessionTick(session);
  const [vaultSel, setVaultSel] = useState('all');
  const [sel, setSel] = useState<{ vaultId: string; itemId: string } | null>(null);
  const [query, setQuery] = useState('');
  const [editor, setEditor] = useState<EditorTarget | null>(null);
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [pane, setPane] = useState<'vaults' | 'list' | 'detail'>('list');
  const [resetSeen, setResetSeen] = useState(false);
  const [restoreSure, setRestoreSure] = useState(false);

  // personal vault first, then by name (the server's order is arbitrary)
  const vaults = useMemo(() => [...session.vaults].sort((a, b) => +b.personal - +a.personal || a.name.localeCompare(b.name)), [session.vaults]);
  const current = vaultSel === 'all' ? undefined : vaults.find((v) => v.id === vaultSel);
  useEffect(() => {
    if (vaultSel !== 'all' && !current) setVaultSel('all');
  }, [vaults]);

  // On phones only one pane shows at a time: move focus into the pane that just appeared.
  useEffect(() => {
    if (!matchMedia('(max-width: 600px)').matches || document.activeElement?.id === 'search') return;
    const q = (s: string) => document.querySelector<HTMLElement>(s);
    (pane === 'detail' ? q('#detail-title') : pane === 'vaults' ? q('.sidebar .vault-link') : (q('.entry[aria-current=true]') ?? q('#list-title')))?.focus();
  }, [pane]);

  const rows: Row[] = useMemo(() => {
    const words = query.trim().toLowerCase().split(/\s+/);
    const out: Row[] = [];
    for (const v of vaults) {
      if (vaultSel !== 'all' && v.id !== vaultSel) continue;
      for (const view of v.items) out.push({ vault: v, view });
    }
    const filtered = words[0] ? out.filter((r) => matches(r, words)) : out;
    return filtered.sort((a, b) => collator.compare((a.view.item?.name ?? '~').toLowerCase(), (b.view.item?.name ?? '~').toLowerCase()));
  }, [vaults, vaultSel, query]);

  const total = vaults.reduce((n, v) => n + v.items.length, 0);
  const selRow = sel ? vaults.find((v) => v.id === sel.vaultId)?.items.find((i) => i.id === sel.itemId) : undefined;
  const selVault = sel ? vaults.find((v) => v.id === sel.vaultId) : undefined;
  const canWriteIn = (v?: VaultView) => !!v && !vaultBlock(session, v);
  const newTarget: VaultView | undefined = (current && canWriteIn(current) ? current : undefined) ?? vaults.find((v) => v.personal && canWriteIn(v)) ?? vaults.find(canWriteIn);
  const newWhy = newTarget ? null : current ? vaultBlock(session, current) : writeBlock(session);
  const block = writeBlock(session);
  const shared = vaults.some((v) => !v.personal && v.state === 'open');

  const owned = vaults.filter((v) => v.role === 'owner' && v.rekeyRecommended && v.state === 'open');
  const pending = vaults.filter((v) => v.state === 'pending');
  const selectVault = (id: string) => {
    setVaultSel(id);
    setPane('list');
    // an entry that is not in the newly selected vault must not stay selected
    if (id !== 'all' && sel && sel.vaultId !== id) setSel(null);
  };
  const newEntry = () => newTarget && setEditor({ vaultId: newTarget.id });
  const newVault = () => setDialog({ kind: 'newVault' });

  async function doDelete(vaultId: string, itemId: string) {
    try {
      await session.deleteItem(vaultId, itemId);
      setSel(null);
      setPane('list');
      toast('Entry deleted');
    } catch (e) {
      if (e instanceof ConflictError) setDialog({ kind: 'conflict', err: e });
      else toast(errMsg(e), 'error');
    }
  }

  const listMeta = !current
    ? `${plural(total, 'entry', 'entries')} in ${plural(vaults.filter((v) => v.state === 'open').length, 'vault')}`
    : current.state === 'locked'
      ? 'This vault cannot be opened'
      : `${current.personal ? 'Only you' : others(current).length ? `Shared with ${names(others(current))}` : 'Only you so far'} · ${plural(current.items.length, 'entry', 'entries')}`;

  // The same vnode is returned while rows, selection and the "All entries" flag are unchanged, so Preact skips diffing thousands of rows on unrelated renders.
  const activeId = sel?.itemId;
  const entryList = useMemo(
    () => (
      <ul class="entries" aria-label={`${plural(rows.length, 'entry', 'entries')}`}>
        {rows.map((r) => {
          const active = activeId === r.view.id;
          const it = r.view.item;
          const sub = [it ? (it.type === 'note' ? 'Secure note' : it.username) : r.view.error, vaultSel === 'all' && r.vault.name].filter(Boolean).join(' · ');
          return (
            <li>
              <button type="button" class="entry" aria-current={active} onClick={() => { setSel({ vaultId: r.vault.id, itemId: r.view.id }); setPane('detail'); }}>
                {it ? <Avatar name={it.name} /> : <span class="avatar warn" aria-hidden="true">!</span>}
                <span class="entry-text">
                  <span class="entry-name">{it?.name ?? 'Unreadable entry'}</span>
                  {sub && <span class="entry-sub">{sub}</span>}
                </span>
              </button>
            </li>
          );
        })}
      </ul>
    ),
    [rows, activeId, vaultSel === 'all'],
  );

  return (
    <div class="shell" data-pane={pane}>
      <header class="topbar">
        <button type="button" class="icon-btn only-narrow" aria-label="Vaults" onClick={() => setPane('vaults')}>
          <Icon name="menu" />
        </button>
        <div class="brand">
          <img src="/icon.svg" alt="" width="28" height="28" />
          <span>Family Vault</span>
        </div>
        <div class="search">
          <Icon name="search" />
          <label class="sr-only" for="search">
            Search entries
          </label>
          <input id="search" type="search" placeholder="Search entries" value={query} autocomplete="off" onInput={(e) => { setQuery(e.currentTarget.value); setPane('list'); }} />
        </div>
        <StatusIndicator session={session} onRetry={async () => void (await session.refresh())} />
        <div class="top-actions">
          <button type="button" class="btn ghost" onClick={lock} title="Remove your keys from memory now. Unlock again with your master password.">
            <Icon name="lock" />
            <span class="lbl">Lock</span>
          </button>
          <Popup
            label={`${session.username}: account menu`}
            class="btn ghost acct"
            head={
              <>
                <strong>{session.username}</strong>
                <span class="muted">{session.isAdmin ? 'Administrator' : 'Member'}</span>
              </>
            }
            items={[
              { label: 'People and fingerprints', icon: 'shield', onSelect: () => setDialog({ kind: 'contacts' }) },
              { label: 'Account and backup', icon: 'user', onSelect: () => setDialog({ kind: 'account' }) },
              ...(session.isAdmin ? [{ label: 'Administration', icon: 'settings' as const, onSelect: () => setDialog({ kind: 'admin' }) }] : []),
              { label: 'Sign out of this device', icon: 'logout', onSelect: () => setDialog({ kind: 'signout' }) },
            ]}
            button={
              <>
                <Avatar name={session.username} />
                <span class="lbl">{session.username}</span>
                <Icon name="down" />
              </>
            }
          />
        </div>
      </header>

      <div class="banners">
        {session.mismatchWarnings.map((w) => (
          <Banner kind="error" action={<button type="button" class="btn small" onClick={() => void session.dismissMismatch(w.id)}>I understand: dismiss</button>}>
            <strong>Warning: {w.username}'s {w.kind === 'key' ? 'encryption key' : w.kind === 'username' ? 'username' : w.kind === 'userid' ? 'name appears under a different account' : 'key in a vault member list'} is different from what this device saw before.</strong>{' '}
            Someone may be impersonating them. Nothing is shared with, or accepted from, this identity. Call {w.username} or talk in person.
          </Banner>
        ))}
        {session.recovery && (
          <Banner
            kind="error"
            action={session.canAcceptRecovery ? <button type="button" class="btn small" onClick={() => { setRestoreSure(false); setDialog({ kind: 'recovery' }); }}>Accept the restored state…</button> : undefined}
          >
            <strong>The servers are showing older data than this device has already seen.</strong> This is expected only if the administrator restored the servers from a backup; otherwise do not accept it.
            Your saved copy stays readable, and changes are turned off until you decide.
            {!session.canAcceptRecovery && ' Part of what the servers show does not look like a restored backup, so it cannot be accepted.'}
          </Banner>
        )}
        {session.syncProblem && !session.recovery && <Banner kind="error">{session.syncProblem.message}</Banner>}
        {session.trustResetReason && !resetSeen && (
          <Banner kind="warn" action={<button type="button" class="btn small" onClick={() => setResetSeen(true)}>OK</button>}>
            {session.trustResetReason === 'unopenable' ? 'The list of people you verified on this device could not be read' : 'This device had no saved list of people you verified'}, so everyone counts as not verified again
            and shared vaults will ask you to compare fingerprints once more. That is safe.
          </Banner>
        )}
        {session.mode === 'offline' && (
          <Banner kind="info">
            <strong>You are offline.</strong> You can still look up and copy passwords saved on this device. Changes are off until a server can be reached.
          </Banner>
        )}
        {session.mode === 'stale' && (
          <Banner kind="warn">
            <strong>Most of the servers cannot be reached.</strong> You are seeing the last copy a server has, which may be out of date. Changes are off until {majority(session)} can be reached.
          </Banner>
        )}
        {pending.map((v) => (
          <Banner kind="info" action={<button type="button" class="btn small primary" onClick={() => setDialog({ kind: 'pending', id: v.id })}>Review…</button>}>
            <strong>{v.pending?.senderName} shared a vault with you.</strong> It stays closed until you confirm it really came from {v.pending?.senderName}.
          </Banner>
        ))}
        {owned.map((v) => (
          <Banner kind="warn" action={<button type="button" class="btn small" onClick={() => setDialog({ kind: 'vault', id: v.id, tab: 'members' })}>Replace the key…</button>}>
            Someone left or was removed from <strong>{v.name}</strong>. Replace the vault's key so their old copy cannot open anything saved from now on.
          </Banner>
        ))}
        {vaults.filter((v) => v.state === 'locked').map((v) => (
          <Banner kind="error">
            The vault “{v.name}” {LOCK_TEXT[v.locked ?? 'undecryptable']}.
          </Banner>
        ))}
      </div>

      <nav class="sidebar" aria-label="Vaults">
        <h2 class="side-heading">Vaults</h2>
        <ul class="vault-list">
          <li>
            <button type="button" class="vault-link" aria-current={vaultSel === 'all'} onClick={() => selectVault('all')}>
              <Icon name="grid" />
              <span class="vault-name">All entries</span>
              <span class="count">{total}</span>
            </button>
          </li>
          {vaults.filter((v) => v.state !== 'pending').map((v) => (
            <li>
              <button type="button" class="vault-link" aria-current={vaultSel === v.id} onClick={() => selectVault(v.id)}>
                <Icon name={vaultIcon(v)} />
                <span class="vault-name">
                  {v.name}
                  <span class="vault-meta">{vaultMeta(v)}</span>
                </span>
                {v.state === 'open' && <span class="count">{v.items.length}</span>}
              </button>
            </li>
          ))}
        </ul>
        {pending.length > 0 && (
          <>
            <h2 class="side-heading">Waiting for you</h2>
            <ul class="vault-list">
              {pending.map((v) => (
                <li>
                  <button type="button" class="vault-link pending" onClick={() => setDialog({ kind: 'pending', id: v.id })}>
                    <Icon name="inbox" />
                    <span class="vault-name">
                      From {v.pending?.senderName}
                      <span class="vault-meta">Waiting for you to confirm the sender</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </>
        )}
        <button type="button" class="btn block" onClick={newVault} disabled={!!block}>
          <Icon name="plus" />
          New vault
        </button>
        <p class="side-help">{block ?? 'Everyone you share a vault with can see everything in it.'}</p>
        <button type="button" class="btn block only-narrow" onClick={() => setPane('list')}>
          Back to entries
        </button>
      </nav>

      <main class="list-pane" aria-labelledby="list-title">
        <div class="list-head">
          <div class="list-title-row">
            <div class="list-title">
              <h1 id="list-title" tabIndex={-1}>
                {current ? current.name : 'All entries'}
              </h1>
              <p class="list-meta">{listMeta}</p>
            </div>
            <button type="button" class="btn primary" disabled={!newTarget} aria-describedby={newWhy ? 'new-why' : undefined} onClick={newEntry}>
              <Icon name="plus" />
              New entry
            </button>
          </div>
          {current && current.state === 'open' && (
            <div class="btn-row">
              {!current.personal && (
                <button type="button" class="btn small" onClick={() => setDialog({ kind: 'vault', id: current.id, tab: 'members' })}>
                  <Icon name={current.role === 'owner' ? 'share' : 'users'} />
                  {current.role === 'owner' ? 'Share' : 'Members'}
                </button>
              )}
              <button type="button" class="btn small" onClick={() => setDialog({ kind: 'vault', id: current.id })}>
                <Icon name="settings" />
                Vault settings
              </button>
            </div>
          )}
          {newWhy && (
            <p class="hint" id="new-why">
              {newWhy}
            </p>
          )}
        </div>
        {current && current.state === 'locked' ? (
          <Empty icon="lock" title="This vault cannot be opened">
            It {LOCK_TEXT[current.locked ?? 'undecryptable']}. Nothing in it is shown.
          </Empty>
        ) : rows.length === 0 ? (
          query ? (
            <Empty icon="search" title="No matches" action={<button type="button" class="btn" onClick={() => setQuery('')}>Clear the search</button>}>
              Nothing {current ? `in ${current.name} ` : ''}matches “{query.trim()}”. Search looks at names, usernames, websites and tags.
            </Empty>
          ) : current ? (
            <Empty icon={vaultIcon(current)} title={`${current.name} is empty`} action={newTarget && <button type="button" class="btn primary" onClick={newEntry}>Add an entry</button>}>
              {current.personal
                ? 'Entries here are only for you.'
                : others(current).length
                  ? `Everything you add here is shared with ${names(others(current))}.`
                  : 'Add entries, then use Share to give others access.'}
            </Empty>
          ) : (
            <Empty
              icon="key"
              title="No passwords yet"
              action={
                <>
                  {newTarget && <button type="button" class="btn primary" onClick={newEntry}>Add your first password</button>}
                  {!shared && !block && <button type="button" class="btn" onClick={newVault}>Create a shared vault</button>}
                </>
              }
            >
              Everything you save is encrypted on this device first. For passwords you share with others, create a shared vault.
            </Empty>
          )
        ) : (
          entryList
        )}
      </main>

      <section class="detail-pane" aria-label="Entry details">
        {selRow && selVault ? (
          <EntryDetail
            vault={selVault}
            view={selRow}
            why={vaultBlock(session, selVault)}
            onBack={() => setPane('list')}
            onEdit={() => setEditor({ vaultId: selVault.id, itemId: selRow.id })}
            onDelete={() => setDialog({ kind: 'delete', vaultId: selVault.id, itemId: selRow.id })}
          />
        ) : total === 0 || !shared ? (
          <GettingStarted
            items={total}
            shared={shared}
            block={block}
            onNew={newTarget && newEntry}
            onVault={newVault}
            onInvite={() => setDialog({ kind: 'admin' })}
            onBackup={() => setDialog({ kind: 'account', tab: 'backup' })}
          />
        ) : (
          <Empty icon="key" title="Select an entry">
            Choose an entry from the list to see its details, or search for one at the top.
          </Empty>
        )}
      </section>

      {editor && (
        <EntryEditor
          target={editor}
          onClose={(id) => {
            if (id) setSel({ vaultId: editor.vaultId, itemId: id });
            if (id) setPane('detail');
            setEditor(null);
          }}
          onConflict={(err) => setDialog({ kind: 'conflict', err })}
        />
      )}
      {dialog?.kind === 'vault' && <VaultDialog vaultId={dialog.id} initialTab={dialog.tab} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'newVault' && <NewVaultDialog onClose={(id) => { setDialog(null); if (id) selectVault(id); }} />}
      {dialog?.kind === 'account' && <AccountDialog initialTab={dialog.tab} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'recovery' && (
        <ConfirmDialog
          title="Accept the restored state?"
          confirmLabel="Accept the restored state"
          danger
          confirmDisabled={!restoreSure}
          onCancel={() => setDialog(null)}
          onConfirm={async () => {
            if (!restoreSure) return;
            try {
              await session.acceptRestoredState();
              toast('Restored state accepted');
              setDialog(null);
            } catch (e) {
              toast(errMsg(e), 'error');
            }
          }}
        >
          <p>Only do this if the administrator really restored the servers from a backup. If not, the servers (or someone between you and them) may be showing you old or forged data.</p>
          <p>This device will then trust what the servers show now: its record of key versions and the saved copy are reset from them. The people you verified stay verified, and so does every warning about changed keys. Vaults shared by people you have not verified will ask you to compare fingerprints again.</p>
          <Check strong checked={restoreSure} onChange={setRestoreSure} label="I know the administrator restored a backup" />
        </ConfirmDialog>
      )}
      {dialog?.kind === 'signout' && (
        <ConfirmDialog title="Sign out of this device?" confirmLabel="Sign out" onCancel={() => setDialog(null)} onConfirm={signOut}>
          <p>This removes the copy of your vaults saved on this device; your passwords stay on the servers. To just protect the screen, use Lock instead.</p>
        </ConfirmDialog>
      )}
      {dialog?.kind === 'contacts' && <ContactsDialog onClose={() => setDialog(null)} />}
      {dialog?.kind === 'pending' && <PendingShareDialog vaultId={dialog.id} onClose={(ok) => { setDialog(null); if (ok) selectVault(dialog.id); }} />}
      {dialog?.kind === 'admin' && <AdminDialog onClose={() => setDialog(null)} />}
      {dialog?.kind === 'conflict' && (
        <ConflictDialog
          err={dialog.err}
          onClose={() => setDialog(null)}
          onEditAgain={() => {
            const e = dialog.err;
            setDialog(null);
            if (e.theirs) setEditor({ vaultId: e.vaultId, itemId: e.itemId });
          }}
        />
      )}
      {dialog?.kind === 'delete' && (
        <ConfirmDialog
          title="Delete this entry?"
          confirmLabel="Delete"
          danger
          onCancel={() => setDialog(null)}
          onConfirm={async () => {
            const d = dialog;
            setDialog(null);
            await doDelete(d.vaultId, d.itemId);
          }}
        >
          <p>
            “{selRow?.item?.name ?? 'This entry'}” will be deleted for everyone who has access to {selVault ? `“${selVault.name}”` : 'this vault'}. This cannot be undone.
          </p>
        </ConfirmDialog>
      )}
    </div>
  );
}

function GettingStarted(p: { items: number; shared: boolean; block: string | null; onNew?: () => void; onVault: () => void; onInvite: () => void; onBackup: () => void }) {
  const { session } = useApp();
  const invited = session.directoryUsers().length > 1;
  const steps: [boolean, string, string, string, (() => void) | undefined][] = [
    [p.items > 0, 'Add your first password', 'Choose New entry and fill in the login. Generate makes a strong password for you.', 'Add a password', p.onNew],
    [p.shared, 'Make a vault to share', 'Your Personal vault is only for you. Passwords several people need go in a shared vault, such as “Household”.', 'Create a vault', p.block ? undefined : p.onVault],
  ];
  if (session.isAdmin) steps.push([invited, 'Invite your family', 'Create an invite code for each person. They open this page, choose Join with invite and type it.', 'Create an invite', p.onInvite]);
  steps.push([false, 'Keep a backup', 'Nobody can reset a forgotten master password: keep it written down somewhere safe, and download an encrypted backup now and then.', 'Download a backup', p.onBackup]);
  return (
    <div class="start">
      <h2>Welcome, {session.username}</h2>
      <p class="muted">A few steps to get your household set up:</p>
      <ol>
        {steps.map(([done, title, body, action, fn], i) => (
          <li class={done ? 'done' : undefined}>
            <span class="step-no" aria-hidden="true">
              {done ? <Icon name="check" /> : i + 1}
            </span>
            <div>
              <h3>
                {title}
                {done && <span class="sr-only"> (done)</span>}
              </h3>
              <p>{body}</p>
              {!done && fn && (
                <button type="button" class="btn small" onClick={fn}>
                  {action}
                </button>
              )}
            </div>
          </li>
        ))}
      </ol>
      {p.block && <p class="hint">{p.block}</p>}
    </div>
  );
}
