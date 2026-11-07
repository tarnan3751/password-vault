import type { ComponentChildren } from 'preact';
import { useState } from 'preact/hooks';
import type { Role } from '../api/types.ts';
import { itemToJson, type Item } from '../crypto/index.ts';
import { ConflictError, type UserLookup } from '../vault/index.ts';
import { Compare, RekeyDialog, ROLE_LABEL, TrustTags } from './trust-dialogs.tsx';
import { useApp, useSessionTick } from './ctx.ts';
import { errMsg } from './errors.ts';
import { Avatar, Banner, FingerprintBox, Icon, Modal, PersonRow, plural, Spinner, Tabs, TextField, useAction } from './kit.tsx';
import { writeBlock } from './status.tsx';

export function ConfirmDialog(p: {
  title: string;
  children: ComponentChildren;
  confirmLabel: string;
  cancelLabel?: string;
  danger?: boolean;
  confirmDisabled?: boolean;
  onConfirm: () => void | Promise<void>;
  onCancel: () => void;
}) {
  const [busy, setBusy] = useState(false);
  return (
    <Modal
      title={p.title}
      onClose={p.onCancel}
      footer={
        <>
          <button type="button" class="btn" onClick={p.onCancel} autofocus>
            {p.cancelLabel ?? 'Cancel'}
          </button>
          <button
            type="button"
            class={p.danger ? 'btn danger solid' : 'btn primary'}
            disabled={busy || p.confirmDisabled}
            onClick={async () => {
              setBusy(true);
              try {
                await p.onConfirm();
              } finally {
                setBusy(false);
              }
            }}
          >
            {p.confirmLabel}
          </button>
        </>
      }
    >
      {p.children}
    </Modal>
  );
}

export function NewVaultDialog(p: { onClose: (createdId?: string) => void }) {
  const { session, toast } = useApp();
  const [name, setName] = useState('');
  const { busy, error, run } = useAction();
  return (
    <Modal
      title="New vault"
      onClose={() => p.onClose()}
      footer={
        <>
          <button type="button" class="btn" onClick={() => p.onClose()}>
            Cancel
          </button>
          <button type="submit" form="new-vault" class="btn primary" disabled={busy || !name.trim() || !session.canWrite}>
            Create vault
          </button>
        </>
      }
    >
      <form
        id="new-vault"
        onSubmit={(e) => {
          e.preventDefault();
          if (!name.trim()) return;
          void run(async () => {
            const id = await session.createVault(name.trim());
            toast(`Vault “${name.trim()}” created`);
            p.onClose(id);
          });
        }}
      >
        <p>Everyone you share a vault with can see everything in it, so make one per group of people, for example “Household” or “Kids”. At first only you are in it.</p>
        <TextField label="Vault name" value={name} onInput={setName} required autofocus placeholder="For example: Household" />
        {!session.canWrite && <Banner kind="warn">{writeBlock(session)}</Banner>}
        {busy && <Spinner label="Creating the vault…" />}
        {error && <Banner kind="error">{error}</Banner>}
      </form>
    </Modal>
  );
}

const ROLE_HELP: Record<Role, string> = {
  owner: 'Can add and change entries, share the vault, remove people, rename it, replace its key and delete it.',
  editor: 'Can add, change and delete entries.',
  viewer: 'Can see and copy entries, but not change them.',
};

const DISCREPANCY: Record<string, string> = {
  left: 'left: still has the current key until an owner replaces it',
  unlisted: "listed by the server but not in the vault's own member list: ignored",
  role_differs: 'the server shows a different access level',
};

function RoleSelect(p: { id: string; value: Role; onChange: (r: Role) => void; disabled?: boolean }) {
  return (
    <select id={p.id} value={p.value} disabled={p.disabled} onChange={(e) => p.onChange(e.currentTarget.value as Role)}>
      {(['viewer', 'editor', 'owner'] as const).map((r) => (
        <option value={r}>{ROLE_LABEL[r]}</option>
      ))}
    </select>
  );
}

export function VaultDialog(p: { vaultId: string; initialTab?: 'general' | 'members'; onClose: () => void }) {
  const { session, toast } = useApp();
  useSessionTick(session);
  const v = session.vault(p.vaultId);
  const [tab, setTab] = useState<'general' | 'members'>(p.initialTab ?? 'general');
  const [name, setName] = useState(v?.name ?? '');
  const { busy, error, setError, run } = useAction();
  const [confirm, setConfirm] = useState<null | { kind: 'delete' } | { kind: 'leave' }>(null);
  const [rekey, setRekey] = useState<null | { remove?: string[]; repair?: boolean }>(null);
  const [who, setWho] = useState('');
  const [found, setFound] = useState<UserLookup | null>(null);
  const [role, setRole] = useState<Role>('editor');
  const [compared, setCompared] = useState(false);

  if (!v) return null;
  const open = v.state === 'open';
  const owner = v.role === 'owner' && open;
  const write = session.canWrite && open;
  const block = writeBlock(session);

  const lookup = (u: string) => {
    setError('');
    try {
      setFound(session.lookupUser(u));
      setWho(u);
      setCompared(false);
    } catch (err) {
      setError(errMsg(err));
    }
  };

  const candidates = session.contacts().filter((c) => !c.isSelf && !c.disabled && !c.blocked && !v.members.some((m) => m.userId === c.userId));

  return (
    <Modal title={v.name} onClose={p.onClose} wide>
      {!open && <Banner kind="error">This vault is not open on this device, so you can only look at its details.</Banner>}
      {block && <Banner kind="warn">{block}</Banner>}
      <Tabs
        label="Vault settings"
        tabs={[
          ['general', 'General'],
          ['members', `Members (${v.members.length})`],
        ]}
        current={tab}
        onChange={setTab}
      >
        {error && <Banner kind="error">{error}</Banner>}

        {tab === 'general' && (
          <div class="stack">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void run(async () => {
                  await session.renameVault(v.id, name.trim());
                  toast('Vault renamed');
                });
              }}
            >
              <TextField
                label="Vault name"
                value={name}
                onInput={setName}
                disabled={!owner || !write}
                required
                hint={!owner ? 'Only an owner of the vault can rename it.' : undefined}
                after={
                  owner && (
                    <button class="btn" type="submit" disabled={busy || !write || !name.trim() || name.trim() === v.name}>
                      Rename
                    </button>
                  )
                }
              />
            </form>
            <dl class="facts">
              <dt>Your access</dt>
              <dd>
                <strong>{ROLE_LABEL[v.role]}</strong>
                <span class="muted"> — {ROLE_HELP[v.role]}</span>
              </dd>
              <dt>Entries</dt>
              <dd>{v.items.length}</dd>
              <dt>Key version</dt>
              <dd>
                {v.keyEpoch} <span class="muted">(goes up by one each time the vault's key is replaced)</span>
              </dd>
            </dl>
            {v.personal ? (
              <p class="muted">This is your personal vault. Only you can see it, and it cannot be shared or deleted.</p>
            ) : (
              open && (
                <section class="danger-zone">
                  <h3>{owner ? 'Delete this vault' : 'Leave this vault'}</h3>
                  <p class="hint">{owner ? 'Deletes the vault and every entry in it for all members.' : 'You lose access to everything in it. An owner can add you again.'}</p>
                  <button type="button" class="btn danger" disabled={!write} onClick={() => setConfirm({ kind: owner ? 'delete' : 'leave' })}>
                    <Icon name={owner ? 'trash' : 'logout'} />
                    {owner ? 'Delete this vault…' : 'Leave this vault…'}
                  </button>
                </section>
              )
            )}
          </div>
        )}

        {tab === 'members' && (
          <div class="stack">
            {v.rosterStatus === 'unreadable' && open && (
              <Banner kind="warn" action={owner ? <button type="button" class="btn small" disabled={!write} onClick={() => setRekey({ repair: true })}>Repair…</button> : undefined}>
                This vault's own member list could not be read, so the list below comes from the server and is not checked.{' '}
                {owner ? 'You can rebuild it; everyone in it must be someone whose fingerprint you have compared.' : 'An owner can repair it.'}
              </Banner>
            )}
            {v.rekeyRecommended && owner && v.rosterStatus === 'ok' && (
              <Banner kind="warn" action={<button type="button" class="btn small" disabled={busy || !write} onClick={() => setRekey({})}>Replace the key…</button>}>
                Someone left or was cut off. Until an owner replaces the vault's key, they still have the current one. Replacing it gives a new key to the people in the member list below.
              </Banner>
            )}
            <ul class="members">
              {v.members.map((m) => (
                <PersonRow
                  name={m.username}
                  tags={
                    <>
                      <TrustTags isSelf={m.isSelf} verified={m.verified} blocked={m.blocked} disabled={m.disabled} />
                      {m.discrepancy && <span class="tag warn">{DISCREPANCY[m.discrepancy]}</span>}
                    </>
                  }
                  fingerprint={m.fingerprint}
                  actions={
                    owner && !v.personal && !m.isSelf && v.rosterStatus === 'ok' && m.discrepancy !== 'unlisted' ? (
                      m.discrepancy !== 'left' && (
                        <div class="member-actions">
                          <label class="sr-only" for={`role-${m.userId}`}>
                            Access for {m.username}
                          </label>
                          <RoleSelect
                            id={`role-${m.userId}`}
                            value={m.role}
                            disabled={busy || !write}
                            onChange={(r) => void run(async () => {
                              await session.setMemberRole(v.id, m.userId, r);
                              toast(`${m.username}: ${ROLE_LABEL[r]}`);
                            })}
                          />
                          <button type="button" class="btn danger small" disabled={busy || !write} onClick={() => setRekey({ remove: [m.userId] })}>
                            Remove…
                          </button>
                        </div>
                      )
                    ) : (
                      <span class="role-label">{ROLE_LABEL[m.role]}</span>
                    )
                  }
                />
              ))}
            </ul>

            {v.personal && <p class="muted">Your personal vault is only for you. To share passwords, create a new vault and share that.</p>}
            {!owner && !v.personal && <p class="muted">Only an owner of this vault can add or remove people.</p>}
            {owner && !v.personal && v.rosterStatus === 'ok' && (
              <section class="add-member">
                <h3>Share this vault with someone</h3>
                {!found ? (
                  <form
                    class="stack"
                    onSubmit={(e) => {
                      e.preventDefault();
                      lookup(who);
                    }}
                  >
                    {candidates.length > 0 && (
                      <div>
                        <p class="field-label">People in your household who are not in this vault yet:</p>
                        <div class="chips">
                          {candidates.map((c) => (
                            <button type="button" class="chip" disabled={!write} onClick={() => lookup(c.username)}>
                              <Avatar name={c.username} />
                              {c.username}
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                    <TextField
                      label="Username"
                      value={who}
                      onInput={setWho}
                      required
                      hint={candidates.length ? 'Or type their username.' : 'They need an account first: an administrator can invite them.'}
                      after={
                        <button type="submit" class="btn" disabled={!who.trim() || !write}>
                          Look up
                        </button>
                      }
                    />
                  </form>
                ) : (
                  <div class="stack">
                    <p>
                      Sharing gives <strong>{found.username}</strong> a copy of this vault's key that only {found.username}'s own key can open. First make sure it is really {found.username}'s key.
                    </p>
                    {found.verified ? (
                      <>
                        <FingerprintBox label={`${found.username}'s fingerprint`} value={found.fingerprint} />
                        <p class="ok-text">
                          <Icon name="check" /> You already compared this fingerprint with {found.username} on this device.
                        </p>
                      </>
                    ) : (
                      <Compare name={found.username} fingerprint={found.fingerprint} checked={compared} onChange={setCompared} />
                    )}
                    <div class="field">
                      <label for="role-new">What can {found.username} do?</label>
                      <RoleSelect id="role-new" value={role} onChange={setRole} />
                      <p class="hint">{ROLE_HELP[role]}</p>
                    </div>
                    <div class="btn-row">
                      <button type="button" class="btn" onClick={() => setFound(null)}>
                        Cancel
                      </button>
                      <button
                        type="button"
                        class="btn primary"
                        disabled={busy || !write || (!found.verified && !compared)}
                        onClick={() =>
                          void run(async () => {
                            const f = found;
                            if (!f.verified && compared) await session.markVerified(f.userId);
                            await session.addMember(v.id, f.username, role);
                            toast(`Shared with ${f.username}`);
                            setFound(null);
                            setWho('');
                          })
                        }
                      >
                        <Icon name="share" />
                        Share with {found.username}
                      </button>
                    </div>
                    {!found.verified && !compared && <p class="hint">Sharing unlocks once you have compared the fingerprint and ticked the box above.</p>}
                  </div>
                )}
              </section>
            )}
          </div>
        )}
      </Tabs>

      {busy && <Spinner label="Saving…" />}

      {rekey && <RekeyDialog vaultId={v.id} remove={rekey.remove} repair={rekey.repair} onClose={() => setRekey(null)} />}
      {confirm?.kind === 'delete' && (
        <ConfirmDialog title="Delete this vault?" confirmLabel="Delete vault" danger onCancel={() => setConfirm(null)} onConfirm={async () => { setConfirm(null); await run(async () => { await session.deleteVault(v.id); toast('Vault deleted'); p.onClose(); }); }}>
          <p>
            “{v.name}” and everything in it ({plural(v.items.length, 'entry', 'entries')}) will be deleted for every member. This cannot be undone. Consider downloading a backup first (Account and backup).
          </p>
        </ConfirmDialog>
      )}
      {confirm?.kind === 'leave' && (
        <ConfirmDialog title="Leave this vault?" confirmLabel="Leave" danger onCancel={() => setConfirm(null)} onConfirm={async () => { setConfirm(null); await run(async () => { await session.leaveVault(v.id); toast('You left the vault'); p.onClose(); }); }}>
          <p>You will lose access to “{v.name}”. An owner can add you again.</p>
        </ConfirmDialog>
      )}
    </Modal>
  );
}

const FIELD_LABELS: [keyof Item, string][] = [
  ['name', 'Name'], ['username', 'Username'], ['password', 'Password'], ['urls', 'Websites'], ['notes', 'Notes'], ['totp', 'One-time code key'],
  ['fields', 'Custom fields'], ['tags', 'Tags'],
];
const SECRET_FIELDS = new Set<keyof Item>(['password', 'totp', 'fields', 'notes']);

function show(it: Item | null | undefined, k: keyof Item, reveal: boolean): string {
  if (!it) return '(deleted)';
  const v = it[k];
  if (SECRET_FIELDS.has(k) && !reveal) return v && (!Array.isArray(v) || v.length) ? '••••••••' : '';
  if (Array.isArray(v)) return v.length ? JSON.stringify(v) : '';
  return String(v ?? '');
}

/** Shown when a save hit a 409: never silently overwrites; the user compares and decides. */
export function ConflictDialog(p: { err: ConflictError; onClose: () => void; onEditAgain: () => void }) {
  const { session, toast } = useApp();
  const [reveal, setReveal] = useState(false);
  const { busy, error, run } = useAction();
  const { mine, theirs, kind } = p.err;
  const theirItem = theirs?.item ?? null;
  const changed = FIELD_LABELS.filter(([k]) => (mine ? JSON.stringify(mine[k]) : '') !== (theirItem ? JSON.stringify(theirItem[k]) : ''));
  const identical = mine && theirItem && itemToJson(mine) === itemToJson(theirItem);

  const resolve = (choice: 'overwrite' | 'discard') =>
    run(
      async () => {
        await session.resolveConflict(p.err, choice);
        toast(choice === 'overwrite' ? 'Your version was saved' : 'Kept the version on the server');
        p.onClose();
      },
      (e) => (e instanceof ConflictError ? 'It changed again while you were deciding. Close this and compare once more.' : errMsg(e)),
    );

  return (
    <Modal
      title="This entry was changed elsewhere"
      onClose={p.onClose}
      wide
      dismissable={false}
      footer={
        <>
          <button type="button" class="btn" disabled={busy} onClick={() => void resolve('discard')}>
            {kind === 'delete' ? 'Keep the entry' : 'Keep the saved version'}
          </button>
          {kind !== 'delete' && theirs && (
            <button type="button" class="btn" disabled={busy} onClick={p.onEditAgain}>
              Edit the saved version
            </button>
          )}
          <button type="button" class="btn danger solid" disabled={busy || !session.canWrite} onClick={() => void resolve('overwrite')}>
            {kind === 'delete' ? 'Delete anyway' : theirs ? 'Overwrite with mine' : 'Re-create mine'}
          </button>
        </>
      }
    >
      <p>
        {kind === 'delete'
          ? 'You tried to delete this entry, but someone (or another of your devices) changed it in the meantime.'
          : theirs
            ? 'Someone else saved a different version while you were editing. Nothing has been overwritten. Choose which version to keep.'
            : 'The entry you were editing was deleted while you were working on it.'}
      </p>
      {kind !== 'delete' && changed.length > 0 && !identical && (
        <div class="table-wrap">
          <table class="diff">
            <caption class="sr-only">Differences between your version and the saved one</caption>
            <thead>
              <tr>
                <th>Field</th>
                <th>Your version</th>
                <th>Saved version</th>
              </tr>
            </thead>
            <tbody>
              {changed.map(([k, label]) => (
                <tr>
                  <th scope="row">{label}</th>
                  <td class="pre">{show(mine, k, reveal)}</td>
                  <td class="pre">{show(theirItem, k, reveal)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <button type="button" class="btn small" aria-pressed={reveal} onClick={() => setReveal(!reveal)}>
            <Icon name={reveal ? 'eyeOff' : 'eye'} />
            Show secret values
          </button>
        </div>
      )}
      {!session.canWrite && <p class="hint">{writeBlock(session)}</p>}
      {error && <Banner kind="error">{error}</Banner>}
    </Modal>
  );
}
