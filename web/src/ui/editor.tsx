import { useState } from 'preact/hooks';
import { cloneItem, newItem, type CustomField, type Item, type ItemType } from '../crypto/index.ts';
import { ConflictError } from '../vault/index.ts';
import { useApp } from './ctx.ts';
import { Generator } from './generator.tsx';
import { Banner, Icon, Modal, NO_AUTOFIX, Seg, Spinner, TextArea, TextField, useAction } from './kit.tsx';
import { writeBlock } from './status.tsx';
import { ConfirmDialog } from './vault-dialogs.tsx';

export interface EditorTarget {
  vaultId: string;
  itemId?: string;
  type?: ItemType;
}

export function EntryEditor(p: { target: EditorTarget; onClose: (savedId?: string) => void; onConflict: (e: ConflictError) => void }) {
  const { session, toast } = useApp();
  // Snapshot at open time: this is the version the user is editing (used to detect concurrent changes).
  const [existing] = useState(() => (p.target.itemId ? session.vault(p.target.vaultId)?.items.find((i) => i.id === p.target.itemId) : undefined));
  const [vaultId, setVaultId] = useState(p.target.vaultId);
  const [start] = useState<Item>(() => {
    if (existing?.item) return cloneItem(existing.item);
    const it = newItem(p.target.type ?? 'login', Date.now());
    it.urls = ['']; // one empty website box to fill in; empty ones are dropped on save
    return it;
  });
  const [it, setIt] = useState<Item>(() => cloneItem(start));
  const [tags, setTags] = useState(it.tags.join(', '));
  const [gen, setGen] = useState(false);
  const { busy, error, run } = useAction();
  const [discard, setDiscard] = useState(false);
  const isNew = !p.target.itemId;
  const writable = session.vaults.filter((v) => v.state === 'open' && (v.role === 'owner' || v.role === 'editor'));
  const block = writeBlock(session);
  const more = !!(it.totp || it.fields.length || it.tags.length);

  const set = (patch: Partial<Item>) => setIt({ ...it, ...patch });
  const setField = (i: number, patch: Partial<CustomField>) => set({ fields: it.fields.map((f, k) => (k === i ? { ...f, ...patch } : f)) });
  const setUrl = (i: number, v: string) => set({ urls: it.urls.map((u, k) => (k === i ? v : u)) });
  const dirty = JSON.stringify(it) !== JSON.stringify(start) || tags !== start.tags.join(', ');
  const close = () => (dirty ? setDiscard(true) : p.onClose());

  function save(e: Event) {
    e.preventDefault();
    if (!session.canWrite) return;
    const draft: Item = {
      ...it,
      name: it.name.trim() || (it.type === 'note' ? 'Untitled note' : 'Untitled login'),
      urls: it.urls.map((u) => u.trim()).filter(Boolean),
      tags: tags.split(',').map((t) => t.trim()).filter(Boolean),
      fields: it.fields.filter((f) => f.name.trim() !== '' || f.value !== '').map((f) => (f.hidden ? { name: f.name, value: f.value, hidden: true } : { name: f.name, value: f.value })),
    };
    void run(async () => {
      try {
        let id = p.target.itemId;
        if (isNew) id = await session.createItem(vaultId, draft);
        else await session.updateItem(vaultId, id!, (x) => Object.assign(x, { ...draft, password_history: x.password_history, created_at: x.created_at, extra: x.extra }), { base: existing });
        toast('Saved');
        p.onClose(id);
      } catch (err) {
        if (!(err instanceof ConflictError)) throw err;
        p.onConflict(err);
        p.onClose();
      }
    });
  }

  return (
    <Modal
      title={isNew ? (it.type === 'note' ? 'New secure note' : 'New login') : `Edit “${start.name}”`}
      onClose={close}
      wide
      footer={
        <>
          {busy && <Spinner label="Saving…" />}
          <button type="button" class="btn" onClick={close}>
            Cancel
          </button>
          <button type="submit" form="editor" class="btn primary" disabled={busy || !!block}>
            <Icon name="check" />
            Save
          </button>
        </>
      }
    >
      <form id="editor" onSubmit={save} class="editor">
        {block && <Banner kind="warn">{block} Nothing you type here can be saved until then.</Banner>}
        {isNew && writable.length > 1 && (
          <div class="field">
            <label for="ed-vault">Save in vault</label>
            <select id="ed-vault" value={vaultId} onChange={(e) => setVaultId(e.currentTarget.value)}>
              {writable.map((v) => (
                <option value={v.id}>{v.personal ? `${v.name} (only you)` : v.name}</option>
              ))}
            </select>
          </div>
        )}
        {isNew && <Seg label="Entry type" options={[['login', 'Login'], ['note', 'Secure note']]} value={it.type} onChange={(t) => set({ type: t })} />}
        <TextField label="Name" value={it.name} onInput={(v) => set({ name: v })} required autofocus placeholder={it.type === 'note' ? 'For example: Passport numbers' : 'For example: Example Bank'} />

        {it.type === 'login' && (
          <>
            <TextField label="Username or email" value={it.username} onInput={(v) => set({ username: v })} autocomplete="off" />
            <TextField
              id="ed-pw"
              label="Password"
              type="password"
              mono
              value={it.password}
              onInput={(v) => set({ password: v })}
              after={
                <button type="button" class="btn" aria-expanded={gen} onClick={() => setGen(!gen)}>
                  <Icon name="sparkle" />
                  Generate
                </button>
              }
            />
            {gen && <Generator onUse={(pw) => { set({ password: pw }); setGen(false); }} />}
            <fieldset>
              <legend>Websites</legend>
              {it.urls.map((u, i) => (
                <div class="input-row">
                  <input type="url" {...NO_AUTOFIX} aria-label={`Website ${i + 1}`} value={u} placeholder="example.com" inputMode="url" onInput={(e) => setUrl(i, e.currentTarget.value)} />
                  <button type="button" class="btn icon-only" aria-label={`Remove website ${i + 1}`} onClick={() => set({ urls: it.urls.filter((_, k) => k !== i) })}>
                    <Icon name="trash" />
                  </button>
                </div>
              ))}
              <button type="button" class="btn small" onClick={() => set({ urls: [...it.urls, ''] })}>
                <Icon name="plus" />
                Add website
              </button>
            </fieldset>
          </>
        )}

        <TextArea label="Notes" value={it.notes} onInput={(v) => set({ notes: v })} rows={it.type === 'note' ? 10 : 3} />

        <details class="more" open={more || undefined}>
          <summary>More fields{it.type === 'login' ? ': one-time code key, custom fields, tags' : ': custom fields, tags'}</summary>
          {it.type === 'login' && (
            <TextField
              label="One-time code key (two-step login)"
              value={it.totp}
              onInput={(v) => set({ totp: v })}
              mono
              hint="Optional. The setup key or otpauth:// link a website shows when you turn on two-step login. It is stored safely here; this app does not show the codes yet."
            />
          )}
          <fieldset>
            <legend>Custom fields</legend>
            {it.fields.length === 0 && <p class="hint">Anything else worth keeping, such as a PIN or a security question.</p>}
            {it.fields.map((f, i) => (
              <div class="cf-row">
                <input {...NO_AUTOFIX} aria-label={`Field ${i + 1} name`} placeholder="Name, e.g. PIN" value={f.name} onInput={(e) => setField(i, { name: e.currentTarget.value })} />
                <input {...NO_AUTOFIX} aria-label={`Field ${i + 1} value`} placeholder="Value" type={(f.hidden ? 'password' : 'text') as 'text'} value={f.value} onInput={(e) => setField(i, { value: e.currentTarget.value })} />
                <label class="inline">
                  <input type="checkbox" checked={!!f.hidden} onChange={(e) => setField(i, { hidden: e.currentTarget.checked })} /> Hide
                </label>
                <button type="button" class="btn icon-only" aria-label={`Remove field ${i + 1}`} onClick={() => set({ fields: it.fields.filter((_, k) => k !== i) })}>
                  <Icon name="trash" />
                </button>
              </div>
            ))}
            <button type="button" class="btn small" onClick={() => set({ fields: [...it.fields, { name: '', value: '' }] })}>
              <Icon name="plus" />
              Add field
            </button>
          </fieldset>
          <TextField label="Tags" value={tags} onInput={setTags} hint="Words that help you find this entry, separated by commas." />
        </details>

        {existing?.item && existing.item.password_history.length > 0 && (
          <p class="hint">
            When you change the password, the old one is kept under “Earlier passwords” ({existing.item.password_history.length} so far).
          </p>
        )}
        {error && <Banner kind="error">{error}</Banner>}
      </form>
      {discard && (
        <ConfirmDialog title="Discard your changes?" confirmLabel="Discard changes" danger onCancel={() => setDiscard(false)} onConfirm={() => p.onClose()} cancelLabel="Keep editing">
          <p>What you typed in this entry has not been saved.</p>
        </ConfirmDialog>
      )}
    </Modal>
  );
}
