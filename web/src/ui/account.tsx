import { useState } from 'preact/hooks';
import type { BackupPayload } from '../crypto/index.ts';
import { checkMasterPassword, strengthLabel } from '../crypto/index.ts';
import type { Progress as Prog } from '../vault/index.ts';
import { useApp, useSessionTick } from './ctx.ts';
import { Avatar, Banner, FingerprintBox, Icon, Modal, PasswordRules, plural, Progress, Seg, Spinner, StrengthMeter, Tabs, TextField, useAction } from './kit.tsx';
import { writeBlock } from './status.tsx';
import { ConfirmDialog } from './vault-dialogs.tsx';

type Tab = 'you' | 'password' | 'backup' | 'settings';

function download(filename: string, text: string) {
  // Blob URLs are same-origin and allowed by CSP (no data: navigation, no inline script).
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

const mismatch = (a: string, b: string) => (b !== '' && a !== b && b.length >= a.length ? 'The two do not match.' : undefined);

export function AccountDialog(p: { onClose: () => void; initialTab?: Tab }) {
  const { session, toast, signOut, autoLockMinutes, setAutoLockMinutes } = useApp();
  useSessionTick(session);
  const [tab, setTab] = useState<Tab>(p.initialTab ?? 'you');
  return (
    <Modal title="Account and backup" onClose={p.onClose} wide>
      <Tabs
        label="Account"
        tabs={[
          ['you', 'You'],
          ['password', 'Password'],
          ['backup', 'Backup'],
          ['settings', 'Settings'],
        ]}
        current={tab}
        onChange={setTab}
      >
        {tab === 'you' && (
          <div class="stack">
            <div class="profile">
              <Avatar name={session.username} big />
              <div>
                <strong>{session.username}</strong>
                <div class="muted">{session.isAdmin ? 'Administrator' : 'Member'}</div>
              </div>
            </div>
            <section class="stack">
              <h3>Your fingerprint</h3>
              <p class="hint">
                A short code that identifies your key. When you share a vault with someone, read it out to each other in person or on a phone call. If it matches what they see, nobody has
                swapped your key.
              </p>
              <FingerprintBox label="Your fingerprint" value={session.fingerprint} />
            </section>
            <SignOutEverywhere onDone={() => { toast('Signed out everywhere'); signOut(); }} />
          </div>
        )}
        {tab === 'password' && <ChangePassword onDone={() => toast('Master password changed')} />}
        {tab === 'backup' && <BackupPane />}
        {tab === 'settings' && (
          <div class="field">
            <label for="autolock">Lock automatically after</label>
            <select id="autolock" value={String(autoLockMinutes)} onChange={(e) => setAutoLockMinutes(Number(e.currentTarget.value))}>
              {[1, 2, 5, 10, 15, 30, 60, 120].map((m) => (
                <option value={String(m)}>{plural(m, 'minute')} without use</option>
              ))}
            </select>
            <p class="hint">Locking removes every key from memory until you enter your master password again. Saved on this device only.</p>
          </div>
        )}
      </Tabs>
    </Modal>
  );
}

function SignOutEverywhere(p: { onDone: () => void }) {
  const { session } = useApp();
  const { busy, error, run } = useAction();
  const [sure, setSure] = useState(false);
  const block = writeBlock(session);
  return (
    <section class="stack">
      <h3>Lost a device?</h3>
      <p class="hint">Sign out everywhere ends your sessions on all devices, including this one. A lost device then needs your master password again.</p>
      {error && <Banner kind="error">{error}</Banner>}
      <div>
        <button type="button" class="btn danger" disabled={busy || !!block} onClick={() => setSure(true)}>
          <Icon name="logout" />
          Sign out everywhere…
        </button>
      </div>
      {block && <p class="hint">{block}</p>}
      {sure && (
        <ConfirmDialog
          title="Sign out everywhere?"
          confirmLabel="Sign out everywhere"
          danger
          onCancel={() => setSure(false)}
          onConfirm={async () => {
            if (await run(() => session.revokeSessions())) p.onDone();
            else setSure(false);
          }}
        >
          <p>Every device signed in to your account, including this one, is signed out straight away.</p>
        </ConfirmDialog>
      )}
    </section>
  );
}

function ChangePassword(p: { onDone: () => void }) {
  const { session } = useApp();
  const [cur, setCur] = useState('');
  const [next, setNext] = useState('');
  const [conf, setConf] = useState('');
  const { busy, error, run } = useAction();
  const block = writeBlock(session);
  const missing = block
    ? ''
    : !cur
      ? 'enter your current master password'
      : checkMasterPassword(next, session.username) !== null
        ? 'choose a new master password that meets the rules'
        : next !== conf
          ? 'type the new master password again to confirm it'
          : '';
  const ok = !block && !missing && !busy;
  return (
    <form
      class="stack"
      onSubmit={(e) => {
        e.preventDefault();
        if (!ok) return;
        void run(async () => {
          await session.changePassword(cur, next);
          setCur(''); setNext(''); setConf('');
          p.onDone();
        });
      }}
    >
      {block && <Banner kind="warn">{block} Changing your master password needs a connection.</Banner>}
      <Banner kind="warn">
        <strong>Nobody can reset a forgotten master password.</strong> If you forget the new one, your personal vault cannot be opened by anyone. Your other devices will be signed out.
      </Banner>
      <TextField label="Current master password" type="password" value={cur} onInput={setCur} autocomplete="current-password" required />
      <TextField label="New master password" type="password" value={next} onInput={setNext} autocomplete="new-password" required describedBy="new-pw-rules" />
      <PasswordRules id="new-pw-rules" password={next} username={session.username} />
      <TextField label="Confirm new master password" type="password" value={conf} onInput={setConf} autocomplete="new-password" required error={mismatch(next, conf)} />
      {error && <Banner kind="error">{error}</Banner>}
      {busy && <Spinner label="Changing your master password. This takes a few seconds on purpose…" />}
      <div>
        <button type="submit" class="btn primary" disabled={!ok} aria-describedby={missing ? 'cpw-why' : undefined}>
          Change master password
        </button>
        {missing && !busy && (
          <p class="hint" id="cpw-why">
            To continue, {missing}.
          </p>
        )}
      </div>
    </form>
  );
}

function BackupPane() {
  const { session, toast } = useApp();
  // export
  const [useMaster, setUseMaster] = useState(false);
  const [pass, setPass] = useState('');
  const [pass2, setPass2] = useState('');
  const exp = useAction();
  // import
  const [file, setFile] = useState<{ name: string; text: string } | null>(null);
  const [ipass, setIpass] = useState('');
  const [preview, setPreview] = useState<BackupPayload | null>(null);
  const imp = useAction();
  const [prog, setProg] = useState<Prog | null>(null);
  const [result, setResult] = useState('');
  const block = writeBlock(session);
  const weak = !useMaster && strengthLabel(pass).label === 'too weak';
  const missingE = !pass ? `enter ${useMaster ? 'your master password' : 'a passphrase'}` : weak ? 'choose a stronger passphrase' : pass !== pass2 ? 'type it again to confirm' : '';

  return (
    <div class="stack">
      <section class="stack">
        <h3>Download an encrypted backup</h3>
        <p class="hint">One file with every vault you can open, encrypted with a passphrase. Keep it somewhere safe, such as a USB stick at home. Works offline too.</p>
        <Seg label="Protect the backup with" options={[['own', 'A separate passphrase'], ['master', 'My master password']]} value={useMaster ? 'master' : 'own'} onChange={(v) => setUseMaster(v === 'master')} />
        {!useMaster && <p class="hint">Recommended: the backup stays safe even if your master password is ever exposed.</p>}
        <TextField label={useMaster ? 'Master password' : 'Backup passphrase'} type="password" value={pass} onInput={setPass} autocomplete="off" />
        {!useMaster && <StrengthMeter password={pass} />}
        <TextField label="Type it again" type="password" value={pass2} onInput={setPass2} autocomplete="off" error={mismatch(pass, pass2)} />
        <Banner kind="warn">
          If you lose this passphrase, nobody can open the backup. The file holds all your passwords: keep it as carefully as the vault itself.
        </Banner>
        {exp.error && <Banner kind="error">{exp.error}</Banner>}
        {exp.busy && <Spinner label="Encrypting…" />}
        <div>
          <button
            type="button"
            class="btn primary"
            disabled={exp.busy || !!missingE}
            aria-describedby={missingE ? 'exp-why' : undefined}
            onClick={() => void exp.run(async () => {
              const r = await session.exportBackup(pass);
              download(r.filename, r.text);
              toast(`Backup downloaded: ${plural(r.items, 'entry', 'entries')} from ${plural(r.vaults, 'vault')}${r.skipped ? ` (${r.skipped} could not be read and were left out)` : ''}`);
              setPass(''); setPass2('');
            })}
          >
            <Icon name="download" />
            Download backup
          </button>
          {missingE && (
            <p class="hint" id="exp-why">
              To continue, {missingE}.
            </p>
          )}
        </div>
      </section>

      <hr />

      <section class="stack">
        <h3>Restore from a backup</h3>
        <p class="hint">
          Restoring adds <em>new</em> vaults named “… (restored)”. Nothing you already have is changed or merged.
        </p>
        <div class="field">
          <label for="bk-file">Backup file</label>
          <input id="bk-file" type="file" accept=".json,application/json" onChange={async (e) => {
            const f = e.currentTarget.files?.[0];
            setPreview(null); setResult(''); imp.setError('');
            if (!f) return setFile(null);
            if (f.size > 64 * 1024 * 1024) { setFile(null); return imp.setError('That file is too large to be a backup.'); }
            setFile({ name: f.name, text: await f.text() });
          }} />
        </div>
        {file && !preview && (
          <TextField
            label="Passphrase of this backup"
            type="password"
            value={ipass}
            onInput={setIpass}
            autocomplete="off"
            after={
              <button
                type="button"
                class="btn"
                disabled={imp.busy || !ipass}
                onClick={() => void imp.run(async () => {
                  setPreview(await session.inspectBackup(file.text, ipass));
                  setIpass('');
                })}
              >
                Open and preview
              </button>
            }
          />
        )}
        {preview && (
          <>
            <Banner kind="ok">
              Backup made by <strong>{preview.exported_by}</strong> on {new Date(preview.exported_at).toLocaleString()}: {plural(preview.vaults.length, 'vault')},{' '}
              {plural(preview.vaults.reduce((n, v) => n + v.items.length, 0), 'entry', 'entries')}.
              <ul>{preview.vaults.map((v) => <li>{v.name}: {plural(v.items.length, 'entry', 'entries')}</li>)}</ul>
            </Banner>
            {prog && <Progress done={prog.done} total={prog.total} label={prog.phase} />}
            <div>
              <button
                type="button"
                class="btn primary"
                disabled={imp.busy || !!block}
                onClick={async () => {
                  await imp.run(async () => {
                    const r = await session.importBackup(preview, setProg);
                    setResult(`Restored ${plural(r.items, 'entry', 'entries')} into ${plural(r.vaults, 'new vault')}${r.failed ? `; ${r.failed} could not be saved` : ''}.`);
                    setPreview(null); setFile(null);
                  });
                  setProg(null);
                }}
              >
                Restore into new vaults
              </button>
              {block && <p class="hint">{block}</p>}
            </div>
          </>
        )}
        {imp.busy && !prog && <Spinner label="Working…" />}
        {imp.error && <Banner kind="error">{imp.error}</Banner>}
        {result && <Banner kind="ok">{result}</Banner>}
      </section>
    </div>
  );
}
