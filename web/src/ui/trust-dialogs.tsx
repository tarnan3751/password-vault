import type { ComponentChildren } from 'preact';
import { useState } from 'preact/hooks';
import { type Progress as Prog, type RekeyPlan } from '../vault/index.ts';
import { useApp, useSessionTick } from './ctx.ts';
import { errMsg } from './errors.ts';
import { Banner, Check, FingerprintBox, Icon, Modal, PersonRow, Progress, Spinner, useAction } from './kit.tsx';
import { writeBlock } from './status.tsx';

/**
 * The out-of-band fingerprint comparison (crypto.md §6.5), explained for family
 * members. The caller gates its action on `checked`.
 */
export function Compare(p: { name: string; fingerprint: string; checked: boolean; onChange: (v: boolean) => void; compact?: boolean }) {
  return (
    <div class="compare">
      {!p.compact && (
        <p>
          A <strong>fingerprint</strong> is a short code that identifies a person's key. If the code below is the same one {p.name} sees on their own device, nobody (not even a server)
          has swapped {p.name}'s key for their own.
        </p>
      )}
      <ol class="steps">
        <li>
          Talk to {p.name} <strong>in person or on a phone call</strong>, not through this app.
        </li>
        <li>
          Ask them to open the menu under their name, choose <strong>Account and backup</strong> and read out their fingerprint (on the command line: <code>fvault fingerprint</code>).
        </li>
        <li>Check that all eight groups match this:</li>
      </ol>
      <FingerprintBox label={`${p.name}'s fingerprint`} value={p.fingerprint} />
      <Banner kind="warn">
        <strong>If even one character is different, stop.</strong> Do not continue: someone may be trying to intercept your passwords. Tell your administrator.
      </Banner>
      <Check strong checked={p.checked} onChange={p.onChange} label={`I compared it and it matches what ${p.name} sees`} />
    </div>
  );
}

/** A vault someone shared with this device whose key is not accepted yet (crypto.md §6.4). Nothing in it has been decrypted. */
export function PendingShareDialog(p: { vaultId: string; onClose: (accepted?: boolean) => void }) {
  const { session, toast } = useApp();
  useSessionTick(session);
  const v = session.vault(p.vaultId);
  const [sure, setSure] = useState(false);
  const { busy, error, run } = useAction();
  if (!v?.pending) return null;
  const { senderName: who, senderFingerprint, replacedByNonOwner } = v.pending;
  return (
    <Modal
      title={`${who} shared a vault with you`}
      onClose={() => p.onClose()}
      footer={
        <>
          {busy && <Spinner label="Opening…" />}
          <button type="button" class="btn" onClick={() => p.onClose()}>
            Not now
          </button>
          <button
            type="button"
            class="btn primary"
            disabled={!sure || busy}
            aria-describedby={sure ? undefined : 'accept-why'}
            onClick={() => void run(async () => {
              await session.acceptPending(p.vaultId);
              toast('Vault opened');
              p.onClose(true);
            })}
          >
            Verify {who} and open the vault
          </button>
        </>
      }
    >
      <div class="stack">
        {replacedByNonOwner ? (
          <Banner kind="error">
            <strong>The key of a vault you already have was replaced by {who}</strong>, who was not an owner of it when this device last saw it. This can be legitimate (an owner asked them to
            replace the key) or a server trying to take over the vault. Check with {who}, and with the vault's owners, before accepting.
          </Banner>
        ) : (
          <p>
            Before it opens, confirm that it really came from <strong>{who}</strong>. Until then nothing in it is decrypted, so nobody can slip you a fake vault in {who}'s name.
          </p>
        )}
        <Compare name={who} fingerprint={senderFingerprint} checked={sure} onChange={setSure} />
        {!sure && (
          <p class="hint" id="accept-why">
            The button below unlocks once you have compared the fingerprint and ticked the box.
          </p>
        )}
        {error && <Banner kind="error">{error}</Banner>}
      </div>
    </Modal>
  );
}

/** Inline "compare, then mark verified" used by the people list and the key-replacement dialog. */
function VerifyInline(p: { userId: string; name: string; fingerprint: string; onDone: () => void; onError: (m: string) => void; onCancel: () => void }) {
  const { session } = useApp();
  const [sure, setSure] = useState(false);
  return (
    <div class="verify-inline">
      <Compare compact name={p.name} fingerprint={p.fingerprint} checked={sure} onChange={setSure} />
      <div class="btn-row">
        <button type="button" class="btn small" onClick={p.onCancel}>
          Cancel
        </button>
        <button
          type="button"
          class="btn small primary"
          disabled={!sure}
          onClick={async () => {
            try {
              await session.markVerified(p.userId);
              p.onDone();
            } catch (e) {
              p.onError(errMsg(e));
            }
          }}
        >
          Mark {p.name} as verified
        </button>
      </div>
    </div>
  );
}

/** A person row with a "Verify…" button that opens the inline fingerprint comparison (one row at a time: `confirming` is the open user id). */
function VerifiableRow(p: { userId: string; name: string; fingerprint: string; tags: ComponentChildren; canVerify: boolean; confirming: string | null; setConfirming: (id: string | null) => void; onError: (m: string) => void; onVerified: () => void }) {
  const open = p.confirming === p.userId;
  return (
    <PersonRow
      name={p.name}
      tags={p.tags}
      fingerprint={p.fingerprint}
      actions={
        p.canVerify &&
        !open && (
          <button type="button" class="btn small" onClick={() => p.setConfirming(p.userId)}>
            <Icon name="shield" />
            Verify…
          </button>
        )
      }
    >
      {open && <VerifyInline userId={p.userId} name={p.name} fingerprint={p.fingerprint} onCancel={() => p.setConfirming(null)} onError={p.onError} onDone={() => { p.setConfirming(null); p.onVerified(); }} />}
    </PersonRow>
  );
}

/** Tags shared by member/contact rows; text, not colour alone. */
export function TrustTags(p: { isSelf: boolean; verified: boolean; blocked: boolean; disabled: boolean; strict?: boolean }) {
  return (
    <>
      {p.isSelf && <span class="tag">you</span>}
      {p.disabled && <span class="tag warn">disabled</span>}
      {p.blocked && (
        <span class="tag danger">
          <Icon name="alert" />
          key changed
        </span>
      )}
      {!p.isSelf && !p.blocked && (
        <span class={p.verified ? 'tag ok' : p.strict ? 'tag danger' : 'tag'}>
          <Icon name={p.verified ? 'check' : 'dot'} />
          {p.verified ? 'verified' : 'not verified'}
        </span>
      )}
    </>
  );
}

/** Every household member with fingerprint and verification state; the place to verify someone without sharing anything. */
export function ContactsDialog(p: { onClose: () => void }) {
  const { session, toast } = useApp();
  useSessionTick(session);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [error, setError] = useState('');
  return (
    <Modal title="People and fingerprints" onClose={p.onClose} wide>
      <div class="stack">
        <p class="muted">
          A <strong>fingerprint</strong> is a short code that identifies a person's key. Compare it once with each person, in person or on a phone call, and this device trusts their key from
          then on.
        </p>
        {error && <Banner kind="error">{error}</Banner>}
        {session.contacts().length < 2 && <p>Nobody else has an account yet.{session.isAdmin && ' Invite people from Administration.'}</p>}
        <ul class="members">
          {session.contacts().map((c) => (
            <VerifiableRow
              userId={c.userId}
              name={c.username}
              fingerprint={c.fingerprint}
              tags={
                <>
                  {c.isAdmin && <span class="tag">admin</span>}
                  <TrustTags isSelf={c.isSelf} verified={c.verified} blocked={c.blocked} disabled={c.disabled} />
                </>
              }
              canVerify={!c.isSelf && !c.verified && !c.blocked}
              confirming={confirming}
              setConfirming={setConfirming}
              onError={setError}
              onVerified={() => toast(`${c.username} is now verified on this device`)}
            />
          ))}
        </ul>
      </div>
    </Modal>
  );
}

const list = (l: { username: string }[]) => l.map((r) => r.username).join(', ');

/**
 * Shows exactly who will receive the new vault key BEFORE anything is sent
 * (crypto.md §6.6), makes the person verify every unverified recipient, then
 * runs the atomic key replacement with progress.
 */
export function RekeyDialog(p: { vaultId: string; remove?: string[]; repair?: boolean; onClose: (done?: boolean) => void }) {
  const { session, toast } = useApp();
  useSessionTick(session);
  const initial = () => {
    try {
      return { plan: session.planRekey(p.vaultId, { remove: p.remove, repair: p.repair }), error: '' };
    } catch (e) {
      return { plan: null as RekeyPlan | null, error: errMsg(e) };
    }
  };
  const [state, setState] = useState(initial);
  const [confirming, setConfirming] = useState<string | null>(null);
  const { busy, error, setError, run } = useAction();
  const [prog, setProg] = useState<Prog | null>(null);
  const plan = state.plan;
  const replan = () => setState(initial());
  const removing = !!p.remove?.length;

  const title = p.repair ? 'Repair the member list' : removing ? `Remove ${plan ? list(plan.removed) : 'member'}` : "Replace the vault's key";
  return (
    <Modal
      title={title}
      onClose={() => !busy && p.onClose()}
      wide
      dismissable={!busy}
      footer={
        <>
          {busy && !prog && <Spinner label="Working…" />}
          <button type="button" class="btn" disabled={busy} onClick={() => p.onClose()}>
            Cancel
          </button>
          <button
            type="button"
            class={removing ? 'btn danger solid' : 'btn primary'}
            disabled={busy || !plan || plan.unverified.length > 0 || !session.canWrite}
            onClick={async () => {
              if (!plan) return;
              const ok = await run(async () => {
                await session.executeRekey(plan, setProg);
                toast(removing ? "Member removed and the vault's key replaced" : "The vault's key was replaced");
                p.onClose(true);
              });
              setProg(null);
              if (!ok) replan();
            }}
          >
            {p.repair ? 'Repair and replace the key' : removing ? 'Remove and replace the key' : 'Replace the key now'}
          </button>
        </>
      }
    >
      <div class="stack">
        {state.error && <Banner kind="error">{state.error}</Banner>}
        {plan && (
          <>
            <p>
              {p.repair
                ? "This vault's member list could not be read. It will be rebuilt from the server's list."
                : removing
                  ? `${list(plan.removed)} will lose access straight away.`
                  : 'Use this after someone has left, so their old copy of the key cannot open anything saved from now on.'}{' '}
              The vault gets a new key (version {plan.epoch}) and everything in it is re-encrypted in one step. The new key is given to <strong>exactly these people</strong>:
            </p>
            <ul class="members">
              {plan.recipients.map((r) => (
                <VerifiableRow
                  userId={r.userId}
                  name={r.username}
                  fingerprint={r.fingerprint}
                  tags={
                    <>
                      <TrustTags isSelf={r.isSelf} verified={r.verified} blocked={false} disabled={false} strict />
                      <span class="muted">{ROLE_LABEL[r.role]}</span>
                    </>
                  }
                  canVerify={!r.isSelf && !r.verified}
                  confirming={confirming}
                  setConfirming={setConfirming}
                  onError={setError}
                  onVerified={replan}
                />
              ))}
            </ul>
            {plan.removed.length > 0 && <p class="muted">{list(plan.removed)} will still know whatever they have already seen: change the passwords that matter.</p>}
            {plan.unverified.length > 0 && (
              <Banner kind="warn">
                Everyone who gets the new key must be someone whose fingerprint you have compared on this device, so nobody can quietly add a stranger. Compare fingerprints with the people
                marked “not verified” to continue.
              </Banner>
            )}
          </>
        )}
        {!session.canWrite && <p class="hint">{writeBlock(session)}</p>}
        {error && <Banner kind="error">{error}</Banner>}
        {prog && <Progress done={prog.done} total={prog.total} label={prog.phase} />}
      </div>
    </Modal>
  );
}

export const ROLE_LABEL: Record<string, string> = { owner: 'Owner', editor: 'Can edit', viewer: 'Can view' };
