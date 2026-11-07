import type { Session, VaultView } from '../vault/index.ts';
import { hostOf, Popup, useAction } from './kit.tsx';

/** "a majority of the servers (2 of 3)" for the number of servers this client knows. */
export function majority(s: Session): string {
  const n = s.api.nodeUrls.length;
  return n >= 2 ? `a majority of the servers (${Math.floor(n / 2) + 1} of ${n})` : 'a majority of the servers';
}

/** Why nothing can be changed right now, in plain words (null when changes work). */
export function writeBlock(s: Session): string | null {
  if (s.recovery) return 'Changes are off until you decide about the older data (see the message at the top).';
  if (s.mode === 'offline') return 'Changes are off while no server can be reached.';
  if (s.mode === 'stale') return `Changes are off until ${majority(s)} can be reached.`;
  return null;
}

/** Why this vault cannot be changed by this person right now (null when it can). */
export function vaultBlock(s: Session, v: VaultView): string | null {
  if (v.state !== 'open') return 'This vault is not open on this device.';
  if (v.role === 'viewer') return 'You can view this vault but not change it. An owner of the vault can make you an editor.';
  return writeBlock(s);
}

/** Persistent connection indicator; the button opens a plain-language explanation. */
export function StatusIndicator(p: { session: Session; onRetry: () => Promise<void> }) {
  const { busy, run } = useAction();
  const s = p.session;
  const kind = s.recovery ? 'offline' : s.mode;
  // the part after the colon is dropped on narrow screens
  const [short, rest = ''] = s.recovery ? ['Read-only', ': older data'] : s.mode === 'online' ? ['Online'] : s.mode === 'stale' ? ['Read-only', ': may be out of date'] : ['Offline', ': read-only'];
  const label = short + rest;
  const [title, ...detail] = s.recovery
    ? ['The servers are showing older data than this device has seen.', 'Expected only after the administrator restored a backup. You can still read and copy everything.']
    : s.mode === 'online'
      ? ['Everything is working.', `Every change is stored on ${majority(s)} before it counts${s.api.nodeUrls.length >= 3 ? ', so nothing is lost if one server fails' : ''}.`]
      : s.mode === 'stale'
        ? ['Most of the servers cannot be reached.', 'You are seeing the last copy one server has, which may be out of date. You can still read and copy entries.']
        : ['No server can be reached.', 'You are looking at the copy saved on this device. You can still read and copy entries.'];
  const retry = s.mode !== 'online' && (
    <button
      type="button"
      class="btn small"
      disabled={busy}
      onClick={() => void run(p.onRetry)}
    >
      {busy ? 'Trying…' : 'Try again'}
    </button>
  );
  return (
    <div class={`status ${kind}`}>
      <Popup
        class="status-btn"
        button={
          <>
            <span class="dot" aria-hidden="true" />
            <span class="sr-only">Connection: </span>
            <span class="status-text">
              {short}
              <span class="status-long">{rest}</span>
            </span>
          </>
        }
      >
        <p>
          <strong>{title}</strong>
        </p>
        <p>
          {detail} {writeBlock(s)}
        </p>
        {s.mode !== 'offline' && <p class="hint">Connected through {hostOf(s.api.currentNode)}.</p>}
        {retry}
      </Popup>
      {retry}
      <span class="sr-only" role="status">
        {s.mode === 'online' && !s.recovery ? '' : `${label}. ${title}`}
      </span>
    </div>
  );
}
