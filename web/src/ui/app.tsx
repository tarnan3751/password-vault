import { useCallback, useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { ApiClient, normalizeNodeUrl } from '../api/index.ts';
import { K, Session, type Deps, type KeyValueStore } from '../vault/index.ts';
import { AppCtx, type Ctx } from './ctx.ts';
import { announce, Icon, LiveRegions } from './kit.tsx';
import { MainView } from './main-view.tsx';
import { Welcome } from './welcome.tsx';

const CLIPBOARD_CLEAR_MS = 30_000;
const POLL_MS = 30_000;

/** Non-secret, per-device preferences only. Keys, tokens and passwords never go here. */
function pref(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}
function setPref(key: string, v: string): void {
  try {
    localStorage.setItem(key, v);
  } catch {
    /* private mode: preference just isn't remembered */
  }
}

interface Toast {
  id: number;
  msg: string;
  kind: 'ok' | 'error';
}

export function App(p: { store: KeyValueStore }) {
  const { store } = p;
  const [booted, setBooted] = useState(false);
  const [session, setSession] = useState<Session | null>(null);
  const [lockedUser, setLockedUser] = useState<string | undefined>();
  const [notice, setNotice] = useState<string | undefined>();
  const [server, setServerState] = useState(pref('fv.server') ?? '');
  const [storedNodes, setStoredNodes] = useState<string[]>([]);
  const [autoLock, setAutoLock] = useState(() => {
    const n = Number(pref('fv.autolock'));
    return Number.isFinite(n) && n >= 1 ? n : 10;
  });
  const [toasts, setToasts] = useState<Toast[]>([]);
  const clipTimer = useRef<number | undefined>(undefined);
  const toastId = useRef(0);

  const needServer = !/^https?:$/.test(location.protocol) && storedNodes.length === 0;

  // -- boot: remember who used this device, so the lock screen can offer them
  useEffect(() => {
    void (async () => {
      const [nodes, last] = await Promise.all([store.get<string[]>(K.nodes), store.get<string>(K.lastUser)]);
      setStoredNodes(nodes ?? []);
      if (last && (await store.get(K.sync(last)))) setLockedUser(last);
      setBooted(true);
    })().catch(() => setBooted(true));
  }, []);

  const makeDeps = useCallback(
    (serverUrl: string): Deps => {
      const nodes = [normalizeNodeUrl(serverUrl.trim() || (location.protocol.startsWith('http') ? location.origin : '')), ...storedNodes].filter((x): x is string => !!x);
      if (nodes.length === 0) throw new Error('Enter the address of your vault server first.');
      // Plain-http nodes may be learned only when this page itself came over http (development).
      const api = new ApiClient({ nodes, allowInsecureLearned: location.protocol === 'http:', onNodesChanged: (n) => void store.set(K.nodes, n).catch(() => {}) });
      return { api, store };
    },
    [storedNodes, store],
  );

  const dropToast = (id: number) => setToasts((t) => t.filter((x) => x.id !== id));
  const toast = useCallback((msg: string, kind: 'ok' | 'error' = 'ok') => {
    const id = ++toastId.current;
    // newest last, at most three, and the same message is never stacked twice
    setToasts((t) => [...t.filter((x) => x.msg !== msg), { id, msg, kind }].slice(-3));
    setTimeout(() => dropToast(id), kind === 'error' ? 8000 : 4000);
    announce(msg, kind === 'error');
  }, []);
  // The visual stack lives in the top layer (a popover), re-shown on every change so it is never under a dialog's backdrop.
  const toastsEl = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = toastsEl.current;
    try {
      if (el?.matches(':popover-open')) el.hidePopover();
      if (toasts.length) el?.showPopover();
    } catch {
      /* no popover support: the stack still shows, just not above dialogs */
    }
  }, [toasts]);

  const copy = useCallback(
    (text: string, what: string) => {
      navigator.clipboard.writeText(text).then(
        () => {
          toast(`${what} copied. It is removed from the clipboard in 30 seconds.`);
          clearTimeout(clipTimer.current);
          clipTimer.current = window.setTimeout(async () => {
            // Best effort: only clear if the clipboard still holds what we put there
            // (reading needs a permission; if unavailable, clear anyway).
            try {
              const cur = await navigator.clipboard.readText();
              if (cur !== text) return;
            } catch {
              /* cannot read: clear regardless */
            }
            try {
              await navigator.clipboard.writeText('');
            } catch {
              /* ignore */
            }
          }, CLIPBOARD_CLEAR_MS);
        },
        () => toast('The browser did not allow copying. Reveal the value, select it and copy it by hand.', 'error'),
      );
    },
    [toast],
  );

  const afterLock = useCallback((username: string, note?: string) => {
    setToasts([]);
    setSession(null);
    setLockedUser(username);
    setNotice(note);
  }, []);

  const lock = useCallback(
    (note?: string) => {
      if (!session) return;
      const u = session.username;
      session.lock();
      afterLock(u, note);
    },
    [session, afterLock],
  );

  const signOut = useCallback(() => {
    if (!session) return;
    const u = session.username;
    session.lock();
    void Promise.all([store.delete(K.sync(u)), store.delete(K.lastUser)]).catch(() => {});
    setSession(null);
    setLockedUser(undefined);
    setNotice('Signed out. The copy saved on this device was removed; your passwords are still on the servers.');
  }, [session, store]);

  // -- the session can lock itself (expired token); reflect that in the UI
  useEffect(() => {
    if (!session) return;
    return session.subscribe(() => {
      if (session.locked) afterLock(session.username, 'You were signed out (the session expired, was ended on another device, or the password was changed). Please log in again.');
    });
  }, [session]);

  // -- auto-lock after inactivity: drops every key from memory
  useEffect(() => {
    if (!session) return;
    let timer = window.setTimeout(() => lock(`Locked after ${autoLock} minute${autoLock === 1 ? '' : 's'} of inactivity.`), autoLock * 60_000);
    let last = 0;
    const reset = () => {
      const now = Date.now();
      if (now - last < 1000) return; // throttle
      last = now;
      clearTimeout(timer);
      timer = window.setTimeout(() => lock(`Locked after ${autoLock} minute${autoLock === 1 ? '' : 's'} of inactivity.`), autoLock * 60_000);
    };
    const evs = ['pointerdown', 'keydown', 'wheel', 'touchstart'] as const;
    for (const e of evs) window.addEventListener(e, reset, { passive: true });
    return () => {
      clearTimeout(timer);
      for (const e of evs) window.removeEventListener(e, reset);
    };
  }, [session, autoLock, lock]);

  // -- keep fresh: poll while visible, and refresh when connectivity returns
  useEffect(() => {
    if (!session) return;
    const go = () => {
      if (document.visibilityState === 'visible') void session.refresh().catch(() => {});
    };
    const iv = window.setInterval(go, POLL_MS);
    window.addEventListener('online', go);
    document.addEventListener('visibilitychange', go);
    return () => {
      clearInterval(iv);
      window.removeEventListener('online', go);
      document.removeEventListener('visibilitychange', go);
    };
  }, [session]);

  const ctx: Ctx | null = useMemo(
    () =>
      session && {
        session,
        toast,
        copy,
        lock: () => lock(),
        signOut,
        autoLockMinutes: autoLock,
        setAutoLockMinutes: (m: number) => {
          setAutoLock(m);
          setPref('fv.autolock', String(m));
        },
      },
    [session, toast, copy, lock, signOut, autoLock],
  );

  if (!booted) return <div class="boot" role="status">Opening Family Vault…</div>;

  return (
    <>
      {ctx ? (
        <AppCtx.Provider value={ctx}>
          <MainView />
        </AppCtx.Provider>
      ) : (
        <Welcome
          key={lockedUser ?? 'new'}
          makeDeps={makeDeps}
          lockedUser={lockedUser}
          server={server}
          onServer={(s) => {
            setServerState(s);
            setPref('fv.server', s);
          }}
          needServer={needServer}
          notice={notice}
          onSession={(s, note) => {
            setSession(s);
            setNotice(undefined);
            setLockedUser(s.username);
            if (note) setTimeout(() => toast(note), 100);
          }}
        />
      )}
      {/* screen readers hear toasts through the live regions (see announce); click a toast to dismiss it */}
      <div class="toasts" popover="manual" ref={toastsEl} aria-hidden="true">
        {toasts.map((t) => (
          <div class={`toast ${t.kind}`} onClick={() => dropToast(t.id)}>
            <Icon name={t.kind === 'ok' ? 'check' : 'alert'} />
            {t.msg}
          </div>
        ))}
      </div>
      <LiveRegions ids />
    </>
  );
}
