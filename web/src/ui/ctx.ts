import { createContext } from 'preact';
import { useContext, useEffect, useState } from 'preact/hooks';
import type { Session } from '../vault/index.ts';

export interface Ctx {
  session: Session;
  toast: (msg: string, kind?: 'ok' | 'error') => void;
  copy: (text: string, what: string) => void;
  lock: () => void;
  signOut: () => void;
  autoLockMinutes: number;
  setAutoLockMinutes: (m: number) => void;
}

export const AppCtx = createContext<Ctx>(null as unknown as Ctx);
export const useApp = (): Ctx => useContext(AppCtx);

/** Re-render whenever the session publishes a change. */
export function useSessionTick(session: Session | null): void {
  const [, setN] = useState(0);
  useEffect(() => session?.subscribe(() => setN((n) => n + 1)), [session]);
}
