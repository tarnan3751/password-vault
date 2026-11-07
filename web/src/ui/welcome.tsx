import { useEffect, useRef, useState } from 'preact/hooks';
import { ApiError, NetworkError } from '../api/index.ts';
import { Session, NoCacheError, type Deps } from '../vault/index.ts';
import { errMsg } from './errors.ts';
import { Banner, Check, Icon, PasswordRules, Seg, Spinner, TextField, usernameProblem } from './kit.tsx';
import { checkMasterPassword, normalizeUsername } from '../crypto/index.ts';

type Mode = 'login' | 'join' | 'setup';

export interface WelcomeProps {
  /** Build dependencies for a (possibly user-chosen) server URL. */
  makeDeps: (serverUrl: string) => Deps;
  /** Pre-filled username when the vault was locked or the device remembers a user. */
  lockedUser?: string;
  server: string;
  onServer: (s: string) => void;
  onSession: (s: Session, note?: string) => void;
  notice?: string;
  /** Needs a server URL because the page origin is not an http(s) node. */
  needServer: boolean;
}

const MODE_HELP: Record<Mode, string> = {
  login: 'You already have an account in this household.',
  join: 'Someone in your household gave you an invite code.',
  setup: 'Nobody has an account yet. The first account becomes the administrator, who invites everyone else.',
};

export function Welcome(p: WelcomeProps) {
  const locked = p.lockedUser !== undefined;
  const [mode, setMode] = useState<Mode>('login');
  const [hasUsers, setHasUsers] = useState<boolean | null>(null);
  const [username, setUsername] = useState(p.lockedUser ?? '');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [code, setCode] = useState('');
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [changeUser, setChangeUser] = useState(false);
  const touched = useRef(false);

  // Ask the server whether anyone has an account yet, to offer the right first step.
  useEffect(() => {
    if (locked || p.needServer) return;
    let deps: Deps;
    try {
      deps = p.makeDeps(p.server);
    } catch {
      return;
    }
    deps.api.health().then(
      (h) => {
        setHasUsers(h.has_users);
        if (!touched.current) setMode(h.has_users ? 'login' : 'setup');
      },
      () => {},
    );
  }, [locked]);

  const registering = mode !== 'login';
  const userErr = usernameProblem(username);
  let normUser = username;
  try {
    normUser = normalizeUsername(username);
  } catch {
    /* reported by userErr */
  }
  const pwOk = checkMasterPassword(password, normUser) === null;
  // The first unmet requirement, said in words next to the (disabled) button.
  const missing = !username.trim()
    ? 'enter a username'
    : userErr
      ? 'fix the username'
      : registering && !code.trim()
        ? mode === 'setup' ? 'enter the bootstrap token' : 'enter your invite code'
        : !password
          ? 'enter your master password'
          : registering && !pwOk
            ? 'choose a master password that meets the rules'
            : registering && confirm !== password
              ? 'type the same master password again in “Confirm master password”'
              : registering && !ack
                ? 'tick the box to confirm you understand there is no recovery'
                : '';
  const canSubmit = !busy && !missing;

  async function submit(e: Event) {
    e.preventDefault();
    if (!canSubmit) return;
    setError('');
    const deps = p.makeDeps(p.server);
    try {
      let s: Session;
      if (registering) {
        setBusy('Creating your account. This takes a few seconds on purpose: it makes your password much harder to guess…');
        s = await Session.register(deps, { username, password, inviteCode: code });
        p.onSession(s);
      } else {
        setBusy('Unlocking. This takes a few seconds on purpose…');
        try {
          s = await Session.login(deps, { username, password });
          p.onSession(s);
        } catch (err) {
          // Only "no server reachable" falls back to the on-device copy. A wrong
          // password or any server answer must NOT silently open the cache.
          if (!(err instanceof NetworkError)) throw err;
          try {
            s = await Session.unlockOffline(deps, { username, password });
            p.onSession(s, 'No server could be reached, so this is the copy saved on this device. You can read and copy entries.');
          } catch (err2) {
            if (err2 instanceof NoCacheError) throw err; // report the connectivity problem instead
            throw err2;
          }
        }
      }
      setPassword('');
      setConfirm('');
    } catch (err) {
      const code = registering && err instanceof ApiError ? err.code : '';
      setError(
        code === 'invalid_invite' && mode === 'setup'
          ? 'That bootstrap token is not right, or the first account already exists. Check the token with whoever set up the servers, or ask for an invite code.'
          : code === 'already_exists'
            ? 'That username is already taken. Choose another one.'
            : errMsg(err),
      );
      setPassword('');
      setConfirm('');
      setTimeout(() => document.getElementById('pw')?.focus(), 0);
    } finally {
      setBusy(null);
    }
  }

  const fixedUser = locked && !changeUser;
  const modes: [Mode, string][] = [['login', 'Log in'], ['join', 'Join with invite'], ['setup', 'First-time setup']];

  return (
    <main class="welcome">
      <div class="welcome-card">
        <div class="brand big">
          <img src="/icon.svg" alt="" width="44" height="44" />
          <h1>Family Vault</h1>
        </div>
        <p class="tagline">{fixedUser ? 'Locked. Enter your master password to continue.' : 'Passwords for your household, encrypted on this device before they are saved anywhere.'}</p>

        {p.notice && <Banner kind="info">{p.notice}</Banner>}

        {!fixedUser && (
          <>
            <Seg
              label="What would you like to do?"
              options={hasUsers ? modes.filter(([m]) => m !== 'setup' || mode === 'setup') : modes}
              value={mode}
              onChange={(m) => {
                touched.current = true;
                setMode(m);
                setError('');
              }}
            />
            <p class="mode-help">{MODE_HELP[mode]}</p>
          </>
        )}

        <form onSubmit={submit} autocomplete="off" aria-busy={!!busy}>
          <fieldset class="plain" disabled={!!busy}>
            {fixedUser ? (
              <p class="locked-user">
                <Icon name="user" />
                <span>
                  Signed in as <strong>{username}</strong>
                </span>
                <button type="button" class="link" onClick={() => { setChangeUser(true); setUsername(''); }}>
                  Not you?
                </button>
              </p>
            ) : (
              <TextField
                label="Username"
                value={username}
                onInput={setUsername}
                autocomplete="username"
                required
                autofocus
                error={userErr}
                hint={registering ? 'Others in the household will see this name. Not case-sensitive.' : undefined}
              />
            )}

            {mode === 'join' && <TextField label="Invite code" value={code} onInput={setCode} required mono hint="The code you were given, for example ABCD-EFGH-…. Capital letters and dashes do not matter." />}
            {mode === 'setup' && (
              <TextField
                label="Bootstrap token"
                value={code}
                onInput={setCode}
                required
                type="password"
                hint={
                  <>
                    The one-time setup code created when the servers were set up. <code>vaultd init-cluster</code> printed it, and it is stored in each server's <code>bootstrap-token</code> file (the{' '}
                    <code>bootstrap_token</code> setting). Ask whoever set up the servers.
                  </>
                }
              />
            )}

            <TextField
              id="pw"
              label="Master password"
              type="password"
              value={password}
              onInput={(v) => {
                touched.current = true;
                setPassword(v);
              }}
              autocomplete={registering ? 'new-password' : 'current-password'}
              required
              autofocus={fixedUser}
              describedBy={registering ? 'pw-rules' : undefined}
            />
            {registering && (
              <>
                <PasswordRules id="pw-rules" password={password} username={normUser} />
                <TextField
                  label="Confirm master password"
                  type="password"
                  value={confirm}
                  onInput={setConfirm}
                  autocomplete="new-password"
                  required
                  error={confirm !== '' && confirm !== password && confirm.length >= password.length ? 'The two passwords do not match.' : undefined}
                  hint={confirm !== '' && confirm === password ? <span class="ok-text"><Icon name="check" /> The passwords match.</span> : undefined}
                />
                <Banner kind="warn">
                  <strong>Nobody can reset a forgotten master password,</strong> not even the administrator: it never leaves this device. If you forget it, everything in your
                  personal vault is lost. Write it down and keep it somewhere safe at home.
                </Banner>
                <Check strong checked={ack} onChange={setAck} label="I understand that a forgotten master password cannot be recovered." />
              </>
            )}

            {error && <Banner kind="error">{error}</Banner>}
            {busy && <Spinner label={busy} />}

            <button type="submit" class="btn primary block big" disabled={!canSubmit} aria-describedby={missing ? 'why' : undefined}>
              {registering ? (mode === 'setup' ? 'Create the first account' : 'Create account') : fixedUser ? 'Unlock' : 'Log in'}
            </button>
            {missing && !busy && (password || code || (username && !fixedUser)) && (
              <p class="hint center" id="why">
                To continue, {missing}.
              </p>
            )}
          </fieldset>
        </form>
        {mode === 'login' && (
          <details class="server-opt">
            <summary>Forgot your master password?</summary>
            <p class="hint">
              Nobody can reset it. An administrator can invite you again as a new account; your personal vault is lost, but others can share their vaults with you again.
            </p>
          </details>
        )}

        <details class="server-opt" open={p.needServer || undefined}>
          <summary>Server address</summary>
          <TextField
            label="Address of your vault server"
            value={p.server}
            onInput={p.onServer}
            placeholder={p.needServer ? 'https://vault.example:8443' : 'Leave empty to use this site'}
            hint="Only needed if this page did not come from your vault server. The other servers are found automatically."
            inputMode="url"
          />
        </details>
      </div>
    </main>
  );
}
