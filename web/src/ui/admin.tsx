import { useEffect, useState } from 'preact/hooks';
import type { AdminClusterResponse, Invite } from '../api/types.ts';
import { useApp, useSessionTick } from './ctx.ts';
import { Banner, Fingerprint, fmtTime, hostOf, Icon, MemberRow, Modal, PersonRow, Spinner, Tabs, useAction } from './kit.tsx';
import { writeBlock } from './status.tsx';
import { ConfirmDialog } from './vault-dialogs.tsx';

type Tab = 'invites' | 'users' | 'cluster';

export function AdminDialog(p: { onClose: () => void }) {
  const { session } = useApp();
  const [tab, setTab] = useState<Tab>('invites');
  const block = writeBlock(session);
  return (
    <Modal title="Administration" onClose={p.onClose} wide>
      <p class="muted">You decide who can join and keep an eye on the servers. You cannot see inside anyone's vaults.</p>
      {block && <Banner kind="warn">{block}</Banner>}
      <Tabs
        label="Administration"
        tabs={[
          ['invites', 'Invites'],
          ['users', 'People'],
          ['cluster', 'Servers'],
        ]}
        current={tab}
        onChange={setTab}
      >
        {tab === 'invites' && <Invites />}
        {tab === 'users' && <Users />}
        {tab === 'cluster' && <ClusterPane />}
      </Tabs>
    </Modal>
  );
}

function Invites() {
  const { session, copy, toast } = useApp();
  const [list, setList] = useState<Invite[] | null>(null);
  const [ttl, setTtl] = useState(72);
  const [fresh, setFresh] = useState<{ code: string; expires: number } | null>(null);
  const { error, run } = useAction();
  const load = async () => void setList(await session.listInvites());
  useEffect(() => void run(load), []);
  const name = (id: string) => session.directoryUsers().find((u) => u.userId === id)?.username ?? 'someone';
  return (
    <div class="stack">
      <p class="hint">Everyone needs their own account: create an invite code for each person.</p>
      {error && <Banner kind="error">{error}</Banner>}
      <form
        class="inline-form"
        onSubmit={(e) => {
          e.preventDefault();
          void run(async () => {
            const r = await session.createInvite(ttl);
            setFresh({ code: r.code, expires: r.expires_at });
            await load();
          });
        }}
      >
        <div class="field">
          <label for="ttl">The code stops working after</label>
          <select id="ttl" value={String(ttl)} onChange={(e) => setTtl(Number(e.currentTarget.value))}>
            <option value="1">1 hour</option>
            <option value="24">1 day</option>
            <option value="72">3 days</option>
            <option value="168">1 week</option>
            <option value="720">30 days</option>
          </select>
        </div>
        <button type="submit" class="btn primary" disabled={!session.canWrite}>
          <Icon name="plus" />
          Create invite
        </button>
      </form>
      {fresh && (
        <section class="invite" aria-labelledby="invite-h">
          <h3 id="invite-h">New invite code</h3>
          <div class="invite-code-row">
            <Fingerprint value={fresh.code} class="fp invite-code" />
            <button type="button" class="btn small" onClick={() => copy(fresh.code, 'Invite code')}>
              <Icon name="copy" />
              Copy
            </button>
          </div>
          <p>Give it to the person you are inviting. They then:</p>
          <ol class="steps">
            <li>
              open <strong>{location.origin}</strong> in their browser,
            </li>
            <li>
              choose <strong>Join with invite</strong>, and
            </li>
            <li>pick a username and master password, and type the code.</li>
          </ol>
          <p class="hint">
            It works once, until {fmtTime(fresh.expires)}, and is shown only now: the servers keep just a scrambled copy of it.
          </p>
        </section>
      )}
      <h3>Invites so far</h3>
      {!list ? (
        <Spinner label="Loading invites…" />
      ) : list.length === 0 ? (
        <p class="muted">No invites yet.</p>
      ) : (
        <ul class="members">
          {list.map((i) => {
            const st = i.used_by ? `Used by ${name(i.used_by)}` : i.expires_at < Date.now() ? 'Expired' : 'Waiting to be used';
            return (
              <MemberRow
                avatar={
                  <span class="avatar plain" aria-hidden="true">
                    <Icon name={i.used_by ? 'check' : 'inbox'} />
                  </span>
                }
                actions={
                  !i.used_by &&
                  i.expires_at >= Date.now() && (
                    <button
                      type="button"
                      class="btn small danger"
                      disabled={!session.canWrite}
                      onClick={() => void run(async () => {
                        await session.revokeInvite(i.invite_id);
                        toast('Invite withdrawn');
                        await load();
                      })}
                    >
                      Withdraw
                    </button>
                  )
                }
              >
                <strong>{st}</strong>
                <div class="muted small-text">
                  Created {fmtTime(i.created_at)} · {i.expires_at < Date.now() ? 'expired' : 'expires'} {fmtTime(i.expires_at)}
                </div>
              </MemberRow>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function Users() {
  const { session, toast } = useApp();
  useSessionTick(session);
  const { error, run } = useAction();
  const [disabling, setDisabling] = useState<{ userId: string; username: string } | null>(null);
  const act = (fn: () => Promise<void>, msg: string) => run(async () => { await fn(); toast(msg); });
  return (
    <div class="stack">
      {error && <Banner kind="error">{error}</Banner>}
      <ul class="members">
        {session.directoryUsers().map((u) => {
          const me = u.userId === session.userId;
          return (
            <PersonRow
              name={u.username}
              tags={
                <>
                  {me && <span class="tag">you</span>}
                  <span class="tag">{u.isAdmin ? 'administrator' : 'member'}</span>
                  {u.disabled && <span class="tag warn">disabled: cannot log in</span>}
                </>
              }
              fingerprint={u.fingerprint}
              actions={
                !me && (
                  <div class="member-actions">
                    <button type="button" class="btn small" disabled={!session.canWrite} onClick={() => void act(() => session.setUserAdmin(u.userId, !u.isAdmin), u.isAdmin ? `${u.username} is no longer an administrator` : `${u.username} is now an administrator`)}>
                      {u.isAdmin ? 'Remove admin' : 'Make admin'}
                    </button>
                    <button
                      type="button"
                      class={u.disabled ? 'btn small' : 'btn small danger'}
                      disabled={!session.canWrite}
                      onClick={() => (u.disabled ? void act(() => session.setUserDisabled(u.userId, false), `${u.username} can log in again`) : setDisabling(u))}
                    >
                      {u.disabled ? 'Enable' : 'Disable…'}
                    </button>
                  </div>
                )
              }
            />
          );
        })}
      </ul>
      <p class="hint">Disabling a person signs them out and stops them logging in. Nothing of theirs is deleted.</p>
      {disabling && (
        <ConfirmDialog
          title={`Disable ${disabling.username}?`}
          confirmLabel="Disable"
          danger
          onCancel={() => setDisabling(null)}
          onConfirm={async () => {
            const u = disabling;
            setDisabling(null);
            await act(() => session.setUserDisabled(u.userId, true), `${u.username} is disabled`);
          }}
        >
          <p>{disabling.username} is signed out everywhere and cannot log in until you enable them again. They still know the passwords they have seen; change the ones that matter.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}

const ROLE_WORDS: Record<string, string> = { leader: 'coordinating the others', follower: 'following the coordinator', candidate: 'choosing a coordinator' };

function ClusterPane() {
  const { session } = useApp();
  const [data, setData] = useState<Awaited<ReturnType<typeof session.clusterStatus>> | null>(null);
  const [busy, setBusy] = useState(false);
  const load = async () => {
    setBusy(true);
    try {
      setData(await session.clusterStatus());
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => void load(), []);
  const admin: AdminClusterResponse | undefined = data?.admin;
  const n = data?.nodes.length ?? 0;
  const up = data?.nodes.filter((x) => x.ok).length ?? 0;
  const need = Math.floor(n / 2) + 1;
  const spare = up - need;
  return (
    <div class="stack">
      {!data ? (
        <Spinner label="Checking the servers…" />
      ) : (
        <>
          <Banner
            kind={up === n ? 'ok' : up >= need ? 'warn' : 'error'}
            action={
              <button type="button" class="btn small" onClick={load} disabled={busy}>
                <Icon name="refresh" />
                {busy ? 'Checking…' : 'Check again'}
              </button>
            }
          >
            <strong>
              {up} of {n} server{n === 1 ? '' : 's'} {up === 1 ? 'is' : 'are'} reachable from this device.
            </strong>{' '}
            {spare > 0
              ? `Everything is working, and ${spare === 1 ? 'one server' : `${spare} servers`} can fail without anyone noticing.`
              : spare === 0
                ? n > 1
                  ? `Saving still works, because it needs a majority of the servers (${need} of ${n}). One more failure makes everything read-only: restart the missing server soon.`
                  : 'Saving works, but there is no spare server.'
                : `Nothing can be saved until a majority of the servers (${need} of ${n}) can be reached. Reading still works.`}
          </Banner>
          <ul class="members">
            {data.nodes.map((x) => (
              <MemberRow
                avatar={
                  <span class={x.ok ? 'avatar plain ok' : 'avatar plain bad'} aria-hidden="true">
                    <Icon name="server" />
                  </span>
                }
              >
                <div class="member-name">
                  <strong>{x.health?.node_id ?? hostOf(x.node)}</strong>
                  <span class={x.ok ? 'tag ok' : 'tag danger'}>
                    <Icon name={x.ok ? 'check' : 'x'} />
                    {x.ok ? 'working' : 'not reachable'}
                  </span>
                  {x.node === session.api.currentNode && <span class="tag">this device is using it</span>}
                </div>
                <div class="muted small-text">
                  {hostOf(x.node)}
                  {x.ok && ` · ${ROLE_WORDS[x.health?.role ?? ''] ?? x.health?.role} · answered in ${x.ms} ms`}
                </div>
              </MemberRow>
            ))}
          </ul>
        </>
      )}
      {admin && (
        <details class="more">
          <summary>Technical details</summary>
          <dl class="facts">
            <dt>Answered by</dt>
            <dd>
              {admin.node_id} ({admin.role})
            </dd>
            <dt>Leader</dt>
            <dd>{admin.leader_id || 'none known'}</dd>
            <dt>Raft term</dt>
            <dd>{admin.term}</dd>
            <dt>Commit / applied index</dt>
            <dd>
              {admin.commit_index} / {admin.applied_index}
            </dd>
            <dt>Data revision</dt>
            <dd>{admin.rev}</dd>
            {admin.peers?.map((peer) => (
              <>
                <dt>Peer {peer.id}</dt>
                <dd>
                  {peer.last_contact_ms < 0 ? 'never contacted' : `last contact ${peer.last_contact_ms} ms ago`}, match index {peer.match_index}
                </dd>
              </>
            ))}
          </dl>
        </details>
      )}
    </div>
  );
}
