import { b64decode, b64encode } from './encoding.ts';
import { open, seal } from './box.ts';
import { checkEpoch, checkIds, validId } from './ids.ts';
import { rosterAad } from './item.ts';
import { asString, decodeUtf8Strict, decodeEntries, asInt, parseObjectText, splitMembers, UnreadableError, jsonString } from './strictjson.ts';

export type Role = 'owner' | 'editor' | 'viewer';
export const ROLES: readonly Role[] = ['owner', 'editor', 'viewer'];
export const isRole = (r: unknown): r is Role => r === 'owner' || r === 'editor' || r === 'viewer';

export interface RosterMember {
  id: string;
  /** 32-byte X25519 public key */
  publicKey: Uint8Array;
  role: Role;
}

export interface Roster {
  v: 1;
  members: RosterMember[];
}

/** Invariants of crypto.md §6.3: valid ids, sorted strictly ascending (hence unique), valid roles, at least one owner. */
export function validateRoster(r: Roster): void {
  if (r.v !== 1) throw new UnreadableError('unsupported roster version');
  let owners = 0;
  r.members.forEach((m, i) => {
    if (!validId(m.id)) throw new UnreadableError('roster member has a malformed ID');
    if (!isRole(m.role)) throw new UnreadableError('roster role must be owner, editor or viewer');
    if (m.publicKey.length !== 32) throw new UnreadableError('roster key must be 32 bytes');
    if (i > 0 && r.members[i - 1]!.id >= m.id) throw new UnreadableError('roster members must be sorted by ID and unique');
    if (m.role === 'owner') owners++;
  });
  if (owners === 0) throw new UnreadableError('roster has no owner');
}

export function rosterToJson(r: Roster): string {
  validateRoster(r);
  return `{"v":1,"members":[${r.members.map((m) => `{"id":${jsonString(m.id)},"pk":"${b64encode(m.publicKey)}","role":${jsonString(m.role)}}`).join(',')}]}`;
}

export function encodeRoster(r: Roster): Uint8Array {
  return new TextEncoder().encode(rosterToJson(r));
}

export function decodeRoster(plaintext: Uint8Array): Roster {
  const { assigned: as } = splitMembers(parseObjectText(decodeUtf8Strict(plaintext)), new Set(['v', 'members']));
  if (!as.has('v') || asInt(as.get('v')!) !== 1) throw new UnreadableError('v must be 1');
  if (!as.has('members')) throw new UnreadableError('missing members');
  const ents = decodeEntries(as.get('members')!, new Set(['id', 'pk', 'role']));
  const members = ents.map((e): RosterMember => {
    for (const req of ['id', 'pk', 'role']) if (!e.has(req)) throw new UnreadableError(`roster entry missing "${req}"`);
    const pk = asString(e.get('pk')!);
    let raw: Uint8Array;
    try {
      raw = b64decode(pk); // strict: standard alphabet, padded, no whitespace, canonical
    } catch {
      throw new UnreadableError('pk must be canonical padded base64');
    }
    if (raw.length !== 32) throw new UnreadableError('pk must be 32 bytes');
    const role = asString(e.get('role')!);
    if (!isRole(role)) throw new UnreadableError('bad role');
    return { id: asString(e.get('id')!), publicKey: raw, role };
  });
  const r: Roster = { v: 1, members };
  validateRoster(r);
  return r;
}

/** encRoster = seal(VK, rosterJSON (NOT padded), aad = "fpv/v1/roster|" + vaultID + "|" + epoch). */
export function encryptRoster(vaultKey: Uint8Array, p: { vaultId: string; epoch: number }, r: Roster): Uint8Array {
  return seal(vaultKey, encodeRoster(r), rosterAad(p.vaultId, p.epoch));
}

export function decryptRoster(vaultKey: Uint8Array, p: { vaultId: string; epoch: number }, blob: Uint8Array): Roster {
  checkIds(p.vaultId);
  checkEpoch(p.epoch);
  const pt = open(vaultKey, blob, rosterAad(p.vaultId, p.epoch));
  try {
    return decodeRoster(pt);
  } finally {
    pt.fill(0);
  }
}

export const rosterMember = (r: Roster, id: string): RosterMember | undefined => r.members.find((m) => m.id === id);
export const rosterOwners = (r: Roster): RosterMember[] => r.members.filter((m) => m.role === 'owner');

function sorted(ms: RosterMember[]): RosterMember[] {
  return [...ms].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

export function rosterWithMember(r: Roster, m: RosterMember): Roster {
  if (rosterMember(r, m.id)) throw new Error('member already in roster');
  const n: Roster = { v: 1, members: sorted([...r.members, m]) };
  validateRoster(n);
  return n;
}

export function rosterWithRole(r: Roster, id: string, role: Role): Roster {
  if (!rosterMember(r, id)) throw new Error('member not in roster');
  const n: Roster = { v: 1, members: r.members.map((m) => (m.id === id ? { ...m, role } : m)) };
  validateRoster(n);
  return n;
}

export function rosterWithout(r: Roster, ids: ReadonlySet<string>): Roster {
  const n: Roster = { v: 1, members: r.members.filter((m) => !ids.has(m.id)) };
  validateRoster(n);
  return n;
}
