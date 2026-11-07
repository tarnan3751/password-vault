import { b64decode, isB64, validId, validUsername, isRole } from '../crypto/index.ts';
import type { SyncResponse } from '../api/types.ts';
import { InvalidSyncError } from './errors.ts';

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const isCount = (n: unknown): n is number => typeof n === 'number' && Number.isInteger(n) && n >= 0 && n <= Number.MAX_SAFE_INTEGER;

function key32(s: unknown): boolean {
  if (typeof s !== 'string') return false;
  try {
    return b64decode(s).length === 32;
  } catch {
    return false;
  }
}
const b64ok = (s: unknown): boolean => typeof s === 'string' && isB64(s);

/**
 * Structural validation of a full sync response (crypto.md §6.2). Anything
 * malformed or duplicated rejects the response AS A WHOLE: a client never
 * works with half of a lying answer. Duplicate detection uses Sets, never
 * plain objects keyed by server-provided strings.
 */
export function validateSync(r: unknown): asserts r is SyncResponse & { account: NonNullable<SyncResponse['account']> } {
  const bad = (why: string): never => {
    throw new InvalidSyncError(why);
  };
  if (!isObj(r) || !isCount(r.rev)) return bad('malformed response');
  const a = r.account;
  if (!isObj(a)) return bad('missing account');
  if (!validId(a.user_id)) bad('account user id');
  if (!validUsername(a.username)) bad('account username');
  if (!key32(a.public_key)) bad('account public key');
  if (!b64ok(a.wrapped_account_key) || !b64ok(a.enc_private_key) || !isObj(a.kdf)) bad('account key material');

  const dir = r.directory ?? [];
  if (!Array.isArray(dir)) return bad('directory');
  const ids = new Set<string>();
  const names = new Set<string>();
  for (const d of dir) {
    if (!isObj(d) || !validId(d.user_id) || !validUsername(d.username) || !key32(d.public_key)) return bad('directory entry');
    if (ids.has(d.user_id as string) || names.has(d.username as string)) return bad('duplicate user in directory');
    ids.add(d.user_id as string);
    names.add(d.username as string);
  }
  const vs = r.vaults ?? [];
  if (!Array.isArray(vs)) return bad('vaults');
  const vids = new Set<string>();
  for (const v of vs) {
    if (!isObj(v) || !validId(v.id)) return bad('vault id');
    if (vids.has(v.id as string)) return bad('duplicate vault');
    vids.add(v.id as string);
    if (typeof v.key_epoch !== 'number' || !Number.isInteger(v.key_epoch) || v.key_epoch < 1 || v.key_epoch > 4294967295) return bad('key epoch');
    if (!b64ok(v.enc_meta) || !b64ok(v.enc_roster)) return bad('vault ciphertext');
    if (!isCount(v.meta_version) || !isCount(v.roster_version) || !isCount(v.rev)) return bad('vault versions');
    if (!isRole(v.my_role)) return bad('role');
    if (!isObj(v.my_key) || !validId(v.my_key.sender_id) || !b64ok(v.my_key.blob)) return bad('wrapped key');
    if (typeof v.personal !== 'boolean' || typeof v.rekey_recommended !== 'boolean') return bad('vault flags');
    if (!Array.isArray(v.members) || !Array.isArray(v.items)) return bad('vault lists');
    const mids = new Set<string>();
    for (const m of v.members) {
      if (!isObj(m) || !validId(m.user_id) || !isRole(m.role)) return bad('vault member');
      if (mids.has(m.user_id as string)) return bad('duplicate member');
      mids.add(m.user_id as string);
    }
    const iids = new Set<string>();
    for (const it of v.items) {
      if (!isObj(it) || !validId(it.id) || !b64ok(it.blob) || !isCount(it.version)) return bad('item');
      if (iids.has(it.id as string)) return bad('duplicate item');
      iids.add(it.id as string);
    }
  }
}
