import { open, seal } from './box.ts';
import { utf8 } from './encoding.ts';
import { checkEpoch, checkIds, epochStr } from './ids.ts';
import { pad } from './pad.ts';
import {
  appendExtras, asBool, asInt, asString, asStringArray, decodeEntries, decodeUtf8Strict, extrasFrom, jsonString, MAX_SAFE_INT,
  parseObjectText, splitMembers, UnreadableError, type ExtraMember,
} from './strictjson.ts';

export const META_PAD_BLOCK = 64;
export const ITEM_PAD_BLOCK = 256;
export const MAX_PASSWORD_HISTORY = 10;

export type ItemType = 'login' | 'note';
export type { ExtraMember };

export interface CustomField {
  name: string;
  value: string;
  hidden?: boolean;
}

export interface PasswordHistoryEntry {
  password: string;
  changed_at: number;
}

/**
 * Decrypted item (crypto.md §5.2). `extra` holds every top-level member this
 * version does not know, as RAW TEXT in source order, so an edit never alters
 * data written by a newer client (not even `12345678901234567890` or `1.0`).
 */
export interface Item {
  v: number;
  type: ItemType;
  name: string;
  username: string;
  password: string;
  urls: string[];
  notes: string;
  totp: string;
  fields: CustomField[];
  tags: string[];
  created_at: number;
  updated_at: number;
  password_history: PasswordHistoryEntry[];
  extra: ExtraMember[];
}

const KNOWN_ITEM = new Set(['v', 'type', 'name', 'username', 'password', 'urls', 'notes', 'totp', 'fields', 'tags', 'created_at', 'updated_at', 'password_history']);
const KNOWN_FIELD = new Set(['name', 'value', 'hidden']);
const KNOWN_HIST = new Set(['password', 'changed_at']);

export function newItem(type: ItemType, nowMs: number): Item {
  return {
    v: 1, type, name: '', username: '', password: '', urls: [], notes: '', totp: '', fields: [], tags: [],
    created_at: nowMs, updated_at: nowMs, password_history: [], extra: [],
  };
}

export class ItemFormatError extends UnreadableError {}

function intText(n: number): string {
  if (!Number.isInteger(n) || n < 0 || n > MAX_SAFE_INT) throw new ItemFormatError('timestamp out of range');
  return String(n);
}

/** Canonical encoding (testvectors/README.md): fixed member order, compact, unknown members last in source order. */
export function itemToJson(it: Item): string {
  if (it.v !== 1) throw new ItemFormatError('unsupported version');
  if (it.type !== 'login' && it.type !== 'note') throw new ItemFormatError('unknown item type');
  const p: string[] = [];
  const put = (k: string, v: string) => p.push(jsonString(k) + ':' + v);
  const str = (k: string, v: string) => v !== '' && put(k, jsonString(v));
  const strs = (k: string, v: string[]) => v.length > 0 && put(k, '[' + v.map(jsonString).join(',') + ']');
  put('v', '1');
  put('type', jsonString(it.type));
  put('name', jsonString(it.name));
  str('username', it.username);
  str('password', it.password);
  strs('urls', it.urls);
  str('notes', it.notes);
  str('totp', it.totp);
  if (it.fields.length) {
    put('fields', '[' + it.fields.map((f) => `{"name":${jsonString(f.name)},"value":${jsonString(f.value)}${f.hidden ? ',"hidden":true' : ''}}`).join(',') + ']');
  }
  strs('tags', it.tags);
  put('created_at', intText(it.created_at));
  put('updated_at', intText(it.updated_at));
  if (it.password_history.length) {
    put('password_history', '[' + it.password_history.map((h) => `{"password":${jsonString(h.password)},"changed_at":${intText(h.changed_at)}}`).join(',') + ']');
  }
  appendExtras(p, it.extra);
  return '{' + p.join(',') + '}';
}

export function encodeItem(it: Item): Uint8Array {
  return utf8(itemToJson(it));
}

/** Decode an item from already-decoded text (used for backup payloads). */
export function decodeItemText(text: string): Item {
  const { assigned: as, extra } = splitMembers(parseObjectText(text), KNOWN_ITEM);
  for (const req of ['v', 'type', 'name']) if (!as.has(req)) throw new ItemFormatError(`missing required member "${req}"`);
  if (asInt(as.get('v')!) !== 1) throw new ItemFormatError('v must be 1');
  const type = asString(as.get('type')!);
  if (type !== 'login' && type !== 'note') throw new ItemFormatError('unknown item type');
  const s = (k: string) => (as.has(k) ? asString(as.get(k)!) : '');
  const a = (k: string) => (as.has(k) ? asStringArray(as.get(k)!) : []);
  const n = (k: string) => (as.has(k) ? asInt(as.get(k)!) : 0);
  const fields: CustomField[] = as.has('fields')
    ? decodeEntries(as.get('fields')!, KNOWN_FIELD).map((e) => {
        const f: CustomField = { name: e.has('name') ? asString(e.get('name')!) : '', value: e.has('value') ? asString(e.get('value')!) : '' };
        if (e.has('hidden') && asBool(e.get('hidden')!)) f.hidden = true;
        return f;
      })
    : [];
  const password_history: PasswordHistoryEntry[] = as.has('password_history')
    ? decodeEntries(as.get('password_history')!, KNOWN_HIST).map((e) => ({
        password: e.has('password') ? asString(e.get('password')!) : '',
        changed_at: e.has('changed_at') ? asInt(e.get('changed_at')!) : 0,
      }))
    : [];
  return {
    v: 1, type, name: asString(as.get('name')!), username: s('username'), password: s('password'), urls: a('urls'), notes: s('notes'),
    totp: s('totp'), fields, tags: a('tags'), created_at: n('created_at'), updated_at: n('updated_at'), password_history, extra: extrasFrom(extra),
  };
}

export function decodeItem(plaintext: Uint8Array): Item {
  return decodeItemText(decodeUtf8Strict(plaintext));
}

export function cloneItem(it: Item): Item {
  return structuredClone(it);
}

/**
 * Apply `edit` to a copy of `old` and maintain the bookkeeping of §5.2:
 * updated_at = now; if the password changed (and the old one was non-empty)
 * prepend the old one to password_history, keeping at most 10.
 */
export function editItem(old: Item, nowMs: number, edit: (it: Item) => void): Item {
  const n = cloneItem(old);
  edit(n);
  n.updated_at = nowMs;
  if (n.password !== old.password && old.password !== '') {
    n.password_history = [{ password: old.password, changed_at: nowMs }, ...n.password_history].slice(0, MAX_PASSWORD_HISTORY);
  }
  return n;
}

// -- AADs (epoch-bound, crypto.md §5) ------------------------------------------

export function vaultMetaAad(vaultId: string, epoch: number): Uint8Array {
  checkIds(vaultId);
  checkEpoch(epoch);
  return utf8(`fpv/v1/vault-meta|${vaultId}|${epochStr(epoch)}`);
}
export function itemAad(vaultId: string, itemId: string, epoch: number): Uint8Array {
  checkIds(vaultId, itemId);
  checkEpoch(epoch);
  return utf8(`fpv/v1/item|${vaultId}|${itemId}|${epochStr(epoch)}`);
}
export function rosterAad(vaultId: string, epoch: number): Uint8Array {
  checkIds(vaultId);
  checkEpoch(epoch);
  return utf8(`fpv/v1/roster|${vaultId}|${epochStr(epoch)}`);
}

export interface ItemRef {
  vaultId: string;
  itemId: string;
  epoch: number;
}

export function encryptItem(vaultKey: Uint8Array, ref: ItemRef, it: Item): Uint8Array {
  const pt = pad(encodeItem(it), ITEM_PAD_BLOCK);
  const blob = seal(vaultKey, pt, itemAad(ref.vaultId, ref.itemId, ref.epoch));
  pt.fill(0);
  return blob;
}

export function decryptItem(vaultKey: Uint8Array, ref: ItemRef, blob: Uint8Array): Item {
  const pt = open(vaultKey, blob, itemAad(ref.vaultId, ref.itemId, ref.epoch));
  try {
    return decodeItem(pt);
  } finally {
    pt.fill(0);
  }
}

// -- vault metadata (§5.1) -----------------------------------------------------

export interface VaultMeta {
  v: number;
  name: string;
  extra: ExtraMember[];
}

export function vaultMetaToJson(m: { name: string; extra?: readonly ExtraMember[] }): string {
  const p = ['"v":1', '"name":' + jsonString(m.name)];
  appendExtras(p, m.extra ?? []);
  return '{' + p.join(',') + '}';
}

export function decodeVaultMeta(plaintext: Uint8Array): VaultMeta {
  const { assigned: as, extra } = splitMembers(parseObjectText(decodeUtf8Strict(plaintext)), new Set(['v', 'name']));
  if (!as.has('v') || asInt(as.get('v')!) !== 1) throw new UnreadableError('v must be 1');
  if (!as.has('name')) throw new UnreadableError('missing name');
  return { v: 1, name: asString(as.get('name')!), extra: extrasFrom(extra) };
}

export function encryptVaultMeta(vaultKey: Uint8Array, p: { vaultId: string; epoch: number; meta: { name: string; extra?: readonly ExtraMember[] } }): Uint8Array {
  const pt = pad(utf8(vaultMetaToJson(p.meta)), META_PAD_BLOCK);
  return seal(vaultKey, pt, vaultMetaAad(p.vaultId, p.epoch));
}

export function decryptVaultMeta(vaultKey: Uint8Array, p: { vaultId: string; epoch: number }, blob: Uint8Array): VaultMeta {
  const pt = open(vaultKey, blob, vaultMetaAad(p.vaultId, p.epoch));
  try {
    return decodeVaultMeta(pt);
  } finally {
    pt.fill(0);
  }
}


