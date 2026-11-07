import { DecryptError, open, seal } from './box.ts';
import { b64decode, b64encode, utf8, zero } from './encoding.ts';
import { decodeItemText, itemToJson, type Item } from './item.ts';
import { deriveBackupKey, kdfToWire, KdfParamsError, validateKdfParams, type KdfParams } from './kdf.ts';
import { asBool, asInt, asString, decodeUtf8Strict, jsonString, parseArray, parseObjectText, splitMembers, UnreadableError, asObject } from './strictjson.ts';

export const BACKUP_FORMAT = 'fpv-backup';
export const BACKUP_VERSION = 1;
export const BACKUP_AAD = utf8('fpv/v1/backup');

export interface BackupEntry {
  id: string;
  item: Item;
}
export interface BackupVault {
  id: string;
  name: string;
  personal: boolean;
  items: BackupEntry[];
}
export interface BackupPayload {
  v: number;
  exported_at: number;
  exported_by: string;
  vaults: BackupVault[];
}

export type BackupErrorCode = 'not_backup' | 'unsupported_version' | 'weak_kdf' | 'decrypt';

/** Classes let the UI tell "not a backup" from "wrong passphrase" (testvectors/README.md). */
export class BackupError extends Error {
  code: BackupErrorCode;
  constructor(code: BackupErrorCode) {
    super(
      code === 'not_backup' ? 'this is not a Family Vault backup file'
      : code === 'unsupported_version' ? 'this backup was made by a newer, unsupported version'
      : code === 'weak_kdf' ? 'this backup uses key-derivation settings that are too weak or unreasonable to accept'
      : 'wrong passphrase, or the backup file is damaged',
    );
    this.name = 'BackupError';
    this.code = code;
  }
}

/** Exact plaintext JSON that is encrypted (compact, UTF-8, not padded), same member order as Go. */
export function payloadToJson(p: BackupPayload): string {
  const vaults = p.vaults.map(
    (v) =>
      `{"id":${jsonString(v.id)},"name":${jsonString(v.name)},"personal":${v.personal ? 'true' : 'false'},"items":[` +
      v.items.map((e) => `{"id":${jsonString(e.id)},"item":${itemToJson(e.item)}}`).join(',') +
      ']}',
  );
  return `{"v":${p.v},"exported_at":${p.exported_at},"exported_by":${jsonString(p.exported_by)},"vaults":[${vaults.join(',')}]}`;
}

/** The file envelope (2-space indent, fixed member order); the blob is already sealed. */
export function backupFileText(kdf: KdfParams, createdAtMs: number, blob: Uint8Array): string {
  return JSON.stringify({ format: BACKUP_FORMAT, version: BACKUP_VERSION, created_at: createdAtMs, kdf: kdfToWire(kdf), blob: b64encode(blob) }, null, 2);
}

export async function encodeBackup(payload: BackupPayload, passphrase: string, kdf: KdfParams, createdAtMs: number = Date.now()): Promise<string> {
  if (payload.v !== BACKUP_VERSION) throw new Error('backup payload version must be 1');
  const key = await deriveBackupKey(passphrase, kdf);
  const pt = utf8(payloadToJson(payload));
  const blob = seal(key, pt, BACKUP_AAD);
  zero(key, pt);
  return backupFileText(kdf, createdAtMs, blob);
}

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/** Strict decoding of the authenticated payload; items follow the §5.3 rules. */
function decodePayload(pt: Uint8Array): BackupPayload {
  const { assigned: as } = splitMembers(parseObjectText(decodeUtf8Strict(pt)), new Set(['v', 'exported_at', 'exported_by', 'vaults']));
  if (!as.has('v')) throw new UnreadableError('missing v');
  if (asInt(as.get('v')!) !== BACKUP_VERSION) throw new BackupError('unsupported_version');
  if (!as.has('vaults') || !as.has('exported_at') || !as.has('exported_by')) throw new UnreadableError('missing member');
  const vaults = parseArray(as.get('vaults')!).map((vt): BackupVault => {
    const { assigned: va } = splitMembers(asObject(vt), new Set(['id', 'name', 'personal', 'items']));
    for (const r of ['id', 'name', 'items']) if (!va.has(r)) throw new UnreadableError('vault missing member');
    const items = parseArray(va.get('items')!).map((et): BackupEntry => {
      const { assigned: ea } = splitMembers(asObject(et), new Set(['id', 'item']));
      if (!ea.has('id') || !ea.has('item')) throw new UnreadableError('entry missing member');
      return { id: asString(ea.get('id')!), item: decodeItemText(ea.get('item')!) };
    });
    return { id: asString(va.get('id')!), name: asString(va.get('name')!), personal: va.has('personal') ? asBool(va.get('personal')!) : false, items };
  });
  return { v: 1, exported_at: asInt(as.get('exported_at')!), exported_by: asString(as.get('exported_by')!), vaults };
}

/**
 * Parse + decrypt a backup file. The KDF parameter bounds are enforced BEFORE
 * any Argon2 work (a hostile file could request 2 GiB / hours of CPU).
 */
export async function decodeBackup(text: string, passphrase: string): Promise<BackupPayload> {
  let head: unknown;
  try {
    head = JSON.parse(text);
  } catch {
    throw new BackupError('not_backup');
  }
  if (!isObj(head) || head.format !== BACKUP_FORMAT) throw new BackupError('not_backup');
  if (head.version !== BACKUP_VERSION) throw new BackupError('unsupported_version');

  let kdf: KdfParams;
  let blob: Uint8Array;
  try {
    const k = head.kdf;
    if (!isObj(k) || typeof k.salt !== 'string' || typeof head.blob !== 'string') throw new Error();
    kdf = { alg: k.alg as string, salt: b64decode(k.salt), time: k.time as number, memory_kib: k.memory_kib as number, parallelism: k.parallelism as number };
    blob = b64decode(head.blob);
  } catch {
    throw new BackupError('decrypt'); // malformed header: Go reports the same class
  }
  try {
    validateKdfParams(kdf);
  } catch (e) {
    if (e instanceof KdfParamsError) throw new BackupError('weak_kdf');
    throw e;
  }
  const key = await deriveBackupKey(passphrase, kdf);
  let pt: Uint8Array;
  try {
    pt = open(key, blob, BACKUP_AAD);
  } catch (e) {
    if (e instanceof DecryptError) throw new BackupError('decrypt');
    throw e;
  } finally {
    zero(key);
  }
  try {
    return decodePayload(pt);
  } catch (e) {
    if (e instanceof BackupError) throw e;
    throw new BackupError('decrypt'); // authenticated but malformed payload
  } finally {
    zero(pt);
  }
}
