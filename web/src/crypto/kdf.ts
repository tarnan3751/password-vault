import { argon2id } from 'hash-wasm';
import { argon2idAsync } from '@noble/hashes/argon2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { b64decode, b64encode, concat, randomBytes, utf8, zero } from './encoding.ts';
import { normalizePassword, normalizeUsername } from './ids.ts';

export const KDF_ALG = 'argon2id';
export const SALT_SIZE = 16;
export const DEFAULT_TIME = 3;
export const DEFAULT_MEMORY_KIB = 65536;
export const DEFAULT_PARALLELISM = 4;
export const MIN_SALT_LEN = 16;
export const MAX_SALT_LEN = 64;
export const MIN_MEMORY_KIB = 65536;
export const MAX_MEMORY_KIB = 262144;
export const MIN_TIME = 3;
export const MAX_TIME = 8;
export const MIN_PARALLELISM = 1;
export const MAX_PARALLELISM = 16;

export const INFO_ENC_KEY = 'fpv/v1/enc-key';
export const INFO_LOGIN_KEY = 'fpv/v1/login-key';
export const INFO_BACKUP_KEY = 'fpv/v1/backup-key';

export interface KdfParams {
  alg: string;
  salt: Uint8Array;
  time: number;
  memory_kib: number;
  parallelism: number;
}

/** JSON shape of api.KDFParams (salt is base64). */
export interface WireKdf {
  alg: string;
  salt: string;
  time: number;
  memory_kib: number;
  parallelism: number;
}

export class KdfParamsError extends Error {
  constructor(reason: string) {
    super(`unacceptable key-derivation parameters: ${reason}`);
    this.name = 'KdfParamsError';
  }
}

export function kdfFromWire(w: WireKdf): KdfParams {
  if (!w || typeof w.salt !== 'string') throw new KdfParamsError('malformed');
  let salt: Uint8Array;
  try {
    salt = b64decode(w.salt);
  } catch {
    throw new KdfParamsError('malformed salt');
  }
  return { alg: w.alg, salt, time: w.time, memory_kib: w.memory_kib, parallelism: w.parallelism };
}

export function kdfToWire(k: KdfParams): WireKdf {
  return { alg: k.alg, salt: b64encode(k.salt), time: k.time, memory_kib: k.memory_kib, parallelism: k.parallelism };
}

export function defaultKdfParams(): KdfParams {
  return {
    alg: KDF_ALG,
    salt: randomBytes(SALT_SIZE),
    time: DEFAULT_TIME,
    memory_kib: DEFAULT_MEMORY_KIB,
    parallelism: DEFAULT_PARALLELISM,
  };
}

/**
 * The parameter floor of crypto.md §2. A malicious server could otherwise hand
 * out cheap parameters and brute-force the login key it receives. Throws
 * KdfParamsError. Always call before deriving keys from server-supplied input.
 */
export function validateKdfParams(p: KdfParams): void {
  const int = (n: unknown): n is number => typeof n === 'number' && Number.isInteger(n);
  if (p.alg !== KDF_ALG) throw new KdfParamsError('unsupported algorithm');
  if (!(p.salt instanceof Uint8Array) || p.salt.length < MIN_SALT_LEN || p.salt.length > MAX_SALT_LEN) throw new KdfParamsError('salt length out of range');
  if (!int(p.memory_kib) || p.memory_kib < MIN_MEMORY_KIB || p.memory_kib > MAX_MEMORY_KIB) throw new KdfParamsError('memory out of range');
  if (!int(p.time) || p.time < MIN_TIME || p.time > MAX_TIME) throw new KdfParamsError('time cost out of range');
  if (!int(p.parallelism) || p.parallelism < MIN_PARALLELISM || p.parallelism > MAX_PARALLELISM) throw new KdfParamsError('parallelism out of range');
}

/** Raw Argon2id (hash-wasm; WASM, so 64 MiB is affordable in a browser). */
export async function argon2idRaw(
  password: Uint8Array,
  salt: Uint8Array,
  time: number,
  memoryKiB: number,
  parallelism: number,
  outLen: number,
): Promise<Uint8Array> {
  // hash-wasm refuses an empty password, but Argon2 itself is defined for it
  // and the vectors include one. Fall back to @noble/hashes (pure JS, slower;
  // never hit by the UI, which rejects empty passwords) rather than diverge.
  if (password.length === 0) return argon2idAsync(password, salt, { t: time, m: memoryKiB, p: parallelism, dkLen: outLen });
  return argon2id({
    password,
    salt,
    iterations: time,
    memorySize: memoryKiB,
    parallelism,
    hashLength: outLen,
    outputType: 'binary',
  });
}

export function hkdfSha256(ikm: Uint8Array, info: string | Uint8Array, length = 32, salt?: Uint8Array): Uint8Array {
  return hkdf(sha256, ikm, salt, typeof info === 'string' ? utf8(info) : info, length);
}

/**
 * A device that holds cached account data refuses prelogin parameters with a
 * smaller memory or time cost than the cached ones (crypto.md §2): a server
 * must not be able to ratchet a user's KDF down later.
 */
export function checkKdfNotWeaker(cached: KdfParams, offered: KdfParams): void {
  if (offered.memory_kib < cached.memory_kib || offered.time < cached.time) {
    throw new KdfParamsError('the server offers weaker parameters than this device has cached');
  }
}

/** argonSalt = SHA-256("fpv/v1/kdf-salt|" + username + "|" || salt): binds the Argon2 salt to the user (crypto.md §2). */
export function argonSalt(username: string, salt: Uint8Array): Uint8Array {
  return sha256(concat(utf8('fpv/v1/kdf-salt|' + username + '|'), salt));
}

export interface MasterKeys {
  encKey: Uint8Array;
  loginKey: Uint8Array;
}

async function deriveFromValidated(p: { username: string; password: string; params: KdfParams }): Promise<MasterKeys> {
  if (normalizeUsername(p.username) !== p.username) throw new Error('username must be passed in normalized form');
  const pw = normalizePassword(p.password);
  const mk = await argon2idRaw(pw, argonSalt(p.username, p.params.salt), p.params.time, p.params.memory_kib, p.params.parallelism, 32);
  zero(pw);
  const keys = { encKey: hkdfSha256(mk, INFO_ENC_KEY), loginKey: hkdfSha256(mk, INFO_LOGIN_KEY) };
  zero(mk);
  return keys;
}

/** Validates the parameter floor and ceiling, then derives encKey and loginKey (crypto.md §2). */
export async function deriveMasterKeys(p: { username: string; password: string; params: KdfParams }): Promise<MasterKeys> {
  validateKdfParams(p.params);
  return deriveFromValidated(p);
}

/** backupKey = HKDF(Argon2id(NFKC(passphrase), RAW salt, ...), "fpv/v1/backup-key") with the §2 bounds (crypto.md §7). */
export async function deriveBackupKey(passphrase: string, p: KdfParams): Promise<Uint8Array> {
  validateKdfParams(p);
  const pw = normalizePassword(passphrase);
  const bk = await argon2idRaw(pw, p.salt, p.time, p.memory_kib, p.parallelism, 32);
  zero(pw);
  const k = hkdfSha256(bk, INFO_BACKUP_KEY);
  zero(bk);
  return k;
}
