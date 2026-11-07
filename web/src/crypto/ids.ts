import { bytesToHex, randomBytes } from './encoding.ts';

/** 16 random bytes as 32 lowercase hex characters (crypto.md §1). */
export function newId(): string {
  return bytesToHex(randomBytes(16));
}

export function validId(s: unknown): s is string {
  return typeof s === 'string' && /^[0-9a-f]{32}$/.test(s);
}

export function checkIds(...ids: string[]): void {
  for (const id of ids) if (!validId(id)) throw new Error('malformed id');
}

export const MAX_EPOCH = 4294967295;

export function checkEpoch(epoch: number): void {
  if (!Number.isInteger(epoch) || epoch < 1 || epoch > MAX_EPOCH) throw new Error('key epoch must be an integer >= 1');
}

/** Base-10, no padding (crypto.md §1). */
export function epochStr(epoch: number): string {
  checkEpoch(epoch);
  return String(epoch);
}

const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{0,31}$/;

export function validUsername(s: unknown): s is string {
  return typeof s === 'string' && USERNAME_RE.test(s);
}

/**
 * Trim ASCII whitespace only, reject any non-ASCII character BEFORE
 * lower-casing, then validate. Matches the Go implementation exactly; JS
 * String.trim() and toLowerCase() are Unicode-aware and must not be used here
 * (e.g. U+212A KELVIN SIGN lower-cases to ASCII "k").
 */
export function normalizeUsername(s: string): string {
  const t = s.replace(/^[ \t\n\v\f\r]+/, '').replace(/[ \t\n\v\f\r]+$/, '');
  if (/[^\x00-\x7f]/.test(t)) throw new Error('invalid username: only ASCII letters, digits, ".", "_" and "-" are allowed');
  const l = t.toLowerCase();
  if (!USERNAME_RE.test(l)) throw new Error('invalid username: use 1-32 characters from a-z, 0-9, ".", "_", "-", starting with a letter or digit');
  return l;
}

/** NFKC then UTF-8, no trimming (crypto.md §1). Lone surrogates become U+FFFD like Go. */
export function normalizePassword(password: string): Uint8Array {
  return new TextEncoder().encode(password.toWellFormed().normalize('NFKC'));
}
