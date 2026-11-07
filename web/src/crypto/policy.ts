import { normalizePassword } from './ids.ts';
import { COMMON_PASSWORDS } from './common-passwords.ts';

// Master-password policy: a FLOOR, not a strength meter. Mirrors Go's
// vaultcrypto.CheckMasterPassword / PasswordHint rule for rule (the first rule
// that fires decides); testvectors/crypto-v1.json (password_policy) pins it.

export type PolicyCode = 'too_short' | 'contains_username' | 'repeated' | 'sequence' | 'common';
export const MIN_PASSWORD_LENGTH = 12;
export const HINT_TEXT = 'Consider a passphrase of four or more unrelated words, for example four random words separated by spaces.';

export interface PolicyViolation {
  code: PolicyCode;
  reason: string;
}

let commonSet: ReadonlySet<string> | undefined;

function asciiLower(s: string): string {
  return s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
}

function isRepeated(rs: number[]): boolean {
  for (let p = 1; p <= 4 && p <= rs.length; p++) {
    if (rs.length % p !== 0) continue;
    let ok = true;
    for (let i = p; i < rs.length; i++) {
      if (rs[i] !== rs[i - p]) {
        ok = false;
        break;
      }
    }
    if (ok) return true;
  }
  return false;
}

function isRun(rs: number[]): boolean {
  if (rs.length < 2) return false;
  const d = rs[1]! - rs[0]!;
  if (d !== 1 && d !== -1) return false;
  for (let i = 2; i < rs.length; i++) if (rs[i]! - rs[i - 1]! !== d) return false;
  return true;
}

/** Returns the violation, or null if the password meets the floor. `username` may be empty. */
export function checkMasterPassword(password: string, username: string): PolicyViolation | null {
  const pw = new TextDecoder().decode(normalizePassword(password));
  const rs = [...pw].map((c) => c.codePointAt(0)!);
  if (rs.length < MIN_PASSWORD_LENGTH) return { code: 'too_short', reason: `Use at least ${MIN_PASSWORD_LENGTH} characters (this one has ${rs.length}).` };
  const low = asciiLower(pw);
  const u = asciiLower(username.replace(/^[ \t\n\v\f\r]+/, '').replace(/[ \t\n\v\f\r]+$/, ''));
  if (u !== '' && (low === u || (u.length >= 3 && low.includes(u)))) return { code: 'contains_username', reason: 'The password must not contain your username.' };
  if (isRepeated(rs)) return { code: 'repeated', reason: 'The password must not be a short pattern repeated over and over.' };
  if (isRun(rs)) return { code: 'sequence', reason: 'The password must not be a simple ascending or descending run of characters.' };
  commonSet ??= new Set(COMMON_PASSWORDS);
  if (commonSet.has(low)) return { code: 'common', reason: 'This password is on the list of very common passwords.' };
  return null;
}

/** The passphrase nudge: shown when the (normalized) password has fewer than four space-separated words. */
export function passwordHint(password: string): string {
  const words = new TextDecoder().decode(normalizePassword(password)).split(' ').filter((w) => w !== '').length;
  return words < 4 ? HINT_TEXT : '';
}
