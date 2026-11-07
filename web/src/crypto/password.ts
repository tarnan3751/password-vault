// Password generator. Uniform: characters are drawn with rejection sampling
// from crypto.getRandomValues (no modulo bias), then required class characters
// are shuffled into uniformly random positions (Fisher-Yates).

export type CharClass = 'lower' | 'upper' | 'digits' | 'symbols';

const SETS: Record<CharClass, string> = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?/~',
};
const AMBIGUOUS = 'O0oIl1|';
export const MAX_GENERATED_LENGTH = 1024;

export interface PasswordOptions {
  length: number;
  classes?: CharClass[];
  excludeAmbiguous?: boolean;
}

/** Uniform integer in [0, n), 1 <= n <= 2^32, by rejection sampling. */
export function randInt(n: number, fill: (a: Uint32Array<ArrayBuffer>) => void = (a) => void crypto.getRandomValues(a)): number {
  if (!Number.isInteger(n) || n < 1 || n > 2 ** 32) throw new Error('randInt: n out of range');
  if (n === 1) return 0;
  const space = 2 ** 32;
  const limit = space - (space % n);
  const buf = new Uint32Array(1);
  for (;;) {
    fill(buf);
    if (buf[0]! < limit) return buf[0]! % n;
  }
}

export function generatePassword(opts: PasswordOptions): string {
  const classes = [...new Set(opts.classes ?? (['lower', 'upper', 'digits', 'symbols'] as CharClass[]))];
  const sets = classes.map((c) => {
    const s = SETS[c];
    if (!s) throw new Error('unknown character class');
    return opts.excludeAmbiguous ? [...s].filter((ch) => !AMBIGUOUS.includes(ch)).join('') : s;
  });
  if (sets.length === 0) throw new Error('no character class selected');
  const { length } = opts;
  if (!Number.isInteger(length) || length < sets.length || length > MAX_GENERATED_LENGTH) throw new Error('password length out of range');
  const all = sets.join('');
  const out: string[] = new Array(length);
  sets.forEach((s, i) => (out[i] = s[randInt(s.length)]!));
  for (let i = sets.length; i < length; i++) out[i] = all[randInt(all.length)]!;
  for (let i = length - 1; i > 0; i--) {
    const j = randInt(i + 1);
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out.join('');
}

/**
 * Rough strength estimate in bits for the master-password hint. It is a hint,
 * not a guarantee: pool size x length, minus penalties for repeats, runs and
 * a few very common patterns. Passphrases of several random words score well.
 */
export function estimateStrengthBits(pw: string): number {
  if (pw.length === 0) return 0;
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9\s]/.test(pw)) pool += 32;
  if (/\s/.test(pw)) pool += 1;
  if (/[^\x00-\x7f]/.test(pw)) pool += 100;
  const chars = [...pw];
  const unique = new Set(chars).size;
  let bits = Math.min(chars.length, unique * 2) * Math.log2(Math.max(pool, 2));
  if (/^(?:password|passw0rd|qwerty|letmein|12345|iloveyou|admin|welcome)/i.test(pw)) bits = Math.min(bits, 20);
  if (/(.)\1{3,}/.test(pw)) bits -= 8;
  return Math.max(0, Math.round(bits));
}

export type Strength = { bits: number; label: 'too weak' | 'weak' | 'fair' | 'good' | 'strong' };

export function strengthLabel(pw: string): Strength {
  const bits = estimateStrengthBits(pw);
  const label = bits < 40 ? 'too weak' : bits < 60 ? 'weak' : bits < 80 ? 'fair' : bits < 100 ? 'good' : 'strong';
  return { bits, label };
}
