// Byte/text helpers. Everything here is deliberately strict: the wire format
// (crypto.md §1) is standard base64 WITH padding and lowercase hex, and a
// lenient decoder could let two implementations disagree about the same input.

const te = new TextEncoder();
const td = new TextDecoder('utf-8', { fatal: true });

export function utf8(s: string): Uint8Array {
  return te.encode(s);
}

/** Strict UTF-8 decode; throws on invalid sequences. */
export function fromUtf8(b: Uint8Array): string {
  return td.decode(b);
}

export function bytesToHex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += (x < 16 ? '0' : '') + x.toString(16);
  return s;
}

export function hexToBytes(h: string): Uint8Array {
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('invalid hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function b64encode(b: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < b.length; i += 3) {
    const n = (b[i]! << 16) | (b[i + 1]! << 8) | b[i + 2]!;
    out += B64[n >> 18] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  const rem = b.length - i;
  if (rem === 1) {
    const n = b[i]! << 16;
    out += B64[n >> 18] + B64[(n >> 12) & 63] + '==';
  } else if (rem === 2) {
    const n = (b[i]! << 16) | (b[i + 1]! << 8);
    out += B64[n >> 18] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + '=';
  }
  return out;
}

const B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;
const B64_VAL = new Uint8Array(128);
for (let i = 0; i < 64; i++) B64_VAL[B64.charCodeAt(i)] = i;

/** Is `s` strict standard base64 with padding, no whitespace, no URL alphabet, and canonical (zero trailing bits)? */
export function isB64(s: string): boolean {
  if (s.length % 4 !== 0 || !B64_RE.test(s)) return false;
  const pad = s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0;
  // Non-zero trailing bits would be a second encoding of the same bytes: decode(encode(x)) is the only way to reach x.
  return pad === 0 || (B64_VAL[s.charCodeAt(s.length - pad - 1)]! & (pad === 2 ? 15 : 3)) === 0;
}

export function b64decode(s: string): Uint8Array {
  if (!isB64(s)) throw new Error('invalid base64');
  const pad = s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0;
  const out = new Uint8Array((s.length / 4) * 3 - pad);
  let o = 0;
  for (let i = 0; i < s.length; i += 4) {
    const n = (B64_VAL[s.charCodeAt(i)]! << 18) | (B64_VAL[s.charCodeAt(i + 1)]! << 12) | (B64_VAL[s.charCodeAt(i + 2)]! << 6) | B64_VAL[s.charCodeAt(i + 3)]!;
    out[o++] = n >> 16;
    if (o < out.length) out[o++] = (n >> 8) & 255;
    if (o < out.length) out[o++] = n & 255;
  }
  return out;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

export function isAllZero(b: Uint8Array): boolean {
  let d = 0;
  for (const x of b) d |= x;
  return d === 0;
}

/** Best-effort wipe. JS gives no guarantee that copies do not exist. */
export function zero(...bs: (Uint8Array | undefined)[]): void {
  for (const b of bs) b?.fill(0);
}

export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  // getRandomValues is limited to 65536 bytes per call.
  for (let o = 0; o < n; o += 65536) crypto.getRandomValues(out.subarray(o, Math.min(n, o + 65536)));
  return out;
}
