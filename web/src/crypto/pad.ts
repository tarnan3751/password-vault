/**
 * Append ASCII spaces until the length is a non-zero multiple of n
 * (crypto.md §5). Empty input becomes n spaces.
 */
export function pad(b: Uint8Array, n: number): Uint8Array {
  if (!(n > 0)) throw new Error('pad: n must be positive');
  let target = Math.ceil(b.length / n) * n;
  if (target === 0) target = n;
  const out = new Uint8Array(target).fill(0x20);
  out.set(b);
  return out;
}
