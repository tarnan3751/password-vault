package vaultcrypto

// Pad appends ASCII spaces (0x20) to b until its length is a non-zero
// multiple of n (crypto.md §5). A non-empty input whose length is already a
// multiple of n is returned unchanged; the empty input becomes n spaces. The
// result is always a fresh slice.
func Pad(b []byte, n int) []byte {
	if n <= 0 {
		panic("vaultcrypto: Pad: n must be positive")
	}
	target := (len(b) + n - 1) / n * n
	if target == 0 {
		target = n
	}
	out := make([]byte, target)
	for i := copy(out, b); i < target; i++ {
		out[i] = ' '
	}
	return out
}
