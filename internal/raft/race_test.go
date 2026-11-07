//go:build race

package raft_test

// The race detector slows large memory-bound operations (JSON decoding of a
// 48 MiB command takes ~40x longer), which some tests scale down for.
const raceEnabled = true
