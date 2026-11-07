//go:build race

package fsm

// raceEnabled shortens the single-goroutine property tests under -race: the
// detector slows them ~25x and finds nothing there (concurrency is covered
// by TestConcurrentReadersDuringApply). The full versions run without -race.
const raceEnabled = true
