package raft

// Test-only key/value state machine and its Porcupine model. The names are
// exported so that the external test package (raft_test, which can import
// memnet) can use them as well.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/anishathalye/porcupine"
)

// KVCommand is a write against KVStore. ID makes it idempotent: a command
// that is applied twice (raft is at-least-once) takes effect once.
type KVCommand struct {
	ID    uint64 `json:"id"`
	Op    string `json:"op"` // "put", "append", "cas"
	Key   string `json:"k"`
	Value string `json:"v"`
	Old   string `json:"o,omitempty"` // cas: expected current value
}

// KVResult is the result of applying a KVCommand.
type KVResult struct {
	OK bool `json:"ok"` // cas: whether it swapped; always true otherwise
}

func EncodeKV(c KVCommand) []byte {
	b, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	return b
}

func DecodeKVResult(b []byte) (KVResult, error) {
	var r KVResult
	err := json.Unmarshal(b, &r)
	return r, err
}

const kvDedupWindow = 1024

// KVStore implements StateMachine. It also checks the StateMachine contract
// (strictly increasing Apply indices) and records violations.
type KVStore struct {
	mu        sync.Mutex
	data      map[string]string
	seen      map[uint64][]byte
	seenOrder []uint64
	lastIndex uint64
	violation string
}

func NewKVStore() *KVStore {
	return &KVStore{data: map[string]string{}, seen: map[uint64][]byte{}}
}

func (s *KVStore) Apply(index uint64, cmd []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index <= s.lastIndex && s.violation == "" {
		s.violation = fmt.Sprintf("Apply(%d) after Apply(%d)", index, s.lastIndex)
	}
	s.lastIndex = index
	var c KVCommand
	if err := json.Unmarshal(cmd, &c); err != nil {
		return nil
	}
	if r, ok := s.seen[c.ID]; ok {
		return r
	}
	res := KVResult{OK: true}
	switch c.Op {
	case "put":
		s.data[c.Key] = c.Value
	case "append":
		s.data[c.Key] += c.Value
	case "cas":
		if s.data[c.Key] == c.Old {
			s.data[c.Key] = c.Value
		} else {
			res.OK = false
		}
	}
	out, _ := json.Marshal(res)
	s.seen[c.ID] = out
	s.seenOrder = append(s.seenOrder, c.ID)
	if len(s.seenOrder) > kvDedupWindow {
		delete(s.seen, s.seenOrder[0])
		s.seenOrder = s.seenOrder[1:]
	}
	return out
}

type kvSnapshot struct {
	Data      map[string]string `json:"data"`
	SeenIDs   []uint64          `json:"ids"`
	SeenRes   [][]byte          `json:"res"`
	LastIndex uint64            `json:"last"`
}

func (s *KVStore) Snapshot() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := kvSnapshot{Data: s.data, LastIndex: s.lastIndex}
	for _, id := range s.seenOrder {
		snap.SeenIDs = append(snap.SeenIDs, id)
		snap.SeenRes = append(snap.SeenRes, s.seen[id])
	}
	return json.Marshal(snap)
}

func (s *KVStore) Restore(b []byte) error {
	var snap kvSnapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = snap.Data
	if s.data == nil {
		s.data = map[string]string{}
	}
	s.seen = map[uint64][]byte{}
	s.seenOrder = nil
	for i, id := range snap.SeenIDs {
		s.seen[id] = snap.SeenRes[i]
		s.seenOrder = append(s.seenOrder, id)
	}
	s.lastIndex = snap.LastIndex
	return nil
}

func (s *KVStore) Get(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[key]
}

// Dump returns the contents in a canonical form for comparisons.
func (s *KVStore) Dump() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.data))
	for k := range s.data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%q;", k, s.data[k])
	}
	return b.String()
}

// Violation reports a StateMachine contract violation, if any.
func (s *KVStore) Violation() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.violation
}

// KVInput / KVOutput are the Porcupine operation types. A write whose outcome
// is unknown is recorded with Unknown set and Return = math.MaxInt64: it may
// take effect at any point after its call, or (equivalently, for an op whose
// effect is never observed) not at all.
type KVInput struct {
	Op    string // "get", "put", "append", "cas"
	Key   string
	Value string
	Old   string
}

type KVOutput struct {
	Value   string // get
	OK      bool   // cas
	Unknown bool
}

var KVModel = porcupine.Model{
	Partition: func(history []porcupine.Operation) [][]porcupine.Operation {
		byKey := map[string][]porcupine.Operation{}
		var keys []string
		for _, op := range history {
			k := op.Input.(KVInput).Key
			if _, ok := byKey[k]; !ok {
				keys = append(keys, k)
			}
			byKey[k] = append(byKey[k], op)
		}
		sort.Strings(keys)
		out := make([][]porcupine.Operation, 0, len(keys))
		for _, k := range keys {
			out = append(out, byKey[k])
		}
		return out
	},
	Init: func() any { return "" },
	Step: func(state, input, output any) (bool, any) {
		st := state.(string)
		in := input.(KVInput)
		out := output.(KVOutput)
		switch in.Op {
		case "get":
			return out.Unknown || out.Value == st, st
		case "put":
			return true, in.Value
		case "append":
			return true, st + in.Value
		case "cas":
			if st == in.Old {
				return out.Unknown || out.OK, in.Value
			}
			return out.Unknown || !out.OK, st
		}
		return false, st
	},
	Equal: func(a, b any) bool { return a.(string) == b.(string) },
	DescribeOperation: func(input, output any) string {
		in := input.(KVInput)
		out := output.(KVOutput)
		res := ""
		switch {
		case out.Unknown:
			res = "?"
		case in.Op == "get":
			res = fmt.Sprintf("%q", out.Value)
		case in.Op == "cas":
			res = fmt.Sprint(out.OK)
		default:
			res = "ok"
		}
		switch in.Op {
		case "cas":
			return fmt.Sprintf("cas(%s, %q->%q) -> %s", in.Key, in.Old, in.Value, res)
		case "get":
			return fmt.Sprintf("get(%s) -> %s", in.Key, res)
		}
		return fmt.Sprintf("%s(%s, %q) -> %s", in.Op, in.Key, in.Value, res)
	},
	DescribeState: func(state any) string { return fmt.Sprintf("%q", state) },
}
