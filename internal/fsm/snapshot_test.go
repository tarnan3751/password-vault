package fsm

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/tarnan3751/password-vault/internal/api"
)

// snapshotRoundTrip checks Snapshot -> Restore -> Snapshot is the identity.
func snapshotRoundTrip(t testing.TB, f *FSM) []byte {
	t.Helper()
	snap, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSnapshot(snap); err != nil {
		t.Fatalf("own snapshot does not validate: %v", err)
	}
	g := New()
	if err := g.Restore(snap); err != nil {
		t.Fatalf("restore own snapshot: %v", err)
	}
	again, _ := g.Snapshot()
	if !bytes.Equal(snap, again) {
		t.Fatal("snapshot is not canonical across restore")
	}
	if g.StateHash() != f.StateHash() || g.Rev() != f.Rev() {
		t.Fatal("restored state differs")
	}
	return snap
}

// richState builds a state exercising every kind of record.
func richState(t testing.TB) *harness {
	h := newHarness(t)
	alice := h.bootstrap(1, "alice")
	bob := h.addUser(alice, 2, "bob")
	carol := h.addUser(alice, 3, "carol")
	vid := h.createVault(alice, 1)
	h.addMember(alice, vid, bob, api.RoleEditor)
	h.addMember(alice, vid, carol, api.RoleViewer)
	for i := 0; i < 5; i++ {
		h.mustOK(bob, &PutItemArgs{VaultID: vid, ItemID: itemID(i), Blob: box(100 + i), KeyEpoch: 1})
	}
	h.mustOK(alice, &RemoveMemberArgs{VaultID: vid, UserID: carol.id})
	h.mustOK(alice, &CreateInviteArgs{InviteHash: inviteHash(77), TTLHours: 5})
	h.mustOK(alice, &CreateInviteArgs{InviteHash: inviteHash(78), TTLHours: 5})
	h.mustOK(alice, &RevokeInviteArgs{InviteID: inviteHash(78)[:16]})
	h.mustOK(alice, &AdminUpdateUserArgs{UserID: carol.id, Disabled: ptr(true)})
	h.do(bob, &DeleteVaultArgs{VaultID: vid}) // a recorded failure
	return h
}

func TestSnapshotRoundTripAndDeterminism(t *testing.T) {
	h1 := richState(t)
	h2 := richState(t)
	s1 := snapshotRoundTrip(t, h1.f)
	s2, _ := h2.f.Snapshot()
	if !bytes.Equal(s1, s2) || h1.f.StateHash() != h2.f.StateHash() {
		t.Fatal("identical command sequences produced different snapshots")
	}
	var doc map[string]any
	if err := json.Unmarshal(s1, &doc); err != nil || doc["format"] != SnapshotFormat || doc["version"] != float64(1) {
		t.Fatalf("snapshot header: %v %v", err, doc["format"])
	}
	// The empty state round-trips too.
	snapshotRoundTrip(t, New())
}

func TestRestoreRejectsGarbageAtomically(t *testing.T) {
	h := richState(t)
	good, _ := h.f.Snapshot()
	before := h.f.StateHash()

	corrupt := func(mut func(d *snapshotDoc)) []byte {
		var d snapshotDoc
		if err := json.Unmarshal(good, &d); err != nil {
			t.Fatal(err)
		}
		mut(&d)
		b, _ := json.Marshal(d)
		return b
	}
	cases := map[string][]byte{
		"empty":            nil,
		"not json":         []byte("{"),
		"trailing":         append(append([]byte{}, good...), '1'),
		"unknown field":    []byte(strings.Replace(string(good), `"rev":`, `"bogus":1,"rev":`, 1)),
		"wrong format":     corrupt(func(d *snapshotDoc) { d.Format = "other" }),
		"wrong version":    corrupt(func(d *snapshotDoc) { d.Version = 2 }),
		"short key":        corrupt(func(d *snapshotDoc) { d.ClusterKey = []byte{1} }),
		"unsorted users":   corrupt(func(d *snapshotDoc) { d.Users[0], d.Users[1] = d.Users[1], d.Users[0] }),
		"dup username":     corrupt(func(d *snapshotDoc) { d.Users[1].Username = d.Users[0].Username }),
		"bad username":     corrupt(func(d *snapshotDoc) { d.Users[0].Username = "Alice" }),
		"weak verifier":    corrupt(func(d *snapshotDoc) { d.Users[0].Verifier.MemoryKiB = 1 << 30 }),
		"zero epoch":       corrupt(func(d *snapshotDoc) { d.Users[0].TokenEpoch = 0 }),
		"invite hash":      corrupt(func(d *snapshotDoc) { d.Invites[0].Hash = strings.Repeat("f", 64) }),
		"invite creator":   corrupt(func(d *snapshotDoc) { d.Invites[0].CreatedBy = userID(99) }),
		"invite user":      corrupt(func(d *snapshotDoc) { d.Invites[0].UsedBy = userID(99) }),
		"vault no owner":   corrupt(func(d *snapshotDoc) { setRoles(d, api.RoleViewer) }),
		"bad role":         corrupt(func(d *snapshotDoc) { setRoles(d, "root") }),
		"vault rev":        corrupt(func(d *snapshotDoc) { d.Vaults[0].Rev = d.Rev + 1 }),
		"item version":     corrupt(func(d *snapshotDoc) { firstWithItems(d).Items[0].Version = d.Rev + 1 }),
		"item blob":        corrupt(func(d *snapshotDoc) { firstWithItems(d).Items[0].Blob = []byte{1} }),
		"unsorted items":   corrupt(func(d *snapshotDoc) { v := firstWithItems(d); v.Items[0], v.Items[1] = v.Items[1], v.Items[0] }),
		"no roster":        corrupt(func(d *snapshotDoc) { d.Vaults[0].EncRoster = nil }),
		"huge roster":      corrupt(func(d *snapshotDoc) { d.Vaults[0].EncRoster = box(MaxRosterBytes + 1) }),
		"roster version":   corrupt(func(d *snapshotDoc) { d.Vaults[0].RosterVersion = 0 }),
		"roster future":    corrupt(func(d *snapshotDoc) { d.Vaults[0].RosterVersion = d.Vaults[0].Rev + 1 }),
		"bad stored kdf":   corrupt(func(d *snapshotDoc) { d.Users[0].KDF.Alg = "scrypt" }),
		"wrapped key size": corrupt(func(d *snapshotDoc) { d.Vaults[0].Members[0].WrappedKey.Blob = box(10) }),
		"member unknown":   corrupt(func(d *snapshotDoc) { d.Vaults[0].Members[0].AddedBy = userID(99) }),
		"personal shared":  corrupt(func(d *snapshotDoc) { sharePersonal(d) }),
		"missing personal": corrupt(func(d *snapshotDoc) { dropPersonal(d) }),
		"idem key":         corrupt(func(d *snapshotDoc) { d.Idempotency[0].Key = "x" }),
		"idem dup":         corrupt(func(d *snapshotDoc) { d.Idempotency[1].Key = d.Idempotency[0].Key }),
		"idem result":      corrupt(func(d *snapshotDoc) { d.Idempotency[0].Result = []byte(`{"ok":{},"err":{"code":"x"}}`) }),
		"idem binding":     corrupt(func(d *snapshotDoc) { d.Idempotency[0].Binding = "" }),
		"too many idem": corrupt(func(d *snapshotDoc) {
			for len(d.Idempotency) <= IdempotencyCapacity {
				e := d.Idempotency[0]
				e.Key = "anon:" + hexID(0x77, len(d.Idempotency))
				d.Idempotency = append(d.Idempotency, e)
			}
		}),
	}
	for name, data := range cases {
		if err := ValidateSnapshot(data); err == nil {
			t.Errorf("%s: ValidateSnapshot accepted garbage", name)
		}
		if err := h.f.Restore(data); err == nil {
			t.Errorf("%s: Restore accepted garbage", name)
		}
		if h.f.StateHash() != before {
			t.Fatalf("%s: failed Restore modified the state", name)
		}
	}
}

func setRoles(d *snapshotDoc, role string) {
	for i := range d.Vaults {
		if !d.Vaults[i].Personal {
			for j := range d.Vaults[i].Members {
				d.Vaults[i].Members[j].Role = role
			}
			return
		}
	}
}

func firstWithItems(d *snapshotDoc) *snapVault {
	for i := range d.Vaults {
		if len(d.Vaults[i].Items) > 1 {
			return &d.Vaults[i]
		}
	}
	panic("no vault with items")
}

func sharePersonal(d *snapshotDoc) {
	for i := range d.Vaults {
		if d.Vaults[i].Personal {
			other := d.Users[0].ID
			if other == d.Vaults[i].Creator {
				other = d.Users[1].ID
			}
			m := d.Vaults[i].Members[0]
			m.UserID = other
			d.Vaults[i].Members = append(d.Vaults[i].Members, m)
			if d.Vaults[i].Members[0].UserID > d.Vaults[i].Members[1].UserID {
				d.Vaults[i].Members[0], d.Vaults[i].Members[1] = d.Vaults[i].Members[1], d.Vaults[i].Members[0]
			}
			return
		}
	}
}

func dropPersonal(d *snapshotDoc) {
	for i := range d.Vaults {
		if d.Vaults[i].Personal {
			d.Vaults = append(d.Vaults[:i], d.Vaults[i+1:]...)
			return
		}
	}
}

// referenceSnapshot is how snapshots were encoded before encodeSnapshot:
// json.Marshal of the document. The bytes (and StateHash) must not change.
func referenceSnapshot(s *state, withKey bool) []byte {
	b, err := json.Marshal(s.doc(withKey))
	if err != nil {
		panic(err)
	}
	return b
}

func encodeSnapshot(f *FSM, withKey bool) []byte {
	b, _ := f.snapshot(withKey)
	return b
}

func checkEncoder(t testing.TB, f *FSM) {
	t.Helper()
	for _, withKey := range []bool{true, false} {
		if got, want := encodeSnapshot(f, withKey), referenceSnapshot(f.s, withKey); !bytes.Equal(got, want) {
			i := 0
			for i < len(got) && i < len(want) && got[i] == want[i] {
				i++
			}
			t.Fatalf("snapshot encoding differs from encoding/json at byte %d:\ngot  %.120q\nwant %.120q", i, got[i:], want[i:])
		}
	}
	if f.StateHash() != sha256.Sum256(referenceSnapshot(f.s, true)) {
		t.Fatal("StateHash differs from the hash of the encoding/json encoding")
	}
}

func TestSnapshotEncoderMatchesEncodingJSON(t *testing.T) {
	checkEncoder(t, New())
	h := richState(t)
	checkEncoder(t, h.f)
	// Values no command can store (Apply validates them), to show that the
	// encoder still agrees: strings that need escaping, nil and empty byte
	// slices, extreme numbers, a bigger buffer than the size hint.
	for _, u := range h.f.s.users {
		u.Username = "a<b>&\"\\\x01\x7f é\u2028\xff"
		u.KDF.Salt = nil
		u.PublicKey = []byte{}
		u.CreatedAt = -1 << 63
		u.TokenEpoch = 1<<64 - 1
		break
	}
	for _, inv := range h.f.s.invites {
		inv.UsedBy = "\t"
	}
	for _, v := range h.f.s.vaults {
		v.EncMeta = box(1 << 20)
		v.bytes = 0
		for _, m := range v.Members {
			m.Role = "<owner>"
		}
	}
	checkEncoder(t, h.f)
	// Large states (every shape the benchmarks use).
	checkEncoder(t, benchFSM(t, benchShapes[0]))
	checkEncoder(t, benchFSM(t, benchShapes[3]))
}

// checkDecoder requires that whenever the canonical decoder accepts data,
// encoding/json accepts it too and decodes the same document.
func checkDecoder(t testing.TB, data []byte, wantFast bool) {
	t.Helper()
	fast, ok := decodeCanonical(data)
	if ok != wantFast && wantFast {
		t.Fatalf("canonical decoder refused a canonical snapshot (%.80q...)", data)
	}
	if !ok {
		return
	}
	var slow snapshotDoc
	if err := strictUnmarshal(data, &slow); err != nil {
		t.Fatalf("canonical decoder accepted what encoding/json refuses (%v): %.200q", err, data)
	}
	if !reflect.DeepEqual(*fast, slow) {
		t.Fatalf("canonical decoder and encoding/json disagree on %.200q", data)
	}
}

func TestSnapshotDecoderMatchesEncodingJSON(t *testing.T) {
	h := richState(t)
	snap, _ := h.f.Snapshot()
	backup, _, _ := h.f.BackupSnapshot()
	empty, _ := New().Snapshot()
	big, _ := benchFSM(t, benchShapes[0]).Snapshot()
	for _, s := range [][]byte{snap, backup, empty, big} {
		checkDecoder(t, s, true)
	}
	// Not canonical: the fast path must step aside (or agree exactly).
	var d snapshotDoc
	if err := json.Unmarshal(snap, &d); err != nil {
		t.Fatal(err)
	}
	indented, _ := json.MarshalIndent(d, "", " ")
	r := strings.NewReplacer
	for name, data := range map[string][]byte{
		"indented":       indented,
		"trailing space": append(append([]byte(nil), snap...), ' '),
		"trailing data":  append(append([]byte(nil), snap...), "{}"...),
		"truncated":      snap[:len(snap)-1],
		"key case":       []byte(r(`"rev":`, `"REV":`).Replace(string(snap))),
		"escape":         []byte(r(`"alice"`, `"\u0061lice"`).Replace(string(snap))),
		"null list":      []byte(r(`"invites":[`, `"invites":null,"x":[`).Replace(string(empty))),
		"null users":     []byte(`{"format":"fpv-state","version":1,"rev":0,"users":null,"invites":[],"vaults":[],"idempotency":[]}`),
		"empty bytes":    []byte(r(`"cluster_key":"`, `"cluster_key":"","x":"`).Replace(string(snap))),
		"base64 newline": []byte(r(`"blob":"A`, `"blob":"\r\nA`).Replace(string(snap))),
		"negative zero":  []byte(r(`"created_at":`, `"created_at":-0`).Replace(string(snap))),
		"leading zero":   []byte(r(`"rev":`, `"rev":0`).Replace(string(snap))),
		"float":          []byte(r(`"token_epoch":1`, `"token_epoch":1.0`).Replace(string(snap))),
		"big epoch":      []byte(r(`"key_epoch":1`, `"key_epoch":99999999999`).Replace(string(snap))),
		"big parallel":   []byte(r(`"parallelism":4`, `"parallelism":256`).Replace(string(snap))),
		"min int":        []byte(r(`"created_at":`, `"created_at":-9223372036854775808`).Replace(string(snap))),
		"under int":      []byte(r(`"created_at":`, `"created_at":-9223372036854775809`).Replace(string(snap))),
		"bool case":      []byte(r(`"disabled":false`, `"disabled":False`).Replace(string(snap))),
	} {
		t.Run(name, func(t *testing.T) { checkDecoder(t, data, false) })
	}
}

func TestBackupSnapshotOmitsClusterKey(t *testing.T) {
	h := richState(t)
	snap, rev, err := h.f.BackupSnapshot()
	if err != nil || rev != h.f.Rev() {
		t.Fatalf("backup: %v rev=%d", err, rev)
	}
	var d snapshotDoc
	if err := json.Unmarshal(snap, &d); err != nil || len(d.ClusterKey) != 0 {
		t.Fatal("backup snapshot contains the cluster key")
	}
	if bytes.Contains(snap, []byte(`"cluster_key"`)) {
		t.Fatal("backup mentions cluster_key")
	}
	if err := ValidateSnapshot(snap); err != nil {
		t.Fatalf("backup snapshot invalid: %v", err)
	}
	// A cluster seeded from it has users but must be initialized again
	// before anything else is accepted.
	g := New()
	if err := g.Restore(snap); err != nil {
		t.Fatal(err)
	}
	if g.Initialized() || !g.HasUsers() {
		t.Fatal("restored backup: expected users and no cluster key")
	}
	gh := &harness{t: t, f: g, now: h.now, seq: 100000}
	ua, _ := g.LookupUserByName("alice")
	alice := &tuser{id: ua.ID, ep: ua.TokenEpoch}
	gh.mustErr(alice, &RevokeSessionsArgs{}, api.CodeUnavailable)
	gh.mustOK(nil, &InitArgs{ClusterKey: bytes.Repeat([]byte{9}, 32)})
	gh.mustOK(alice, &RevokeSessionsArgs{})
}

func TestRestoreAcceptsOldKDFPolicy(t *testing.T) {
	// KDF bounds are policy for new writes; a state written under older,
	// looser bounds must still restore.
	h := richState(t)
	snap, _ := h.f.Snapshot()
	var d snapshotDoc
	if err := json.Unmarshal(snap, &d); err != nil {
		t.Fatal(err)
	}
	d.Users[0].KDF.Time, d.Users[0].KDF.MemoryKiB, d.Users[0].KDF.Parallelism = 2, 19456, 1
	old, _ := json.Marshal(d)
	if err := ValidateSnapshot(old); err != nil {
		t.Fatalf("state with old KDF parameters rejected: %v", err)
	}
	if err := ValidateKDF(d.Users[0].KDF); err == nil {
		t.Fatal("old parameters must be refused for new writes")
	}
}
