package audit

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func appendEvents(t *testing.T, s *Store, source string, count int, payloadPrefix string) {
	t.Helper()
	for i := 1; i <= count; i++ {
		_, err := s.Append(Event{
			ID:         payloadPrefix + "-" + source + "-" + time.Unix(int64(i), 0).UTC().Format("150405"),
			Source:     source,
			Type:       "note",
			OccurredAt: time.Unix(int64(1700000000+i), 0).UTC(),
			Payload:    []byte(payloadPrefix),
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

// Full process: save, close, reopen, seal, narrow per recipient, verify each
// recipient's visible window, merge supplementary disclosures, and reject
// conflicting or cross-seal merges.
func TestDisclosureLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	appendEvents(t, store, "camera-a", 8, "v1")
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: the investigation material survives a restart.
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := len(reopened.QuerySource("camera-a")); got != 8 {
		t.Fatalf("reopened store has %d records, want 8", got)
	}

	summary, err := reopened.Seal("camera-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySealedFile(path, *summary); err != nil {
		t.Fatalf("sealed file must verify: %v", err)
	}

	// One verified investigation material covering seq 1-8.
	parent, err := reopened.BuildRangeProof("camera-a", 1, 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRangeProof(*summary, *parent); err != nil {
		t.Fatal(err)
	}

	// Narrow for two recipients with different windows.
	alice, err := NarrowDisclosure(*summary, *parent, "alice", 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NarrowDisclosure(*summary, *parent, "bob", 5, 8)
	if err != nil {
		t.Fatal(err)
	}
	if alice.SealID != summary.ID() || alice.ParentStart != 1 || alice.ParentEnd != 8 {
		t.Fatalf("narrowed disclosure must name its inherited seal basis and parent window: %+v", alice)
	}
	if err := VerifyDisclosure(*summary, *alice); err != nil {
		t.Fatalf("alice window must verify: %v", err)
	}
	if err := VerifyDisclosure(*summary, *bob); err != nil {
		t.Fatalf("bob window must verify: %v", err)
	}
	if len(alice.Records) != 3 || alice.Records[0].Seq != 2 || alice.Records[2].Seq != 4 {
		t.Fatalf("alice sees exactly seq 2-4: %+v", alice.Records)
	}
	if len(bob.Records) != 4 || bob.Records[0].Seq != 5 || bob.Records[3].Seq != 8 {
		t.Fatalf("bob sees exactly seq 5-8: %+v", bob.Records)
	}

	// Narrowing beyond the verified parent range is refused.
	if _, err := NarrowDisclosure(*summary, *parent, "alice", 4, 9); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("narrowing past the parent range must fail, got %v", err)
	}

	// Supplementary evidence for alice: adjacent window 5-6, then an
	// overlapping window 3-5. Overlaps are counted once.
	supp1, err := NarrowDisclosure(*summary, *parent, "alice", 5, 6)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := MergeDisclosures(*alice, *supp1)
	if err != nil {
		t.Fatalf("adjacent merge: %v", err)
	}
	supp2, err := NarrowDisclosure(*summary, *parent, "alice", 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	merged, err = MergeDisclosures(*merged, *supp2)
	if err != nil {
		t.Fatalf("overlapping merge: %v", err)
	}
	if merged.StartSeq != 2 || merged.EndSeq != 6 || len(merged.Records) != 5 {
		t.Fatalf("merged window must be seq 2-6 with 5 unique records, got %d-%d len %d",
			merged.StartSeq, merged.EndSeq, len(merged.Records))
	}
	if err := VerifyDisclosure(*summary, *merged); err != nil {
		t.Fatalf("merged disclosure must verify: %v", err)
	}

	// Conflicting overlap: same seq, different content. Both materials are
	// kept; the merge is refused.
	forged := *supp2
	forged.Records = append([]Record(nil), supp2.Records...)
	forged.Records[0].Event.Payload = []byte("tampered")
	if _, err := MergeDisclosures(*alice, forged); err == nil {
		t.Fatal("conflicting overlap must be refused")
	} else {
		var conflict *DisclosureConflictError
		if !errors.As(err, &conflict) || conflict.Seq != 3 {
			t.Fatalf("want conflict at seq 3, got %v", err)
		}
	}
	if err := VerifyDisclosure(*summary, *alice); err != nil {
		t.Fatalf("original disclosure must remain intact after refused merge: %v", err)
	}

	// A different seal under the same source name must not mix.
	store2, err := Open(filepath.Join(t.TempDir(), "other.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	appendEvents(t, store2, "camera-a", 8, "v2")
	summary2, err := store2.Seal("camera-a")
	if err != nil {
		t.Fatal(err)
	}
	parent2, err := store2.BuildRangeProof("camera-a", 1, 8)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NarrowDisclosure(*summary2, *parent2, "alice", 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MergeDisclosures(*alice, *other); !errors.Is(err, ErrDisclosureMismatch) {
		t.Fatalf("same source name under a different seal must not merge, got %v", err)
	}

	// Different recipients (disclosure permissions) must not mix either.
	if _, err := MergeDisclosures(*alice, *bob); !errors.Is(err, ErrDisclosureMismatch) {
		t.Fatalf("different recipients must not merge, got %v", err)
	}

	// A recipient cannot be shown a window against the wrong seal.
	if err := VerifyDisclosure(*summary2, *alice); err == nil {
		t.Fatal("disclosure verified against a foreign seal must fail")
	}
}

// A recipient's window never reports invisible records as missing.
func TestDisclosureInvisibleRangeNotMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	appendEvents(t, store, "sensor", 10, "v1")
	summary, err := store.Seal("sensor")
	if err != nil {
		t.Fatal(err)
	}
	parent, err := store.BuildRangeProof("sensor", 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	narrow, err := NarrowDisclosure(*summary, *parent, "carol", 4, 6)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDisclosure(*summary, *narrow); err != nil {
		t.Fatalf("window 4-6 of a 10-record seal must verify without records 1-3 and 7-10: %v", err)
	}
	// But a gap inside the recipient's own window is reported.
	gapped := *narrow
	gapped.Records = append(gapped.Records[:1], gapped.Records[2:]...)
	gapped.MerkleSteps = append(gapped.MerkleSteps[:1], gapped.MerkleSteps[2:]...)
	err = VerifyDisclosure(*summary, gapped)
	var tamper *TamperError
	if !errors.As(err, &tamper) || tamper.Kind != TamperMissingRange {
		t.Fatalf("gap inside the visible window must be reported as missing_range, got %v", err)
	}
}
