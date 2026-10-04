package audit

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func rediscloseFixture(t *testing.T) (*SealSummary, Disclosure, Authorization) {
	t.Helper()
	store, err := Open(t.TempDir() + "/audit.log")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	types := []string{"read", "write", "read", "admin", "read", "write"}
	for i, eventType := range types {
		if _, err := store.Append(Event{
			ID:         "evt-" + string(rune('a'+i)),
			Source:     "billing",
			Type:       eventType,
			OccurredAt: base.Add(time.Duration(i) * time.Minute),
			Payload:    []byte{byte(i + 1)},
		}); err != nil {
			t.Fatal(err)
		}
	}
	summary, err := store.Seal("billing")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := store.BuildRangeProof("billing", 1, 6)
	if err != nil {
		t.Fatal(err)
	}
	held, err := NarrowDisclosure(*summary, *proof, "auditor-a", 2, 5)
	if err != nil {
		t.Fatal(err)
	}
	auth := Authorization{
		ID:            "auth-1",
		SealID:        summary.ID(),
		Source:        "billing",
		Grantor:       "owner",
		Recipient:     "auditor-a",
		StartSeq:      2,
		EndSeq:        5,
		AllowDelegate: true,
		IssuedAt:      base,
	}
	return summary, *held, auth
}

func subAuth(auth Authorization, id, recipient string, start, end uint64) Authorization {
	return Authorization{
		ID:        id,
		SealID:    auth.SealID,
		Source:    auth.Source,
		Grantor:   auth.Recipient,
		Recipient: recipient,
		StartSeq:  start,
		EndSeq:    end,
		IssuedAt:  auth.IssuedAt.Add(time.Hour),
	}
}

func TestRediscloseDerivesSubsetWithInheritedBasis(t *testing.T) {
	summary, held, auth := rediscloseFixture(t)
	sub := subAuth(auth, "auth-1.1", "auditor-b", 3, 4)
	derived, err := Redisclose(*summary, auth, sub, held, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	if derived.SealID != summary.ID() || derived.AuthID != "auth-1.1" {
		t.Fatalf("derived material must name its seal and authorization, got seal %q auth %q", derived.SealID, derived.AuthID)
	}
	if derived.Recipient != "auditor-b" || derived.StartSeq != 3 || derived.EndSeq != 4 {
		t.Fatalf("unexpected derived window: %+v", derived)
	}
	if derived.ParentStart != held.StartSeq || derived.ParentEnd != held.EndSeq {
		t.Fatalf("derived material must record the parent window it was narrowed from")
	}
	if err := VerifyDisclosure(*summary, *derived); err != nil {
		t.Fatalf("derived disclosure must verify against the seal summary: %v", err)
	}
}

func TestRediscloseRejectsCrossingBoundaries(t *testing.T) {
	summary, held, auth := rediscloseFixture(t)

	// Beyond the sub-authorization range.
	sub := subAuth(auth, "auth-1.1", "auditor-b", 3, 4)
	if _, err := Redisclose(*summary, auth, sub, held, 3, 5); !errors.Is(err, ErrUnauthorizedScope) {
		t.Fatalf("range outside the sub-authorization must be unauthorized, got %v", err)
	}
	// Beyond the held authorization even though the sub-auth claims it.
	wide := subAuth(auth, "auth-1.2", "auditor-b", 2, 6)
	if _, err := Redisclose(*summary, auth, wide, held, 2, 6); !errors.Is(err, ErrUnauthorizedScope) {
		t.Fatalf("sub-authorization wider than the held grant must fail, got %v", err)
	}
	// Within the authorization but outside the window the holder can see.
	narrowHeld, err := NarrowDisclosureForTest(summary, held)
	if err != nil {
		t.Fatal(err)
	}
	sub2 := subAuth(auth, "auth-1.3", "auditor-b", 2, 2)
	if _, err := Redisclose(*summary, auth, sub2, *narrowHeld, 2, 2); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("range invisible to the holder must be an invalid-range error, got %v", err)
	}
	// Delegation not permitted.
	noDelegate := auth
	noDelegate.AllowDelegate = false
	if _, err := Redisclose(*summary, noDelegate, sub, held, 3, 4); !errors.Is(err, ErrUnauthorizedScope) {
		t.Fatalf("delegation without permission must fail, got %v", err)
	}
	// Authorization bound to a different recipient or seal must not apply.
	stranger := auth
	stranger.Recipient = "auditor-x"
	if _, err := Redisclose(*summary, stranger, sub, held, 3, 4); !errors.Is(err, ErrUnauthorizedScope) {
		t.Fatalf("authorization of another recipient must not justify this disclosure, got %v", err)
	}
}

// NarrowDisclosureForTest derives a smaller held window (3-4) from the
// fixture's 2-5 disclosure by re-narrowing through the store proof.
func NarrowDisclosureForTest(summary *SealSummary, held Disclosure) (*Disclosure, error) {
	proof := RangeProof{
		Version:       2,
		Source:        held.Source,
		StartSeq:      held.StartSeq,
		EndSeq:        held.EndSeq,
		SealedCount:   held.SealedCount,
		FirstPrevious: held.FirstPrevious,
		Records:       held.Records,
		MerkleSteps:   held.MerkleSteps,
	}
	return NarrowDisclosure(*summary, proof, held.Recipient, 3, 4)
}

func TestRediscloseContentScope(t *testing.T) {
	summary, held, auth := rediscloseFixture(t)
	auth.Content = ContentScope{Types: []string{"read", "write"}}

	// Sub-authorization widening the visible content is refused.
	wider := subAuth(auth, "auth-c1", "auditor-b", 2, 5)
	if _, err := Redisclose(*summary, auth, wider, held, 2, 5); !errors.Is(err, ErrUnauthorizedScope) {
		t.Fatalf("content scope wider than the held grant must fail, got %v", err)
	}
	// A window containing a non-visible record type is refused and the error
	// names only the sequence number, never the record content.
	sub := subAuth(auth, "auth-c2", "auditor-b", 2, 5)
	sub.Content = ContentScope{Types: []string{"read"}}
	_, err := Redisclose(*summary, auth, sub, held, 2, 5)
	if !errors.Is(err, ErrUnauthorizedScope) {
		t.Fatalf("window with an invisible record type must fail, got %v", err)
	}
	var unauth *UnauthorizedError
	if !errors.As(err, &unauth) {
		t.Fatalf("expected UnauthorizedError, got %T", err)
	}
	if unauth.StartSeq != 2 {
		t.Fatalf("error must name the first invisible sequence number 2, got %d", unauth.StartSeq)
	}
	if strings.Contains(err.Error(), "write") || strings.Contains(err.Error(), "evt-") {
		t.Fatalf("error must not leak record content: %v", err)
	}
	// A window covering only visible records succeeds.
	derived, err := Redisclose(*summary, auth, sub, held, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDisclosure(*summary, *derived); err != nil {
		t.Fatal(err)
	}
}

func TestMergeDisclosuresRejectsDifferentAuthorizations(t *testing.T) {
	summary, held, auth := rediscloseFixture(t)
	subA := subAuth(auth, "auth-m1", "auditor-b", 2, 3)
	subB := subAuth(auth, "auth-m2", "auditor-b", 4, 5)
	left, err := Redisclose(*summary, auth, subA, held, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Redisclose(*summary, auth, subB, held, 4, 5)
	if err != nil {
		t.Fatal(err)
	}
	// Adjacent windows under different authorizations look mergeable but
	// must not silently combine into a wider permission.
	if _, err := MergeDisclosures(*left, *right); !errors.Is(err, ErrDisclosureMismatch) {
		t.Fatalf("merging across authorizations must be refused, got %v", err)
	}
	// Same authorization, adjacent windows: merges as before.
	right.AuthID = left.AuthID
	merged, err := MergeDisclosures(*left, *right)
	if err != nil {
		t.Fatal(err)
	}
	if merged.StartSeq != 2 || merged.EndSeq != 5 || merged.AuthID != left.AuthID {
		t.Fatalf("unexpected merge result: %+v", merged)
	}
	if err := VerifyDisclosure(*summary, *merged); err != nil {
		t.Fatal(err)
	}
}
