package audit

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestDisclosureSurvivesReopenNarrowAndSupplementMerge(t *testing.T) {
	store := openTestStore(t)
	events := []Event{
		newEvent("a-1", "alpha"), newEvent("a-2", "alpha"), newEvent("a-3", "alpha"),
		newEvent("a-4", "alpha"), newEvent("a-5", "alpha"),
		newEvent("b-1", "beta"),
	}
	if _, err := store.AppendBatch(events); err != nil {
		t.Fatal(err)
	}
	initial, err := store.BuildDisclosure("alpha", 1, 3, DisclosureGrant{Recipient: "lawyer", Permission: "case-a"})
	if err != nil {
		t.Fatal(err)
	}
	if initial.VisibleCount() != 3 || initial.OutsideVisibleCount() != 2 || len(initial.InheritedSeals) != 1 {
		t.Fatalf("initial visible=%d hidden=%d basis=%d", initial.VisibleCount(), initial.OutsideVisibleCount(), len(initial.InheritedSeals))
	}
	encoded, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store = mustOpen(t, store.Path())
	var transferred Disclosure
	if err := json.Unmarshal(encoded, &transferred); err != nil {
		t.Fatal(err)
	}
	narrowed, err := transferred.Narrow(2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := narrowed.VerifyForReceiver(DisclosureGrant{Recipient: "lawyer", Permission: "case-a"}); err != nil {
		t.Fatalf("narrowed material failed receiver verification: %v", err)
	}
	if narrowed.VisibleCount() != 1 || narrowed.OutsideVisibleCount() != 4 {
		t.Fatalf("narrowed visible=%d hidden=%d", narrowed.VisibleCount(), narrowed.OutsideVisibleCount())
	}
	if got := narrowed.Proof.Records[0].Event.ID; got != "a-2" {
		t.Fatalf("narrowed material exposed %q, want a-2", got)
	}
	if err := narrowed.VerifyForReceiver(DisclosureGrant{Recipient: "other", Permission: "case-a"}); !errors.Is(err, ErrDisclosureGrant) {
		t.Fatalf("wrong receiver got %v, want ErrDisclosureGrant", err)
	}
	if _, err := narrowed.Narrow(1, 2); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("widening a narrow material got %v, want ErrInvalidRange", err)
	}

	supplement, err := store.BuildDisclosure("alpha", 4, 5, DisclosureGrant{Recipient: "lawyer", Permission: "case-a"})
	if err != nil {
		t.Fatal(err)
	}
	merged, err := MergeDisclosures(*initial, *supplement)
	if err != nil {
		t.Fatal(err)
	}
	if merged.VisibleCount() != 5 || merged.OutsideVisibleCount() != 0 {
		t.Fatalf("merged visible=%d hidden=%d", merged.VisibleCount(), merged.OutsideVisibleCount())
	}
	if len(merged.Proof.Records) != 5 {
		t.Fatalf("adjacent merge has %d records, want 5", len(merged.Proof.Records))
	}
	if err := merged.Verify(); err != nil {
		t.Fatalf("merged material verification failed: %v", err)
	}
}

func TestOverlappingMergeCountsDuplicateOnce(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.AppendBatch([]Event{
		newEvent("a-1", "alpha"), newEvent("a-2", "alpha"), newEvent("a-3", "alpha"), newEvent("a-4", "alpha"),
	}); err != nil {
		t.Fatal(err)
	}
	left, err := store.BuildDisclosure("alpha", 1, 3, DisclosureGrant{Recipient: "auditor"})
	if err != nil {
		t.Fatal(err)
	}
	right, err := store.BuildDisclosure("alpha", 3, 4, DisclosureGrant{Recipient: "auditor"})
	if err != nil {
		t.Fatal(err)
	}
	merged, err := MergeDisclosures(*left, *right)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Proof.StartSeq != 1 || merged.Proof.EndSeq != 4 || len(merged.Proof.Records) != 4 {
		t.Fatalf("overlap merge range=%d-%d records=%d", merged.Proof.StartSeq, merged.Proof.EndSeq, len(merged.Proof.Records))
	}
}

func TestMergeRejectsDifferentPermissionSealAndGap(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.AppendBatch([]Event{newEvent("a-1", "alpha"), newEvent("a-2", "alpha"), newEvent("a-3", "alpha"), newEvent("a-4", "alpha")}); err != nil {
		t.Fatal(err)
	}
	first, err := store.BuildDisclosure("alpha", 1, 1, DisclosureGrant{Recipient: "r", Permission: "p1"})
	if err != nil {
		t.Fatal(err)
	}
	otherPermission, err := store.BuildDisclosure("alpha", 2, 2, DisclosureGrant{Recipient: "r", Permission: "p2"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MergeDisclosures(*first, *otherPermission); !errors.Is(err, ErrIncompatibleDisclosure) {
		t.Fatalf("different permission merge got %v, want ErrIncompatibleDisclosure", err)
	}
	gap, err := store.BuildDisclosure("alpha", 3, 3, DisclosureGrant{Recipient: "r", Permission: "p1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MergeDisclosures(*first, *gap); !errors.Is(err, ErrIncompatibleDisclosure) {
		t.Fatalf("gap merge got %v, want ErrIncompatibleDisclosure", err)
	}

	otherSealStore := openTestStore(t)
	if _, err := otherSealStore.Append(newEvent("a-1", "alpha")); err != nil {
		t.Fatal(err)
	}
	sameSourceName, err := otherSealStore.BuildDisclosure("alpha", 1, 1, DisclosureGrant{Recipient: "r", Permission: "p1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MergeDisclosures(*first, *sameSourceName); !errors.Is(err, ErrIncompatibleDisclosure) {
		t.Fatalf("same source name with a different seal merged: %v", err)
	}
}

func TestDisclosureKeepsInvisibleRecordsDistinctFromMissingRecords(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.AppendBatch([]Event{
		newEvent("a-1", "alpha"), newEvent("a-2", "alpha"), newEvent("a-3", "alpha"),
	}); err != nil {
		t.Fatal(err)
	}
	disclosure, err := store.BuildDisclosure("alpha", 2, 2, DisclosureGrant{Recipient: "limited"})
	if err != nil {
		t.Fatal(err)
	}
	if disclosure.Proof.SealedCount != 3 || disclosure.VisibleCount() != 1 || disclosure.OutsideVisibleCount() != 2 {
		t.Fatalf("visible scope was not preserved: sealed=%d visible=%d outside=%d", disclosure.Proof.SealedCount, disclosure.VisibleCount(), disclosure.OutsideVisibleCount())
	}

	tampered := copyProof(disclosure.Proof)
	tampered.Records[0].Event.Payload = []byte("changed")
	bad := *disclosure
	bad.Proof = tampered
	assertTamper(t, bad.Verify(), TamperRewrite, 2)
}

func TestOverlappingConflictRejectsMergeAndKeepsBothMaterials(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.AppendBatch([]Event{
		newEvent("a-1", "alpha"), newEvent("a-2", "alpha"), newEvent("a-3", "alpha"),
	}); err != nil {
		t.Fatal(err)
	}
	original, err := store.BuildDisclosure("alpha", 1, 2, DisclosureGrant{Recipient: "auditor"})
	if err != nil {
		t.Fatal(err)
	}
	supplement, err := store.BuildDisclosure("alpha", 2, 3, DisclosureGrant{Recipient: "auditor"})
	if err != nil {
		t.Fatal(err)
	}
	conflicting := *supplement
	conflicting.Proof.Records[0].RecordHash = append([]byte(nil), original.Proof.Records[0].RecordHash...)
	if _, err := MergeDisclosures(*original, conflicting); !errors.Is(err, ErrDisclosureConflict) {
		t.Fatalf("contradictory overlap got %v, want ErrDisclosureConflict", err)
	}
	if len(original.Proof.Records) != 2 || len(conflicting.Proof.Records) != 2 {
		t.Fatal("conflicting inputs were mutated")
	}
}
