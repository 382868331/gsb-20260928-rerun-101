package audit

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestRangeProofSetVerifiesIndependentSources(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.AppendBatch([]Event{
		newEvent("a-1", "alpha"), newEvent("b-1", "beta"),
		newEvent("a-2", "alpha"), newEvent("b-2", "beta"),
		newEvent("a-3", "alpha"), newEvent("a-4", "alpha"),
	}); err != nil {
		t.Fatal(err)
	}
	alphaSeal, err := store.Seal("alpha")
	if err != nil {
		t.Fatal(err)
	}
	betaSeal, err := store.Seal("beta")
	if err != nil {
		t.Fatal(err)
	}
	alphaProof, err := store.BuildRangeProof("alpha", 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	betaProof, err := store.BuildRangeProof("beta", 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRangeProofSet([]SealSummary{*alphaSeal, *betaSeal}, []RangeProof{*alphaProof, *betaProof}); err != nil {
		t.Fatalf("valid multi-source proof set failed: %v", err)
	}
}

func TestRangeProofSetReportsGapsAndStrays(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.AppendBatch([]Event{newEvent("a-1", "alpha"), newEvent("b-1", "beta")}); err != nil {
		t.Fatal(err)
	}
	alphaSeal, err := store.Seal("alpha")
	if err != nil {
		t.Fatal(err)
	}
	betaSeal, err := store.Seal("beta")
	if err != nil {
		t.Fatal(err)
	}
	alphaProof, err := store.BuildRangeProof("alpha", 1, 1)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyRangeProofSet(nil, nil); !errors.Is(err, ErrEmptyRangeSet) {
		t.Fatalf("empty set got %v, want ErrEmptyRangeSet", err)
	}
	if err := VerifyRangeProofSet([]SealSummary{*alphaSeal, *betaSeal}, []RangeProof{*alphaProof}); err == nil {
		t.Fatal("declared beta source without proof passed")
	} else {
		assertTamper(t, err, TamperMissingRange, 0)
	}
	stray := RangeProof{Version: 2, Source: "ghost", StartSeq: 1, EndSeq: 1}
	if err := VerifyRangeProofSet([]SealSummary{*alphaSeal}, []RangeProof{*alphaProof, stray}); err == nil {
		t.Fatal("proof without a matching summary passed")
	} else {
		assertTamper(t, err, TamperWrongSource, 0)
	}
}

func TestEmptyRangeHasExplicitConclusion(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.AppendBatch([]Event{newEvent("a-1", "alpha"), newEvent("a-2", "alpha")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BuildRangeProof("alpha", 2, 1); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("empty range build got %v, want ErrInvalidRange", err)
	}
	if _, err := store.BuildRangeProof("alpha", 0, 1); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("zero start build got %v, want ErrInvalidRange", err)
	}
	seal, err := store.Seal("alpha")
	if err != nil {
		t.Fatal(err)
	}
	empty := RangeProof{Version: 2, Source: "alpha", StartSeq: 2, EndSeq: 1, SealedCount: seal.RecordCount}
	assertTamper(t, VerifyRangeProof(*seal, empty), TamperMissingRange, 0)
}

func TestRangeBoundaryInsideSegmentVerifies(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.AppendBatch([]Event{
		newEvent("a-1", "alpha"), newEvent("a-2", "alpha"), newEvent("a-3", "alpha"),
		newEvent("a-4", "alpha"), newEvent("a-5", "alpha"), newEvent("a-6", "alpha"),
	}); err != nil {
		t.Fatal(err)
	}
	seal, err := store.Seal("alpha")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := store.BuildRangeProof("alpha", 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRangeProof(*seal, *proof); err != nil {
		t.Fatalf("mid-segment range failed: %v", err)
	}
	if _, err := store.BuildRangeProof("alpha", 5, 7); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("range past the segment end got %v, want ErrInvalidRange", err)
	}
	over := *proof
	over.EndSeq = 7
	assertTamper(t, VerifyRangeProof(*seal, over), TamperMissingRange, 7)
}

func TestRangeProofSetDetectsWholeSegmentReplacement(t *testing.T) {
	original := openTestStore(t)
	if _, err := original.AppendBatch([]Event{newEvent("a-1", "alpha"), newEvent("a-2", "alpha"), newEvent("b-1", "beta")}); err != nil {
		t.Fatal(err)
	}
	alphaSeal, err := original.Seal("alpha")
	if err != nil {
		t.Fatal(err)
	}
	betaSeal, err := original.Seal("beta")
	if err != nil {
		t.Fatal(err)
	}
	betaProof, err := original.BuildRangeProof("beta", 1, 1)
	if err != nil {
		t.Fatal(err)
	}

	replacement := openTestStore(t)
	if _, err := replacement.AppendBatch([]Event{newEvent("fake-1", "alpha"), newEvent("fake-2", "alpha")}); err != nil {
		t.Fatal(err)
	}
	fakeProof, err := replacement.BuildRangeProof("alpha", 1, 2)
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyRangeProofSet([]SealSummary{*alphaSeal, *betaSeal}, []RangeProof{*fakeProof, *betaProof})
	assertTamper(t, err, TamperRewrite, 1)
}

func TestOldRangeProofStillVerifiesAgainstOldSummary(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.AppendBatch([]Event{newEvent("a-1", "alpha"), newEvent("a-2", "alpha")}); err != nil {
		t.Fatal(err)
	}
	oldSeal, err := store.Seal("alpha")
	if err != nil {
		t.Fatal(err)
	}
	oldProof, err := store.BuildRangeProof("alpha", 1, 2)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.AppendBatch([]Event{newEvent("a-3", "alpha"), newEvent("a-4", "alpha")}); err != nil {
		t.Fatal(err)
	}
	newSeal, err := store.Seal("alpha")
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyRangeProof(*oldSeal, *oldProof); err != nil {
		t.Fatalf("old proof no longer verifies against the old summary: %v", err)
	}
	assertTamper(t, VerifyRangeProof(*newSeal, *oldProof), TamperWrongSource, 0)

	// The new summary must not bless a copy that lost the newer records, and
	// the old summary must not bless a file that grew past its seal.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	frames := splitFrames(t, store.path)
	truncated := filepath.Join(t.TempDir(), "truncated.audit")
	writeFrames(t, truncated, frames[:2])
	assertTamper(t, VerifySealedFile(truncated, *newSeal), TamperTailTruncation, 3)
	assertTamper(t, VerifySealedFile(store.path, *oldSeal), TamperInsertion, 3)
}
