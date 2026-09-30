package audit

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"
)

func TestIndependentSourcesKeepSeparateSequences(t *testing.T) {
	store := openTestStore(t)
	events := []Event{
		eventFor("a-1", "source-a", time.Date(2026, 9, 29, 1, 0, 0, 0, time.UTC)),
		eventFor("b-1", "source-b", time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)),
		eventFor("a-2", "source-a", time.Date(2026, 9, 29, 2, 0, 0, 0, time.UTC)),
		eventFor("b-2", "source-b", time.Date(2026, 9, 29, 0, 30, 0, 0, time.UTC)),
	}
	if _, err := store.AppendBatch(events); err != nil {
		t.Fatal(err)
	}

	a := store.QuerySource("source-a")
	b := store.QuerySource("source-b")
	if len(a) != 2 || a[0].Seq != 1 || a[1].Seq != 2 {
		t.Fatalf("source-a sequences = %+v", a)
	}
	if len(b) != 2 || b[0].Seq != 1 || b[1].Seq != 2 {
		t.Fatalf("source-b sequences = %+v", b)
	}
	if bytes.Equal(a[1].PreviousHash, b[0].RecordHash) {
		t.Fatal("source chains were linked through unrelated records")
	}

	sealA, err := store.Seal("source-a")
	if err != nil {
		t.Fatal(err)
	}
	if sealA.RecordCount != 2 || len(sealA.MerkleRoot) != hashLength {
		t.Fatalf("invalid source seal: %+v", sealA)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := VerifySealedFile(store.path, *sealA); err != nil {
		t.Fatalf("source seal should ignore source-b records: %v", err)
	}
}

func TestRangeProofContainsOnlyRequestedRange(t *testing.T) {
	store, seal := sealedSourceStore(t, "source-a", 5)
	proof, err := store.BuildRangeProof("source-a", 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.Records) != 3 || proof.Records[0].Seq != 2 || proof.Records[2].Seq != 4 {
		t.Fatalf("proof records = %+v", proof.Records)
	}
	if len(proof.Inclusion) != 3 {
		t.Fatalf("got %d inclusion proofs", len(proof.Inclusion))
	}
	for _, record := range proof.Records {
		if record.Event.ID == "a-1" || record.Event.ID == "a-5" {
			t.Fatal("proof disclosed records outside the requested range")
		}
	}
	if err := VerifyRangeProof(*proof, *seal); err != nil {
		t.Fatal(err)
	}
}

func TestRangeProofReportsMissingInterval(t *testing.T) {
	store, seal := sealedSourceStore(t, "source-a", 4)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	copyPath := copyFile(t, store.path)
	frames := splitFrames(t, copyPath)
	removeFrame(t, copyPath, frames[1])

	proof, err := BuildRangeProofFromFile(copyPath, *seal, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyRangeProof(*proof, *seal)
	var incomplete *RangeIncompleteError
	if !errors.As(err, &incomplete) {
		t.Fatalf("expected RangeIncompleteError, got %v", err)
	}
	if len(incomplete.MissingSeqs) != 1 || incomplete.MissingSeqs[0] != 2 {
		t.Fatalf("missing sequences = %v", incomplete.MissingSeqs)
	}
}

func TestRangeProofRejectsSegmentReplacement(t *testing.T) {
	store, seal := sealedSourceStore(t, "source-a", 3)
	proof, err := store.BuildRangeProof("source-a", 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	replacement := proof.Records[0]
	replacement.Event.Payload = []byte("replaced")
	proof.Records[0] = replacement
	err = VerifyRangeProof(*proof, *seal)
	assertTamper(t, err, TamperRewrite, 2)
}

func TestTailDeletionCannotBeProvedFromCopyAlone(t *testing.T) {
	store, seal := sealedSourceStore(t, "source-a", 4)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	copyPath := copyFile(t, store.path)
	frames := splitFrames(t, copyPath)
	writeFrames(t, copyPath, frames[:2])

	err := VerifySealedFile(copyPath, *seal)
	assertTamper(t, err, TamperTailTruncation, 3)

	proof, proofErr := BuildRangeProofFromFile(copyPath, *seal, 1, 2)
	if proofErr != nil {
		t.Fatal(proofErr)
	}
	if err := VerifyRangeProof(*proof, *seal); err == nil {
		t.Fatal("proof from a truncated copy was accepted without the sealed tail boundary")
	}
}

func TestIncompleteFrameDuringSealIsDetectedWithExternalSummary(t *testing.T) {
	store, seal := sealedSourceStore(t, "source-a", 3)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	copyPath := copyFile(t, store.path)
	frames := splitFrames(t, copyPath)
	var interrupted bytes.Buffer
	for _, frame := range frames[:2] {
		interrupted.Write(frame.data)
	}
	interrupted.Write([]byte{0x41, 0x55})
	if err := os.WriteFile(copyPath, interrupted.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	err := VerifySealedFile(copyPath, *seal)
	assertTamper(t, err, TamperTailTruncation, 3)
}

func sealedSourceStore(t *testing.T, source string, n int) (*Store, *SealSummary) {
	t.Helper()
	store := openTestStore(t)
	events := make([]Event, n)
	base := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	for i := range events {
		events[i] = eventFor("a-"+string(rune('1'+i)), source, base.Add(time.Duration(i)*time.Minute))
	}
	if _, err := store.AppendBatch(events); err != nil {
		t.Fatal(err)
	}
	seal, err := store.Seal(source)
	if err != nil {
		t.Fatal(err)
	}
	return store, seal
}

func eventFor(id, source string, occurredAt time.Time) Event {
	return Event{ID: id, Source: source, Type: "project.generated", OccurredAt: occurredAt, Payload: []byte(id)}
}

func removeFrame(t *testing.T, path string, removed frameLocation) {
	t.Helper()
	data := mustReadFile(t, path)
	var out bytes.Buffer
	out.Write(data[:removed.start])
	out.Write(data[removed.end:])
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeFrames(t *testing.T, path string, frames []frameLocation) {
	t.Helper()
	var out bytes.Buffer
	for _, frame := range frames {
		out.Write(frame.data)
	}
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
