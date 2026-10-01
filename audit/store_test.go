package audit

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAppendBatchPreservesSourceOrderAndReopens(t *testing.T) {
	store := openTestStore(t)
	events := testEvents(4)
	if _, err := store.AppendBatch(events); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := mustOpen(t, store.path)
	records := reopened.Query()
	if len(records) != len(events) {
		t.Fatalf("got %d records, want %d", len(records), len(events))
	}
	for i, event := range events {
		if records[i].Seq != uint64(i+1) {
			t.Fatalf("record %d has seq %d", i, records[i].Seq)
		}
		if records[i].Event.ID != event.ID || records[i].Event.Source != event.Source || !bytes.Equal(records[i].Event.Payload, event.Payload) {
			t.Fatalf("record %d content changed", i+1)
		}
	}
}

func TestRecoversOnlyIncompleteTail(t *testing.T) {
	store := openTestStore(t)
	events := testEvents(3)
	if _, err := store.AppendBatch(events); err != nil {
		t.Fatal(err)
	}
	partial := []byte{0x41, 0x55, 0x44, 0x31, 0x00}
	if _, err := store.file.Write(partial); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := mustOpen(t, store.path)
	records := reopened.Query()
	if len(records) != 3 {
		t.Fatalf("recovered to %d records, want 3", len(records))
	}
	if records[2].Event.ID != "event-3" || !bytes.Equal(records[2].RecordHash, hashRecord(3, records[1].RecordHash, events[2])) {
		t.Fatal("last complete record was not preserved accurately")
	}
}

func TestDoesNotTruncateCompleteCorruptFrame(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.AppendBatch(testEvents(3)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	copyPath := copyFile(t, store.path)
	frames := splitFrames(t, copyPath)
	flipByteAt(t, copyPath, int64(frames[1].start+frameHeaderLength+20))
	before, err := os.Stat(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(copyPath); err == nil {
		t.Fatal("Open accepted a complete corrupt frame")
	}
	after, err := os.Stat(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	if before.Size() != after.Size() {
		t.Fatalf("corrupt file changed from %d to %d bytes", before.Size(), after.Size())
	}
}

func TestSealDetectsRewrittenCopyByContentHash(t *testing.T) {
	store := openTestStore(t)
	events := testEvents(4)
	if _, err := store.AppendBatch(events); err != nil {
		t.Fatal(err)
	}
	seal, err := store.Seal("build")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	copyPath := copyFile(t, store.path)
	frames := splitFrames(t, copyPath)
	payloadOffset := frameHeaderLength
	flipByteAt(t, copyPath, int64(frames[1].start+payloadOffset+20))

	err = VerifySealedFile(copyPath, *seal)
	assertTamper(t, err, TamperRewrite, 2)
}

func TestSealDetectsMiddleDeletionAndNotByCountAlone(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.AppendBatch(testEvents(4)); err != nil {
		t.Fatal(err)
	}
	seal, err := store.Seal("build")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	copyPath := copyFile(t, store.path)
	frames := splitFrames(t, copyPath)
	data, err := os.ReadFile(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	removed := frames[1]
	var tampered bytes.Buffer
	tampered.Write(data[:removed.start])
	tampered.Write(data[removed.end:])
	if err := os.WriteFile(copyPath, tampered.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	err = VerifySealedFile(copyPath, *seal)
	assertTamper(t, err, TamperMiddleDeletion, 2)
}

func TestSealDetectsTailTruncationUsingExternalSummary(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.AppendBatch(testEvents(4)); err != nil {
		t.Fatal(err)
	}
	seal, err := store.Seal("build")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	copyPath := copyFile(t, store.path)
	frames := splitFrames(t, copyPath)
	var prefix bytes.Buffer
	for _, frame := range frames[:2] {
		prefix.Write(frame.data)
	}
	if err := os.WriteFile(copyPath, prefix.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	err = VerifySealedFile(copyPath, *seal)
	assertTamper(t, err, TamperTailTruncation, 3)
}

func TestSealDetectsInsertionAfterSealedPrefix(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.AppendBatch(testEvents(4)); err != nil {
		t.Fatal(err)
	}
	seal, err := store.Seal("build")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	copyPath := copyFile(t, store.path)
	copy, err := Open(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	inserted := Event{ID: "inserted", Source: "build", Type: "forged", OccurredAt: time.Now(), Payload: []byte("not part of seal")}
	if _, err := copy.Append(inserted); err != nil {
		t.Fatal(err)
	}
	if err := copy.Close(); err != nil {
		t.Fatal(err)
	}

	err = VerifySealedFile(copyPath, *seal)
	assertTamper(t, err, TamperInsertion, 5)
}

func TestValidCopyPassesSealVerification(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.AppendBatch(testEvents(3)); err != nil {
		t.Fatal(err)
	}
	seal, err := store.Seal("build")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := VerifySealedFile(copyFile(t, store.path), *seal); err != nil {
		t.Fatal(err)
	}
}

func TestIndependentSourcesKeepSeparateSequences(t *testing.T) {
	store := openTestStore(t)
	events := []Event{
		newEvent("a-1", "alpha"),
		newEvent("b-1", "beta"),
		newEvent("a-2", "alpha"),
		newEvent("b-2", "beta"),
	}
	if _, err := store.AppendBatch(events); err != nil {
		t.Fatal(err)
	}

	alpha := store.QuerySource("alpha")
	beta := store.QuerySource("beta")
	if len(alpha) != 2 || alpha[0].Seq != 1 || alpha[1].Seq != 2 {
		t.Fatalf("alpha sequences = %+v", alpha)
	}
	if len(beta) != 2 || beta[0].Seq != 1 || beta[1].Seq != 2 {
		t.Fatalf("beta sequences = %+v", beta)
	}
	if physical := store.Query(); len(physical) != 4 || physical[0].Event.ID != "a-1" || physical[1].Event.ID != "b-1" {
		t.Fatalf("physical append order changed: %+v", physical)
	}
}

func TestRangeProofExcludesOtherRecordsAndDetectsMissingSeq(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.AppendBatch([]Event{
		newEvent("a-1", "alpha"), newEvent("b-1", "beta"),
		newEvent("a-2", "alpha"), newEvent("a-3", "alpha"), newEvent("a-4", "alpha"),
	}); err != nil {
		t.Fatal(err)
	}
	seal, err := store.Seal("alpha")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := store.BuildRangeProof("alpha", 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.Records) != 2 || proof.Records[0].Event.ID != "a-2" || proof.Records[1].Event.ID != "a-3" {
		t.Fatalf("proof exposed the wrong records: %+v", proof.Records)
	}
	if err := VerifyRangeProof(*seal, *proof); err != nil {
		t.Fatalf("valid range proof failed: %v", err)
	}

	proof.Records = proof.Records[:1]
	proof.MerkleSteps = proof.MerkleSteps[:1]
	err = VerifyRangeProof(*seal, *proof)
	assertTamper(t, err, TamperMissingRange, 2)
}

func TestSealDetectsCompleteSegmentReplacementWhileOtherSourceRemainsValid(t *testing.T) {
	original := openTestStore(t)
	if _, err := original.AppendBatch([]Event{
		newEvent("a-1", "alpha"), newEvent("b-1", "beta"),
		newEvent("a-2", "alpha"), newEvent("b-2", "beta"),
	}); err != nil {
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
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}

	replacement := openTestStore(t)
	if _, err := replacement.AppendBatch([]Event{newEvent("fake-a-1", "alpha"), newEvent("fake-a-2", "alpha")}); err != nil {
		t.Fatal(err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}

	originalFrames := readAllFrames(t, original.path)
	replacementFrames := readAllFrames(t, replacement.path)
	mixed := filepath.Join(t.TempDir(), "mixed.audit")
	writeFrames(t, mixed, append(framesForSource(t, replacementFrames, "alpha"), framesForSource(t, originalFrames, "beta")...))

	err = VerifySealedFile(mixed, *alphaSeal)
	assertTamper(t, err, TamperSegmentReplacement, 2)
	if err := VerifySealedFile(mixed, *betaSeal); err != nil {
		t.Fatalf("unrelated beta source should still verify: %v", err)
	}
}

func TestIncompleteFrameDuringSealIsReportedUsingExternalSummary(t *testing.T) {
	store := openTestStore(t)
	events := []Event{newEvent("a-1", "alpha"), newEvent("a-2", "alpha"), newEvent("a-3", "alpha")}
	if _, err := store.AppendBatch(events); err != nil {
		t.Fatal(err)
	}
	seal, err := store.Seal("alpha")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	frames := splitFrames(t, store.path)
	var prefix bytes.Buffer
	for _, frame := range frames[:2] {
		prefix.Write(frame.data)
	}
	prefix.Write([]byte{0x41, 0x55, 0x44, 0x31})
	copyPath := filepath.Join(t.TempDir(), "interrupted.audit")
	if err := os.WriteFile(copyPath, prefix.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	err = VerifySealedFile(copyPath, *seal)
	assertTamper(t, err, TamperTailTruncation, 3)
}

type frameLocation struct {
	start int
	end   int
	data  []byte
}

func readAllFrames(t *testing.T, path string) []frameLocation {
	t.Helper()
	return splitFrames(t, path)
}

func framesForSource(t *testing.T, frames []frameLocation, source string) []frameLocation {
	t.Helper()
	var out []frameLocation
	for _, frame := range frames {
		_, payload, _, _, err := readFrame(frame.data, 0)
		if err != nil {
			t.Fatal(err)
		}
		var env envelope
		if err := json.Unmarshal(payload, &env); err != nil {
			t.Fatal(err)
		}
		if env.Source == source {
			out = append(out, frame)
		}
	}
	return out
}

func writeFrames(t *testing.T, path string, frames []frameLocation) {
	t.Helper()
	var buf bytes.Buffer
	for _, frame := range frames {
		buf.Write(frame.data)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
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

func splitFrames(t *testing.T, path string) []frameLocation {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var frames []frameLocation
	for offset := 0; offset < len(data); {
		if offset+frameHeaderLength > len(data) {
			t.Fatal("short frame header")
		}
		var header frameHeader
		if err := binary.Read(bytes.NewReader(data[offset:offset+frameHeaderLength]), binary.BigEndian, &header); err != nil {
			t.Fatal(err)
		}
		end := offset + frameHeaderLength + int(header.Length) + hashLength
		frames = append(frames, frameLocation{start: offset, end: end, data: data[offset:end]})
		offset = end
	}
	return frames
}

func flipByteAt(t *testing.T, path string, offset int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := []byte{0}
	if _, err := f.ReadAt(buf, offset); err != nil {
		t.Fatal(err)
	}
	buf[0] ^= 0xff
	if _, err := f.WriteAt(buf, offset); err != nil {
		t.Fatal(err)
	}
}

func copyFile(t *testing.T, path string) string {
	t.Helper()
	src, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dstPath := filepath.Join(t.TempDir(), "copy.audit")
	dst, err := os.Create(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	return dstPath
}

func assertTamper(t *testing.T, err error, kind TamperKind, seq uint64) {
	t.Helper()
	var tamper *TamperError
	if !errors.As(err, &tamper) {
		t.Fatalf("expected TamperError, got %v", err)
	}
	if tamper.Kind != kind || tamper.RecordSeq != seq {
		t.Fatalf("got kind=%s seq=%d, want kind=%s seq=%d", tamper.Kind, tamper.RecordSeq, kind, seq)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	return mustOpen(t, filepath.Join(t.TempDir(), "audit.log"))
}

func mustOpen(t *testing.T, path string) *Store {
	t.Helper()
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func testEvents(n int) []Event {
	events := make([]Event, n)
	base := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	for i := range events {
		events[i] = Event{
			ID:         "event-" + string(rune('1'+i)),
			Source:     "build",
			Type:       "project.generated",
			OccurredAt: base.Add(time.Duration(i) * time.Minute),
			Payload:    []byte{byte(i + 1), byte(i + 2), byte(i + 3)},
		}
	}
	return events
}

func newEvent(id, source string) Event {
	return Event{ID: id, Source: source, Type: "project.generated", OccurredAt: time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC), Payload: []byte(id)}
}

func TestSealedRangeProofStaysValidAfterLaterAppends(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.AppendBatch([]Event{newEvent("a-1", "alpha"), newEvent("a-2", "alpha"), newEvent("a-3", "alpha")}); err != nil {
		t.Fatal(err)
	}
	oldSeal, err := store.Seal("alpha")
	if err != nil {
		t.Fatal(err)
	}
	oldProof, err := store.BuildSealedRangeProof(*oldSeal, 1, 3)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.AppendBatch([]Event{newEvent("a-4", "alpha"), newEvent("a-5", "alpha")}); err != nil {
		t.Fatal(err)
	}
	newSeal, err := store.Seal("alpha")
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyRangeProof(*oldSeal, *oldProof); err != nil {
		t.Fatalf("proof built before the appends must still verify against the old summary: %v", err)
	}
	rebuilt, err := store.BuildSealedRangeProof(*oldSeal, 2, 3)
	if err != nil {
		t.Fatalf("old summary must remain provable after later appends: %v", err)
	}
	if rebuilt.SealedCount != oldSeal.RecordCount {
		t.Fatalf("rebuilt proof anchors to %d records, want the old seal count %d", rebuilt.SealedCount, oldSeal.RecordCount)
	}
	if err := VerifyRangeProof(*oldSeal, *rebuilt); err != nil {
		t.Fatalf("rebuilt proof must verify against the old summary: %v", err)
	}
	if err := VerifyRangeProof(*newSeal, *rebuilt); err == nil {
		t.Fatal("old-seal proof must not verify against the new summary")
	}
	if _, err := store.BuildSealedRangeProof(*oldSeal, 1, 4); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("range beyond the old seal must be refused, got %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := VerifySealedFile(store.path, *oldSeal); err == nil {
		t.Fatal("new appends must not let the file pass under the old summary")
	} else {
		assertTamper(t, err, TamperInsertion, 4)
	}
}

func TestSealedRangeProofRejectsReplacedPrefix(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.AppendBatch([]Event{newEvent("a-1", "alpha"), newEvent("a-2", "alpha")}); err != nil {
		t.Fatal(err)
	}
	seal, err := store.Seal("alpha")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	replacement := openTestStore(t)
	if _, err := replacement.AppendBatch([]Event{newEvent("fake-1", "alpha"), newEvent("fake-2", "alpha")}); err != nil {
		t.Fatal(err)
	}
	if _, err := replacement.BuildSealedRangeProof(*seal, 1, 2); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("replaced segment must not produce proofs for the old summary, got %v", err)
	}
}

func TestCombinedRangeProofVerifiesIndependentSourcesWithoutGlobalOrder(t *testing.T) {
	store := openTestStore(t)
	base := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	late := Event{ID: "a-1", Source: "alpha", Type: "project.generated", OccurredAt: base.Add(2 * time.Hour), Payload: []byte("a-1")}
	early := Event{ID: "b-1", Source: "beta", Type: "project.generated", OccurredAt: base, Payload: []byte("b-1")}
	if _, err := store.AppendBatch([]Event{
		late, early,
		{ID: "a-2", Source: "alpha", Type: "project.generated", OccurredAt: base.Add(3 * time.Hour), Payload: []byte("a-2")},
		{ID: "b-2", Source: "beta", Type: "project.generated", OccurredAt: base.Add(-time.Hour), Payload: []byte("b-2")},
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
	summaries := []SealSummary{*alphaSeal, *betaSeal}
	requests := []SourceRangeRequest{
		{Source: "alpha", StartSeq: 1, EndSeq: 2},
		{Source: "beta", StartSeq: 2, EndSeq: 2},
	}
	combined, err := store.BuildCombinedRangeProof(summaries, requests)
	if err != nil {
		t.Fatal(err)
	}
	if len(combined.Ranges) != 2 {
		t.Fatalf("combined proof has %d ranges, want 2", len(combined.Ranges))
	}
	if err := VerifyCombinedRangeProof(summaries, *combined); err != nil {
		t.Fatalf("valid combined proof failed: %v", err)
	}

	tampered := *combined
	tampered.Ranges = append([]RangeProof(nil), combined.Ranges...)
	tampered.Ranges[0].Records = append([]Record(nil), combined.Ranges[0].Records...)
	tampered.Ranges[0].Records[1].Event.Payload = []byte("forged")
	if err := VerifyCombinedRangeProof(summaries, tampered); err == nil {
		t.Fatal("tampered alpha range must fail")
	} else {
		assertTamper(t, err, TamperRewrite, 2)
	}

	swapped := *combined
	swapped.Ranges = append([]RangeProof(nil), combined.Ranges...)
	swapped.Ranges[0], swapped.Ranges[1] = swapped.Ranges[1], swapped.Ranges[0]
	if err := VerifyCombinedRangeProof(summaries, swapped); err != nil {
		t.Fatalf("range order inside the bundle is not a global order and must not matter: %v", err)
	}

	if err := VerifyCombinedRangeProof([]SealSummary{*alphaSeal}, *combined); err == nil {
		t.Fatal("missing beta summary must fail")
	} else {
		assertTamper(t, err, TamperWrongSource, 0)
	}
	if err := VerifyCombinedRangeProof(summaries, CombinedRangeProof{Version: 2}); err == nil {
		t.Fatal("empty combined proof must fail")
	} else {
		assertTamper(t, err, TamperMissingRange, 0)
	}
	if _, err := store.BuildCombinedRangeProof(summaries, nil); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("empty request list must be refused, got %v", err)
	}
	if _, err := store.BuildCombinedRangeProof(summaries, []SourceRangeRequest{{Source: "alpha", StartSeq: 0, EndSeq: 1}}); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("empty range must be refused, got %v", err)
	}
}
