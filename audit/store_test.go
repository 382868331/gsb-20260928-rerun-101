package audit

import (
	"bytes"
	"encoding/binary"
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
	seal, err := store.Seal("batch-1")
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
	seal, err := store.Seal("batch-1")
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
	seal, err := store.Seal("batch-1")
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
	seal, err := store.Seal("batch-1")
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
	inserted := Event{ID: "inserted", Source: "project-x", Type: "forged", OccurredAt: time.Now(), Payload: []byte("not part of seal")}
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
	seal, err := store.Seal("batch-1")
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

type frameLocation struct {
	start int
	end   int
	data  []byte
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
			Source:     []string{"build", "review", "release", "policy"}[i%4],
			Type:       "project.generated",
			OccurredAt: base.Add(time.Duration(i) * time.Minute),
			Payload:    []byte{byte(i + 1), byte(i + 2), byte(i + 3)},
		}
	}
	return events
}
