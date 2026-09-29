package auditlog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sampleEvents(n int) []Event {
	ev := make([]Event, n)
	for i := range ev {
		ev[i] = Event{
			Time:      time.Date(2026, 9, 29, 10, 0, i, 0, time.UTC),
			EventType: "build.finished",
			Source:    "pipeline",
			ID:        "",
			Data:      []byte{byte(i), byte(i + 1), byte(i + 2)},
		}
	}
	return ev
}

func buildLog(t *testing.T, n int) (dir, path string, l *Log) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "audit.log")
	l, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range sampleEvents(n) {
		if err := l.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	return dir, path, l
}

func TestAppendScanOrderAndCount(t *testing.T) {
	_, path, l := buildLog(t, 5)
	if got := l.Count(); got != 5 {
		t.Fatalf("count = %d, want 5", got)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var i int
	if err := l.Scan(func(r Record) error {
		want := sampleEvents(5)[i]
		if r.Index != uint64(i) || r.EventType != want.EventType ||
			string(r.Data) != string(want.Data) || !r.Time.Equal(want.Time) {
			t.Fatalf("record %d mismatch: %+v", i, r)
		}
		i++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if i != 5 {
		t.Fatalf("scanned %d records, want 5", i)
	}
}

// copyFile makes a real modified copy for tamper experiments; verification is
// done against the actual changed bytes, never against record counts alone.
func copyFile(t *testing.T, src, dst string) []byte {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return data
}

func frameBounds(t *testing.T, data []byte) (bounds [][2]int64) {
	t.Helper()
	off := int64(0)
	for off < int64(len(data)) {
		fl, _, _, complete, err := readFrame(data[off:])
		if err != nil || !complete {
			t.Fatalf("bad frame at %d: %v", off, err)
		}
		bounds = append(bounds, [2]int64{off, off + fl})
		off += fl
	}
	return bounds
}

func TestRewriteByteDetected(t *testing.T) {
	dir, path, l := buildLog(t, 5)
	l.Close()
	dst := filepath.Join(dir, "rewrite.log")
	data := copyFile(t, path, dst)
	b := frameBounds(t, data)
	// Flip a byte inside the third record's payload.
	pos := b[2][0] + headerSize + 3
	data[pos] ^= 0xFF
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyChain(dst); err == nil {
		t.Fatal("rewrite of a record byte was not detected")
	}
}

func TestMiddleDeleteDetected(t *testing.T) {
	dir, path, l := buildLog(t, 5)
	l.Close()
	dst := filepath.Join(dir, "delete.log")
	data := copyFile(t, path, dst)
	b := frameBounds(t, data)
	// Physically delete record #2 from the middle of a copy.
	removed := data[b[2][0]:b[2][1]]
	var altered []byte
	altered = append(altered, data[:b[2][0]]...)
	altered = append(altered, data[b[2][1]:]...)
	if err := os.WriteFile(dst, altered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyChain(dst); err == nil {
		t.Fatal("middle deletion was not detected")
	} else if te, ok := err.(*TamperError); ok {
		// Deleting the frame shifts the next frame to the earlier offset; its
		// magic still parses but the back-link must fail.
		_ = te
	}
	_ = removed
}

func TestInsertionDetected(t *testing.T) {
	dir, path, l := buildLog(t, 5)
	l.Close()
	dst := filepath.Join(dir, "insert.log")
	data := copyFile(t, path, dst)
	b := frameBounds(t, data)
	// Duplicate record #0 (which carries an all-zero prev hash) into the middle.
	frame0 := append([]byte(nil), data[b[0][0]:b[0][1]]...)
	var altered []byte
	altered = append(altered, data[:b[3][0]]...)
	altered = append(altered, frame0...)
	altered = append(altered, data[b[3][0]:]...)
	if err := os.WriteFile(dst, altered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyChain(dst); err == nil {
		t.Fatal("insertion of a record into the middle was not detected")
	}
}

func TestTailTruncationRequiresSummary(t *testing.T) {
	dir, path, l := buildLog(t, 5)
	s, err := l.Seal("batch-1")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()

	dst := filepath.Join(dir, "tail.log")
	data := copyFile(t, path, dst)
	b := frameBounds(t, data)
	// Drop the final two records: the remaining prefix is a valid chain.
	truncated := data[:b[3][0]]
	if err := os.WriteFile(dst, truncated, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyChain(dst)
	if err != nil {
		t.Fatalf("truncated tail should still form a valid chain, got: %v", err)
	}
	if res.RecordCount != 3 {
		t.Fatalf("chain verify count = %d, want 3", res.RecordCount)
	}
	res2, err := VerifyAgainstSummary(dst, s)
	if err == nil {
		t.Fatal("tail truncation was not detected against the sealed summary")
	}
	if res2 == nil || !res2.TailTruncated {
		t.Fatalf("expected TailTruncated=true, got %+v", res2)
	}

	// The untouched log must verify against the same summary.
	if _, err := VerifyAgainstSummary(path, s); err != nil {
		t.Fatalf("original log failed summary verification: %v", err)
	}
}

func TestInterruptedWriteRecovery(t *testing.T) {
	_, path, l := buildLog(t, 3)
	l.Close()
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b := frameBounds(t, good)
	// Simulate a torn append: full frame for record #3 header + partial body.
	torn := append([]byte(nil), good...)
	torn = append(torn, good[b[2][0]:b[2][0]+headerSize+4]...)
	if err := os.WriteFile(path, torn, 0o600); err != nil {
		t.Fatal(err)
	}
	l2, err := Open(path)
	if err != nil {
		t.Fatalf("open with torn tail failed: %v", err)
	}
	if got := l2.Count(); got != 3 {
		t.Fatalf("after recovery count = %d, want 3", got)
	}
	// Recovery must truncate the file back to the last complete record.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != int64(len(good)) {
		t.Fatalf("recovered size %d, want %d", fi.Size(), len(good))
	}
	// Appending after recovery chains correctly.
	if err := l2.Append(sampleEvents(4)[3]); err != nil {
		t.Fatal(err)
	}
	l2.Close()
	if _, err := VerifyChain(path); err != nil {
		t.Fatalf("chain broken after recovery+append: %v", err)
	}
}

func TestCorruptMiddleIsNotSilentlyDropped(t *testing.T) {
	_, path, l := buildLog(t, 4)
	l.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b := frameBounds(t, data)
	// Corrupt a byte in record #1 while leaving the full frame length intact.
	data[b[1][0]+headerSize+2] ^= 0x01
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("corrupt middle frame must not be silently recovered away")
	}
}

func TestSummaryRoundTrip(t *testing.T) {
	dir, _, l := buildLog(t, 2)
	s, err := l.Seal("b")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	sumPath := filepath.Join(dir, "sum.json")
	if err := WriteSummary(sumPath, s); err != nil {
		t.Fatal(err)
	}
	s2, err := ReadSummary(sumPath)
	if err != nil {
		t.Fatal(err)
	}
	if s2.RecordCount != 2 || s2.LogSHA256 != s.LogSHA256 {
		t.Fatalf("summary round trip mismatch: %+v vs %+v", s, s2)
	}
}
