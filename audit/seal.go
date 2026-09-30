package audit

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// SealSummary is intentionally not stored in the audited file. The calling
// application must retain it in separate durable storage. Without it, an
// entirely missing file tail cannot be distinguished from a shorter valid log.
type SealSummary struct {
	Version     uint64    `json:"version"`
	SealedAt    time.Time `json:"sealed_at"`
	Source      string    `json:"source"`
	RecordCount uint64    `json:"record_count"`
	LastHash    []byte    `json:"last_hash"`
	MerkleRoot  []byte    `json:"merkle_root"`
}

func (s SealSummary) ID() string {
	return hex.EncodeToString(s.LastHash)
}

func (s SealSummary) MarshalJSON() ([]byte, error) {
	type alias SealSummary
	return json.Marshal(alias(SealSummary{
		Version:     s.Version,
		SealedAt:    s.SealedAt.UTC(),
		Source:      s.Source,
		RecordCount: s.RecordCount,
		LastHash:    s.LastHash,
		MerkleRoot:  s.MerkleRoot,
	}))
}

func validateSummary(summary SealSummary) error {
	if summary.Version != 2 || summary.Source == "" || summary.RecordCount == 0 || len(summary.LastHash) != hashLength || len(summary.MerkleRoot) != hashLength {
		return fmt.Errorf("invalid seal summary")
	}
	return nil
}

// VerifySealedFile validates an arbitrary copy against a summary retained
// outside that copy. It never repairs the file.
func VerifySealedFile(path string, summary SealSummary) error {
	if err := validateSummary(summary); err != nil {
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	validEnd, err := scanValidPrefix(f)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	if validEnd != info.Size() {
		recordsAtValidEnd, _, prefixErr := readRecordsForVerification(bytes.NewReader(data[:validEnd]))
		remaining := data[validEnd:]
		incompleteFrame := len(remaining) < frameHeaderLength
		if !incompleteFrame {
			var damagedHeader frameHeader
			if err := binary.Read(bytes.NewReader(remaining[:frameHeaderLength]), binary.BigEndian, &damagedHeader); err != nil {
				return err
			}
			incompleteFrame = int64(len(remaining)) < int64(frameHeaderLength)+int64(damagedHeader.Length)+hashLength
		}
		validSourceCount := 0
		if prefixErr == nil {
			validSourceCount = len(recordsForSource(recordsAtValidEnd, summary.Source))
		}
		if incompleteFrame && prefixErr == nil && uint64(validSourceCount) < summary.RecordCount {
			return &TamperError{
				Kind:      TamperTailTruncation,
				RecordSeq: uint64(validSourceCount) + 1,
				Message:   "incomplete final frame removed sealed records; compare the external seal summary",
			}
		}
		seq := uint64(0)
		if prefixErr == nil {
			seq = uint64(validSourceCount) + 1
		}
		return &TamperError{Kind: TamperRewrite, RecordSeq: seq, ByteOffset: validEnd, Message: "damaged or rewritten frame after the last valid record"}
	}

	records, _, err := readRecordsForVerification(bytes.NewReader(data))
	if err != nil {
		return err
	}
	sourceRecords := recordsForSource(records, summary.Source)
	if uint64(len(sourceRecords)) < summary.RecordCount {
		return &TamperError{
			Kind:      TamperTailTruncation,
			RecordSeq: uint64(len(sourceRecords)) + 1,
			Message:   fmt.Sprintf("sealed source %q has %d records, copy retains %d; compare the external seal summary", summary.Source, summary.RecordCount, len(sourceRecords)),
		}
	}
	if uint64(len(sourceRecords)) > summary.RecordCount {
		return &TamperError{
			Kind:      TamperInsertion,
			RecordSeq: summary.RecordCount + 1,
			Message:   "records were inserted after the sealed source prefix",
		}
	}
	var previous []byte
	leaves := make([][]byte, 0, len(sourceRecords))
	for _, record := range sourceRecords {
		expectedHash := hashRecord(record.Seq, previous, record.Event)
		if !bytes.Equal(record.RecordHash, expectedHash) {
			return &TamperError{Kind: TamperSegmentReplacement, RecordSeq: record.Seq, Message: "source segment content was replaced"}
		}
		previous = record.RecordHash
		leaves = append(leaves, append([]byte(nil), record.RecordHash...))
	}
	if !bytes.Equal(previous, summary.LastHash) || !bytes.Equal(merkleRoot(leaves), summary.MerkleRoot) {
		return &TamperError{Kind: TamperSegmentReplacement, RecordSeq: summary.RecordCount, Message: "sealed segment hash or root does not match"}
	}
	return nil
}

func recordsForSource(records []Record, source string) []Record {
	var out []Record
	for _, record := range records {
		if record.Event.Source == source {
			out = append(out, record)
		}
	}
	return out
}

// VerifyOpenStore checks the active store's complete hash chain and framing.
func VerifyOpenStore(store *Store) error {
	f, err := os.Open(store.path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, _, err = readRecords(f)
	return err
}
