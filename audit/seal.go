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
	}))
}

// VerifySealedFile validates an arbitrary copy against a summary retained
// outside that copy. It never repairs the file.
func VerifySealedFile(path string, summary SealSummary) error {
	if summary.Version != 1 || summary.RecordCount == 0 || len(summary.LastHash) != hashLength {
		return fmt.Errorf("invalid seal summary")
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
		if incompleteFrame && prefixErr == nil && uint64(len(recordsAtValidEnd)) < summary.RecordCount {
			return &TamperError{
				Kind:      TamperTailTruncation,
				RecordSeq: uint64(len(recordsAtValidEnd)) + 1,
				Message:   "incomplete final frame removed sealed records; compare the external seal summary",
			}
		}
		seq := uint64(0)
		if prefixErr == nil {
			seq = uint64(len(recordsAtValidEnd)) + 1
		}
		return &TamperError{Kind: TamperRewrite, RecordSeq: seq, ByteOffset: validEnd, Message: "damaged or rewritten frame after the last valid record"}
	}

	records, _, err := readRecordsForVerification(bytes.NewReader(data))
	if err != nil {
		return err
	}
	if uint64(len(records)) < summary.RecordCount {
		return &TamperError{
			Kind:      TamperTailTruncation,
			RecordSeq: uint64(len(records)) + 1,
			Message:   fmt.Sprintf("sealed log has %d records, copy retains %d; compare the external seal summary", summary.RecordCount, len(records)),
		}
	}
	if uint64(len(records)) > summary.RecordCount {
		return &TamperError{
			Kind:      TamperInsertion,
			RecordSeq: summary.RecordCount + 1,
			Message:   "records were inserted after the sealed prefix",
		}
	}
	if !bytes.Equal(records[len(records)-1].RecordHash, summary.LastHash) {
		return &TamperError{Kind: TamperRewrite, RecordSeq: summary.RecordCount, Message: "sealed final hash does not match"}
	}
	return nil
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
