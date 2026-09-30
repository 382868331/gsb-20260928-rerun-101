package audit

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// SealSummary is intentionally not stored in the audited file. The calling
// application must retain it in separate durable storage. Without it, an
// entirely missing file tail cannot be distinguished from a shorter valid log.
type SealSummary struct {
	Version     uint64 `json:"version"`
	Source      string `json:"source"`
	RecordCount uint64 `json:"record_count"`
	LastHash    []byte `json:"last_hash"`
	MerkleRoot  []byte `json:"merkle_root"`
}

func (s SealSummary) ID() string {
	return hex.EncodeToString(s.LastHash)
}

func (s SealSummary) MarshalJSON() ([]byte, error) {
	type alias SealSummary
	return json.Marshal(alias(SealSummary{
		Version:     s.Version,
		Source:      s.Source,
		RecordCount: s.RecordCount,
		LastHash:    s.LastHash,
		MerkleRoot:  s.MerkleRoot,
	}))
}

// VerifySealedFile validates an arbitrary copy against a summary retained
// outside that copy. It never repairs the file.
func VerifySealedFile(path string, summary SealSummary) error {
	if summary.Version != 1 || summary.Source == "" || summary.RecordCount == 0 || len(summary.LastHash) != hashLength || len(summary.MerkleRoot) != hashLength {
		return fmt.Errorf("invalid seal summary")
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	records, validEnd, err := readSourceRecordsLenient(bytes.NewReader(data), summary.Source)
	if err != nil {
		return err
	}
	if validEnd != len(data) {
		seq := uint64(1)
		if len(records) > 0 {
			seq = records[len(records)-1].Seq + 1
		}
		if uint64(len(records)) < summary.RecordCount {
			return &TamperError{Kind: TamperTailTruncation, RecordSeq: seq, ByteOffset: int64(validEnd), Message: "incomplete frame after sealed records; compare the external seal summary"}
		}
		return &TamperError{Kind: TamperRewrite, RecordSeq: summary.RecordCount + 1, ByteOffset: int64(validEnd), Message: "incomplete frame after the sealed prefix"}
	}
	if err := verifySourceChain(records, summary.Source); err != nil {
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
	recordHashes := make([][]byte, len(records))
	for i := range records {
		recordHashes[i] = records[i].RecordHash
	}
	if !bytes.Equal(merkleRoot(recordHashes), summary.MerkleRoot) {
		return &TamperError{Kind: TamperRewrite, RecordSeq: summary.RecordCount, Message: "sealed merkle root does not match"}
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
