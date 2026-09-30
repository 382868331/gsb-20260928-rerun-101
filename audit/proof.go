package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

type RangeProof struct {
	Version     uint64     `json:"version"`
	Source      string     `json:"source"`
	StartSeq    uint64     `json:"start_seq"`
	EndSeq      uint64     `json:"end_seq"`
	Records     []Record   `json:"records"`
	Inclusion   [][][]byte `json:"inclusion_proofs"`
	MissingSeqs []uint64   `json:"missing_seqs"`
}

// BuildRangeProofFromFile builds a proof from an arbitrary copy. The external
// summary supplies the sealed boundary; the copy alone cannot establish it.
func BuildRangeProofFromFile(path string, summary SealSummary, startSeq, endSeq uint64) (*RangeProof, error) {
	if summary.Version != 1 || summary.Source == "" || summary.RecordCount == 0 || len(summary.MerkleRoot) != hashLength {
		return nil, fmt.Errorf("invalid seal summary")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	records, _, err := readSourceRecordsLenient(f, summary.Source)
	if err != nil {
		return nil, err
	}
	return buildCopyRangeProof(records, summary, startSeq, endSeq)
}

func buildRangeProof(records []Record, source string, startSeq, endSeq uint64) (*RangeProof, error) {
	if source == "" || startSeq == 0 || endSeq < startSeq {
		return nil, fmt.Errorf("invalid range proof request")
	}
	hashes := make([][]byte, len(records))
	for i := range records {
		hashes[i] = records[i].RecordHash
	}
	proof := RangeProof{Version: 1, Source: source, StartSeq: startSeq, EndSeq: endSeq}
	for seq := startSeq; seq <= endSeq; seq++ {
		if seq > uint64(len(records)) {
			proof.MissingSeqs = append(proof.MissingSeqs, seq)
			continue
		}
		index := int(seq - 1)
		proof.Records = append(proof.Records, records[index])
		proof.Inclusion = append(proof.Inclusion, merkleProof(hashes, index))
	}
	return &proof, nil
}

func buildCopyRangeProof(records []Record, summary SealSummary, startSeq, endSeq uint64) (*RangeProof, error) {
	if startSeq == 0 || endSeq < startSeq || endSeq > summary.RecordCount {
		return nil, fmt.Errorf("invalid range proof request")
	}
	leafHashes := make([][]byte, summary.RecordCount)
	bySeq := make(map[uint64]Record)
	for _, record := range records {
		if record.Seq > 0 && record.Seq <= summary.RecordCount {
			leafHashes[record.Seq-1] = append([]byte(nil), record.RecordHash...)
			bySeq[record.Seq] = record
		}
	}
	for i := len(records) - 1; i >= 0; i-- {
		record := records[i]
		if record.Seq > 1 && record.Seq <= summary.RecordCount && leafHashes[record.Seq-2] == nil {
			leafHashes[record.Seq-2] = append([]byte(nil), record.PreviousHash...)
		}
	}
	proof := RangeProof{Version: 1, Source: summary.Source, StartSeq: startSeq, EndSeq: endSeq}
	for seq := startSeq; seq <= endSeq; seq++ {
		record, ok := bySeq[seq]
		if !ok {
			proof.MissingSeqs = append(proof.MissingSeqs, seq)
			continue
		}
		if leafHashes[seq-1] == nil {
			return nil, fmt.Errorf("cannot reconstruct proof boundary for sequence %d", seq)
		}
		proof.Records = append(proof.Records, record)
		proof.Inclusion = append(proof.Inclusion, merkleProof(leafHashes, int(seq-1)))
	}
	return &proof, nil
}

func readSourceRecordsLenient(r io.Reader, source string) ([]Record, int, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, err
	}
	var records []Record
	offset := 0
	for offset < len(data) {
		_, payload, storedDigest, next, err := readFrame(data, offset)
		if err != nil {
			var tamper *TamperError
			if errors.As(err, &tamper) && offset < len(data) {
				break
			}
			return nil, offset, err
		}
		if !bytes.Equal(sha256Hash(payload), storedDigest) {
			var damaged envelope
			jsonErr := json.Unmarshal(payload, &damaged)
			if jsonErr == nil && normalizeEvent(damaged.Event).Source == source {
				return nil, next, &TamperError{Kind: TamperRewrite, RecordSeq: damaged.Seq, ByteOffset: int64(offset), Message: "frame checksum mismatch"}
			}
			if jsonErr == nil {
				offset = next
				continue
			}
			return nil, next, &TamperError{Kind: TamperRewrite, RecordSeq: uint64(len(records)) + 1, ByteOffset: int64(offset), Message: "frame checksum mismatch"}
		}
		var env envelope
		if err := json.Unmarshal(payload, &env); err != nil {
			return nil, next, &TamperError{Kind: TamperRewrite, RecordSeq: uint64(len(records)) + 1, ByteOffset: int64(offset), Message: err.Error()}
		}
		event := normalizeEvent(env.Event)
		if event.Source == source {
			records = append(records, Record{Seq: env.Seq, PreviousHash: append([]byte(nil), env.Previous...), Event: event, RecordHash: append([]byte(nil), env.RecordHash...)})
		}
		offset = next
	}
	return records, offset, nil
}

func verifySourceChain(records []Record, source string) error {
	var previous []byte
	for i, record := range records {
		expectedSeq := uint64(i + 1)
		if record.Seq != expectedSeq {
			if record.Seq > expectedSeq {
				return &TamperError{Kind: TamperMiddleDeletion, RecordSeq: expectedSeq, Message: "source sequence number gap"}
			}
			return &TamperError{Kind: TamperInsertion, RecordSeq: record.Seq, Message: "source sequence repeats"}
		}
		if !bytes.Equal(record.PreviousHash, previous) {
			return &TamperError{Kind: TamperInsertion, RecordSeq: record.Seq, Message: "record breaks the source hash chain"}
		}
		if !bytes.Equal(record.RecordHash, hashRecord(record.Seq, previous, record.Event)) {
			return &TamperError{Kind: TamperRewrite, RecordSeq: record.Seq, Message: "record content hash mismatch"}
		}
		previous = record.RecordHash
	}
	return nil
}

func VerifyRangeProof(proof RangeProof, summary SealSummary) error {
	if proof.Version != 1 || summary.Version != 1 || proof.Source == "" || proof.Source != summary.Source || proof.StartSeq == 0 || proof.EndSeq < proof.StartSeq {
		return fmt.Errorf("invalid range proof or seal summary")
	}
	if len(summary.MerkleRoot) != hashLength || proof.EndSeq > summary.RecordCount {
		return fmt.Errorf("range proof does not fit the sealed summary")
	}
	missing := make(map[uint64]bool)
	for _, seq := range proof.MissingSeqs {
		if seq < proof.StartSeq || seq > proof.EndSeq || missing[seq] {
			return fmt.Errorf("invalid missing sequence marker")
		}
		missing[seq] = true
	}
	if len(proof.Records) != len(proof.Inclusion) {
		return fmt.Errorf("range proof has mismatched records and inclusion proofs")
	}
	present := make(map[uint64]bool)
	var previousSeq uint64
	for i, record := range proof.Records {
		if record.Event.Source != proof.Source || record.Seq < proof.StartSeq || record.Seq > proof.EndSeq || present[record.Seq] {
			return &TamperError{Kind: TamperRewrite, RecordSeq: record.Seq, Message: "range proof contains an invalid record"}
		}
		if missing[record.Seq] {
			return fmt.Errorf("sequence marked both present and missing")
		}
		if !bytes.Equal(record.RecordHash, hashRecord(record.Seq, record.PreviousHash, record.Event)) {
			return &TamperError{Kind: TamperRewrite, RecordSeq: record.Seq, Message: "range proof record hash mismatch"}
		}
		if !verifyMerkleProof(record.RecordHash, int(record.Seq-1), proof.Inclusion[i], summary.MerkleRoot) {
			return &TamperError{Kind: TamperRewrite, RecordSeq: record.Seq, Message: "record is not committed by the sealed merkle root"}
		}
		if previousSeq != 0 {
			for seq := previousSeq + 1; seq < record.Seq; seq++ {
				if !missing[seq] {
					return &TamperError{Kind: TamperMiddleDeletion, RecordSeq: seq, Message: "required sequence is absent from the range proof"}
				}
			}
		}
		present[record.Seq] = true
		previousSeq = record.Seq
	}
	for seq := proof.StartSeq; seq <= proof.EndSeq; seq++ {
		if !present[seq] && !missing[seq] {
			return &TamperError{Kind: TamperMiddleDeletion, RecordSeq: seq, Message: "required sequence is absent from the range proof"}
		}
	}
	if len(missing) > 0 {
		return &RangeIncompleteError{Source: proof.Source, MissingSeqs: proof.MissingSeqs}
	}
	return nil
}

type RangeIncompleteError struct {
	Source      string
	MissingSeqs []uint64
}

func (e *RangeIncompleteError) Error() string {
	return fmt.Sprintf("range proof for source %q is missing sequences %v", e.Source, e.MissingSeqs)
}
