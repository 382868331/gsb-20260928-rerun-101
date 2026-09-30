package audit

import (
	"bytes"
	"errors"
	"fmt"
)

var ErrInvalidRange = errors.New("invalid audit range")

type RangeProof struct {
	Version       uint64              `json:"version"`
	Source        string              `json:"source"`
	StartSeq      uint64              `json:"start_seq"`
	EndSeq        uint64              `json:"end_seq"`
	SealedCount   uint64              `json:"sealed_count"`
	FirstPrevious []byte              `json:"first_previous_hash,omitempty"`
	Records       []Record            `json:"records"`
	MerkleSteps   [][]MerkleProofStep `json:"merkle_steps"`
}

// BuildRangeProof returns only the requested source records plus hash nodes
// needed to anchor them in the externally retained sealed Merkle root.
func (s *Store) BuildRangeProof(source string, startSeq, endSeq uint64) (*RangeProof, error) {
	state := s.sources[source]
	if state == nil || startSeq == 0 || endSeq < startSeq {
		return nil, ErrInvalidRange
	}
	if endSeq > uint64(len(state.records)) {
		return nil, fmt.Errorf("%w: source %q sealed through seq %d", ErrInvalidRange, source, len(state.records))
	}
	leaves := make([][]byte, len(state.records))
	for i, record := range state.records {
		leaves[i] = append([]byte(nil), record.RecordHash...)
	}
	records := make([]Record, 0, endSeq-startSeq+1)
	steps := make([][]MerkleProofStep, 0, endSeq-startSeq+1)
	for seq := startSeq; seq <= endSeq; seq++ {
		index := int(seq - 1)
		records = append(records, state.records[index])
		steps = append(steps, merkleProof(leaves, index))
	}
	var firstPrevious []byte
	if startSeq > 1 {
		firstPrevious = append([]byte(nil), state.records[startSeq-2].RecordHash...)
	}
	return &RangeProof{
		Version:       2,
		Source:        source,
		StartSeq:      startSeq,
		EndSeq:        endSeq,
		SealedCount:   uint64(len(state.records)),
		FirstPrevious: firstPrevious,
		Records:       records,
		MerkleSteps:   steps,
	}, nil
}

// VerifyRangeProof checks a narrow proof against a summary the verifier already
// trusts. It does not require access to records outside the requested range.
func VerifyRangeProof(summary SealSummary, proof RangeProof) error {
	if err := validateSummary(summary); err != nil {
		return err
	}
	if proof.Version != 2 || proof.Source != summary.Source || proof.SealedCount != summary.RecordCount {
		return &TamperError{Kind: TamperWrongSource, Message: "range proof does not match the external seal summary"}
	}
	if proof.StartSeq == 0 || proof.EndSeq < proof.StartSeq || proof.EndSeq > proof.SealedCount {
		return &TamperError{Kind: TamperMissingRange, Message: "requested range is outside the sealed segment"}
	}
	if len(proof.Records) != int(proof.EndSeq-proof.StartSeq+1) || len(proof.MerkleSteps) != len(proof.Records) {
		return &TamperError{Kind: TamperMissingRange, RecordSeq: proof.StartSeq, Message: "range proof omits a required sequence number"}
	}
	var previous []byte
	for i, record := range proof.Records {
		seq := proof.StartSeq + uint64(i)
		if record.Seq != seq || record.Event.Source != proof.Source {
			kind := TamperWrongSource
			if record.Event.Source == proof.Source {
				kind = TamperMissingRange
			}
			return &TamperError{Kind: kind, RecordSeq: seq, Message: "range record has the wrong sequence or source"}
		}
		if i == 0 {
			previous = proof.FirstPrevious
		} else {
			previous = proof.Records[i-1].RecordHash
		}
		expectedHash := hashRecord(seq, previous, record.Event)
		if !bytes.Equal(record.RecordHash, expectedHash) {
			return &TamperError{Kind: TamperRewrite, RecordSeq: seq, Message: "range record hash does not match its content"}
		}
		if !verifyMerkleProof(summary.MerkleRoot, record.RecordHash, int(seq-1), proof.MerkleSteps[i]) {
			return &TamperError{Kind: TamperRewrite, RecordSeq: seq, Message: "record is not included in the sealed segment Merkle root"}
		}
	}
	if proof.EndSeq == proof.SealedCount && !bytes.Equal(proof.Records[len(proof.Records)-1].RecordHash, summary.LastHash) {
		return &TamperError{Kind: TamperSegmentReplacement, RecordSeq: proof.SealedCount, Message: "sealed final hash does not match"}
	}
	return nil
}
