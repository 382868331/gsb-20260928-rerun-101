package audit

import (
	"bytes"
	"errors"
	"fmt"
)

var ErrInvalidRange = errors.New("invalid audit range")

// SourceRangeRequest names one independently numbered source segment and the
// inclusive sequence range the receiver is allowed to see.
type SourceRangeRequest struct {
	Source   string `json:"source"`
	StartSeq uint64 `json:"start_seq"`
	EndSeq   uint64 `json:"end_seq"`
}

// CombinedRangeProof bundles per-source range proofs. Each range is anchored
// to its own source's seal summary. The bundle deliberately carries no
// cross-source ordering: event timestamps from different sources are not a
// trusted global sequence, and verification never derives one from them.
type CombinedRangeProof struct {
	Version uint64       `json:"version"`
	Ranges  []RangeProof `json:"ranges"`
}

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

// BuildSealedRangeProof builds a range proof anchored to a specific,
// externally retained seal summary. Appends made after that seal form a new
// seal and do not change what the old summary covers, so proofs for the old
// summary remain buildable and verifiable. The store must still contain the
// exact sealed prefix; otherwise the proof would borrow records the summary
// does not cover.
func (s *Store) BuildSealedRangeProof(summary SealSummary, startSeq, endSeq uint64) (*RangeProof, error) {
	if err := validateSummary(summary); err != nil {
		return nil, err
	}
	if startSeq == 0 || endSeq < startSeq {
		return nil, ErrInvalidRange
	}
	if endSeq > summary.RecordCount {
		return nil, fmt.Errorf("%w: source %q sealed through seq %d", ErrInvalidRange, summary.Source, summary.RecordCount)
	}
	state := s.sources[summary.Source]
	if state == nil || uint64(len(state.records)) < summary.RecordCount {
		return nil, fmt.Errorf("%w: store no longer holds the sealed prefix of source %q", ErrInvalidRange, summary.Source)
	}
	sealedLast := state.records[summary.RecordCount-1].RecordHash
	if !bytes.Equal(sealedLast, summary.LastHash) {
		return nil, fmt.Errorf("%w: store prefix does not match the seal summary for source %q", ErrInvalidRange, summary.Source)
	}
	leaves := make([][]byte, summary.RecordCount)
	for i := range leaves {
		leaves[i] = append([]byte(nil), state.records[i].RecordHash...)
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
		Source:        summary.Source,
		StartSeq:      startSeq,
		EndSeq:        endSeq,
		SealedCount:   summary.RecordCount,
		FirstPrevious: firstPrevious,
		Records:       records,
		MerkleSteps:   steps,
	}, nil
}

// BuildCombinedRangeProof assembles one range proof per requested source,
// each anchored to that source's own seal summary. Sources stay independent:
// the result does not merge, sort, or compare events across sources.
func (s *Store) BuildCombinedRangeProof(summaries []SealSummary, requests []SourceRangeRequest) (*CombinedRangeProof, error) {
	if len(requests) == 0 {
		return nil, fmt.Errorf("%w: combined proof needs at least one source range", ErrInvalidRange)
	}
	bySource := make(map[string]SealSummary, len(summaries))
	for _, summary := range summaries {
		if err := validateSummary(summary); err != nil {
			return nil, err
		}
		if _, dup := bySource[summary.Source]; dup {
			return nil, fmt.Errorf("%w: duplicate seal summary for source %q", ErrInvalidRange, summary.Source)
		}
		bySource[summary.Source] = summary
	}
	seen := make(map[string]bool, len(requests))
	ranges := make([]RangeProof, 0, len(requests))
	for _, request := range requests {
		if seen[request.Source] {
			return nil, fmt.Errorf("%w: duplicate range request for source %q", ErrInvalidRange, request.Source)
		}
		seen[request.Source] = true
		summary, ok := bySource[request.Source]
		if !ok {
			return nil, fmt.Errorf("%w: no seal summary for source %q", ErrInvalidRange, request.Source)
		}
		proof, err := s.BuildSealedRangeProof(summary, request.StartSeq, request.EndSeq)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, *proof)
	}
	return &CombinedRangeProof{Version: 2, Ranges: ranges}, nil
}

// VerifyCombinedRangeProof verifies every range in the bundle against the
// externally retained seal summary for that range's source. Each source is
// checked on its own chain; a valid bundle says nothing about the relative
// order of events from different sources, and event timestamps must not be
// read as a trusted global sequence.
func VerifyCombinedRangeProof(summaries []SealSummary, proof CombinedRangeProof) error {
	if proof.Version != 2 || len(proof.Ranges) == 0 {
		return &TamperError{Kind: TamperMissingRange, Message: "combined proof is empty or has an unsupported version"}
	}
	bySource := make(map[string]SealSummary, len(summaries))
	for _, summary := range summaries {
		if err := validateSummary(summary); err != nil {
			return err
		}
		if _, dup := bySource[summary.Source]; dup {
			return &TamperError{Kind: TamperWrongSource, Message: "duplicate seal summary for source " + summary.Source}
		}
		bySource[summary.Source] = summary
	}
	seen := make(map[string]bool, len(proof.Ranges))
	for _, rangeProof := range proof.Ranges {
		if seen[rangeProof.Source] {
			return &TamperError{Kind: TamperWrongSource, Message: "combined proof repeats source " + rangeProof.Source}
		}
		seen[rangeProof.Source] = true
		summary, ok := bySource[rangeProof.Source]
		if !ok {
			return &TamperError{Kind: TamperWrongSource, Message: "no seal summary for proof source " + rangeProof.Source}
		}
		if err := VerifyRangeProof(summary, rangeProof); err != nil {
			return err
		}
	}
	return nil
}
