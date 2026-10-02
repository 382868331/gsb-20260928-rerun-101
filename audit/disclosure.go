package audit

import (
	"bytes"
	"errors"
	"fmt"
)

// ErrDisclosureConflict reports overlapping records that carry the same
// sequence number but different content. Both disclosures are retained by
// the caller; the merge is refused.
var ErrDisclosureConflict = errors.New("disclosure records conflict")

// ErrDisclosureMismatch reports an attempt to combine disclosures that do
// not share the same seal basis, source, and recipient. Matching source
// names alone never authorize a merge.
var ErrDisclosureMismatch = errors.New("disclosures do not share seal, source, and recipient")

// DisclosureConflictError identifies the sequence number whose two versions
// disagree, so auditors can keep both materials on file.
type DisclosureConflictError struct {
	Seq   uint64
	HashA []byte
	HashB []byte
}

func (e *DisclosureConflictError) Error() string {
	return fmt.Sprintf("%s at seq %d", ErrDisclosureConflict, e.Seq)
}

// Disclosure is a per-recipient narrowed view derived from an already
// verified range proof. SealID records which external seal summary the
// material inherits its trust from; a recipient can only ever verify the
// window [StartSeq, EndSeq] and must not treat records outside it as
// missing.
type Disclosure struct {
	Version       uint64              `json:"version"`
	SealID        string              `json:"seal_id"`
	Source        string              `json:"source"`
	Recipient     string              `json:"recipient"`
	StartSeq      uint64              `json:"start_seq"`
	EndSeq        uint64              `json:"end_seq"`
	SealedCount   uint64              `json:"sealed_count"`
	ParentStart   uint64              `json:"parent_start"`
	ParentEnd     uint64              `json:"parent_end"`
	FirstPrevious []byte              `json:"first_previous_hash,omitempty"`
	Records       []Record            `json:"records"`
	MerkleSteps   [][]MerkleProofStep `json:"merkle_steps"`
}

// NarrowDisclosure verifies the parent range proof against the externally
// retained seal summary, then extracts the sub-range the recipient is
// allowed to see. The result names the seal basis it inherits (SealID) and
// the parent window it was narrowed from.
func NarrowDisclosure(summary SealSummary, parent RangeProof, recipient string, startSeq, endSeq uint64) (*Disclosure, error) {
	if recipient == "" {
		return nil, errors.New("disclosure recipient is required")
	}
	if err := VerifyRangeProof(summary, parent); err != nil {
		return nil, err
	}
	if startSeq == 0 || endSeq < startSeq {
		return nil, fmt.Errorf("%w: empty range", ErrInvalidRange)
	}
	if startSeq < parent.StartSeq || endSeq > parent.EndSeq {
		return nil, fmt.Errorf("%w: narrowed range %d-%d exceeds the verified parent range %d-%d",
			ErrInvalidRange, startSeq, endSeq, parent.StartSeq, parent.EndSeq)
	}
	offset := startSeq - parent.StartSeq
	count := endSeq - startSeq + 1
	records := make([]Record, 0, count)
	steps := make([][]MerkleProofStep, 0, count)
	for i := uint64(0); i < count; i++ {
		records = append(records, parent.Records[offset+i])
		steps = append(steps, parent.MerkleSteps[offset+i])
	}
	var firstPrevious []byte
	if startSeq == parent.StartSeq {
		firstPrevious = append([]byte(nil), parent.FirstPrevious...)
	} else {
		firstPrevious = append([]byte(nil), parent.Records[offset-1].RecordHash...)
	}
	return &Disclosure{
		Version:       2,
		SealID:        summary.ID(),
		Source:        parent.Source,
		Recipient:     recipient,
		StartSeq:      startSeq,
		EndSeq:        endSeq,
		SealedCount:   parent.SealedCount,
		ParentStart:   parent.StartSeq,
		ParentEnd:     parent.EndSeq,
		FirstPrevious: firstPrevious,
		Records:       records,
		MerkleSteps:   steps,
	}, nil
}

// VerifyDisclosure checks one recipient's window against the seal summary
// the recipient independently trusts. Records outside [StartSeq, EndSeq]
// are invisible to this recipient and are never reported as missing; only
// the disclosed window is checked for gaps, wrong source, or tampering.
func VerifyDisclosure(summary SealSummary, d Disclosure) error {
	if err := validateSummary(summary); err != nil {
		return err
	}
	if d.Version != 2 || d.SealID != summary.ID() || d.Source != summary.Source || d.SealedCount != summary.RecordCount {
		return &TamperError{Kind: TamperWrongSource, Message: "disclosure does not match the external seal summary it claims to inherit"}
	}
	if d.StartSeq == 0 || d.EndSeq < d.StartSeq {
		return &TamperError{Kind: TamperMissingRange, Message: "disclosed range is empty"}
	}
	if d.EndSeq > d.SealedCount {
		return &TamperError{Kind: TamperMissingRange, RecordSeq: d.SealedCount + 1, Message: "disclosed range extends past the sealed segment boundary"}
	}
	if len(d.Records) != int(d.EndSeq-d.StartSeq+1) || len(d.MerkleSteps) != len(d.Records) {
		return &TamperError{Kind: TamperMissingRange, RecordSeq: d.StartSeq, Message: "disclosure omits a sequence number inside the recipient's own window"}
	}
	var previous []byte
	for i, record := range d.Records {
		seq := d.StartSeq + uint64(i)
		if record.Seq != seq || record.Event.Source != d.Source {
			kind := TamperWrongSource
			if record.Event.Source == d.Source {
				kind = TamperMissingRange
			}
			return &TamperError{Kind: kind, RecordSeq: seq, Message: "disclosed record has the wrong sequence or source"}
		}
		if i == 0 {
			previous = d.FirstPrevious
		} else {
			previous = d.Records[i-1].RecordHash
		}
		if !bytes.Equal(record.RecordHash, hashRecord(seq, previous, record.Event)) {
			return &TamperError{Kind: TamperRewrite, RecordSeq: seq, Message: "disclosed record hash does not match its content"}
		}
		if !verifyMerkleProof(summary.MerkleRoot, record.RecordHash, int(seq-1), d.MerkleSteps[i]) {
			return &TamperError{Kind: TamperRewrite, RecordSeq: seq, Message: "disclosed record is not included in the sealed segment Merkle root"}
		}
	}
	if d.EndSeq == d.SealedCount && !bytes.Equal(d.Records[len(d.Records)-1].RecordHash, summary.LastHash) {
		return &TamperError{Kind: TamperSegmentReplacement, RecordSeq: d.SealedCount, Message: "sealed final hash does not match"}
	}
	return nil
}

// MergeDisclosures combines two disclosures that share the same seal basis,
// source, and recipient when their windows are adjacent or overlapping.
// Overlapping records are counted once. If overlapping content disagrees,
// both disclosures are left untouched and a *DisclosureConflictError is
// returned so the caller keeps both materials on file.
func MergeDisclosures(a, b Disclosure) (*Disclosure, error) {
	if a.SealID == "" || a.SealID != b.SealID || a.Source != b.Source || a.Recipient != b.Recipient ||
		a.SealedCount != b.SealedCount || a.Version != b.Version {
		return nil, ErrDisclosureMismatch
	}
	lo, hi := a, b
	if b.StartSeq < a.StartSeq {
		lo, hi = b, a
	}
	if hi.StartSeq > lo.EndSeq+1 {
		return nil, fmt.Errorf("%w: windows %d-%d and %d-%d are neither adjacent nor overlapping",
			ErrInvalidRange, lo.StartSeq, lo.EndSeq, hi.StartSeq, hi.EndSeq)
	}
	end := lo.EndSeq
	if hi.EndSeq > end {
		end = hi.EndSeq
	}
	merged := &Disclosure{
		Version:     lo.Version,
		SealID:      lo.SealID,
		Source:      lo.Source,
		Recipient:   lo.Recipient,
		StartSeq:    lo.StartSeq,
		EndSeq:      end,
		SealedCount: lo.SealedCount,
	}
	if lo.ParentStart < hi.ParentStart {
		merged.ParentStart = lo.ParentStart
	} else {
		merged.ParentStart = hi.ParentStart
	}
	if lo.ParentEnd > hi.ParentEnd {
		merged.ParentEnd = lo.ParentEnd
	} else {
		merged.ParentEnd = hi.ParentEnd
	}
	bySeq := make(map[uint64]int, end-lo.StartSeq+1)
	for _, d := range []Disclosure{lo, hi} {
		for i, record := range d.Records {
			seq := d.StartSeq + uint64(i)
			if at, seen := bySeq[seq]; seen {
				existing := merged.Records[at]
				if !bytes.Equal(existing.RecordHash, record.RecordHash) || !recordsEqual(existing, record) {
					return nil, &DisclosureConflictError{Seq: seq, HashA: existing.RecordHash, HashB: record.RecordHash}
				}
				continue
			}
			bySeq[seq] = len(merged.Records)
			merged.Records = append(merged.Records, record)
			merged.MerkleSteps = append(merged.MerkleSteps, d.MerkleSteps[i])
		}
	}
	merged.FirstPrevious = append([]byte(nil), lo.FirstPrevious...)
	return merged, nil
}

func recordsEqual(a, b Record) bool {
	return a.Seq == b.Seq &&
		a.Event.ID == b.Event.ID &&
		a.Event.Source == b.Event.Source &&
		a.Event.Type == b.Event.Type &&
		a.Event.OccurredAt.Equal(b.Event.OccurredAt) &&
		bytes.Equal(a.Event.Payload, b.Event.Payload)
}
