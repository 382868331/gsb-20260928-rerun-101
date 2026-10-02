package audit

import (
	"bytes"
	"errors"
	"fmt"
	"time"
)

var (
	ErrDisclosureGrant        = errors.New("invalid disclosure grant")
	ErrIncompatibleDisclosure = errors.New("incompatible disclosure")
	ErrDisclosureConflict     = errors.New("conflicting disclosure")
)

// DisclosureGrant identifies the receiver and the permission under which a
// visible range was released. Two materials for the same receiver remain
// separate when their permission names differ.
type DisclosureGrant struct {
	Recipient  string `json:"recipient"`
	Permission string `json:"permission,omitempty"`
}

// Disclosure is a receiver-specific material. It contains the visible records
// and enough sealed metadata to distinguish records outside the grant from
// records missing through tampering.
type Disclosure struct {
	Version        uint64          `json:"version"`
	Grant          DisclosureGrant `json:"grant"`
	Seal           SealSummary     `json:"seal"`
	Proof          RangeProof      `json:"proof"`
	InheritedSeals []SealSummary   `json:"inherited_seals,omitempty"`
	ReleasedAt     time.Time       `json:"released_at"`
}

// BuildDisclosure seals the current source prefix and releases one range to
// the named receiver. The returned value is safe for the caller to serialize
// outside the audit store.
func (s *Store) BuildDisclosure(source string, startSeq, endSeq uint64, grant DisclosureGrant) (*Disclosure, error) {
	if err := validateGrant(grant); err != nil {
		return nil, err
	}
	seal, err := s.Seal(source)
	if err != nil {
		return nil, err
	}
	proof, err := s.BuildRangeProof(source, startSeq, endSeq)
	if err != nil {
		return nil, err
	}
	return NewDisclosure(*seal, *proof, grant)
}

// NewDisclosure packages an already trusted seal and verified range proof for
// one receiver.
func NewDisclosure(seal SealSummary, proof RangeProof, grant DisclosureGrant) (*Disclosure, error) {
	if err := validateGrant(grant); err != nil {
		return nil, err
	}
	if err := VerifyRangeProof(seal, proof); err != nil {
		return nil, err
	}
	return &Disclosure{
		Version:        2,
		Grant:          normalizeGrant(grant),
		Seal:           copySeal(seal),
		Proof:          copyProof(proof),
		InheritedSeals: []SealSummary{copySeal(seal)},
		ReleasedAt:     time.Now().UTC(),
	}, nil
}

// Narrow returns a material whose interval is contained by the current one.
// The child keeps the same seal and records the inherited seal basis.
func (d Disclosure) Narrow(startSeq, endSeq uint64) (*Disclosure, error) {
	if err := d.Verify(); err != nil {
		return nil, err
	}
	if startSeq < d.Proof.StartSeq || endSeq > d.Proof.EndSeq || startSeq == 0 || endSeq < startSeq {
		return nil, fmt.Errorf("%w: requested range is not contained by the authorized range", ErrInvalidRange)
	}

	proof := RangeProof{
		Version:     d.Proof.Version,
		Source:      d.Proof.Source,
		StartSeq:    startSeq,
		EndSeq:      endSeq,
		SealedCount: d.Proof.SealedCount,
		Records:     make([]Record, 0, endSeq-startSeq+1),
		MerkleSteps: make([][]MerkleProofStep, 0, endSeq-startSeq+1),
	}
	for seq := startSeq; seq <= endSeq; seq++ {
		index := int(seq - d.Proof.StartSeq)
		proof.Records = append(proof.Records, copyRecord(d.Proof.Records[index]))
		proof.MerkleSteps = append(proof.MerkleSteps, copyMerkleSteps(d.Proof.MerkleSteps[index]))
	}
	if startSeq == d.Proof.StartSeq {
		proof.FirstPrevious = append([]byte(nil), d.Proof.FirstPrevious...)
	} else {
		previousIndex := int(startSeq - d.Proof.StartSeq - 1)
		proof.FirstPrevious = append([]byte(nil), d.Proof.Records[previousIndex].RecordHash...)
	}

	child := Disclosure{
		Version:        2,
		Grant:          copyGrant(d.Grant),
		Seal:           copySeal(d.Seal),
		Proof:          proof,
		InheritedSeals: copySeals(d.InheritedSeals),
		ReleasedAt:     time.Now().UTC(),
	}
	if !containsSeal(child.InheritedSeals, d.Seal) {
		child.InheritedSeals = append(child.InheritedSeals, copySeal(d.Seal))
	}
	return &child, nil
}

// MergeDisclosures combines two adjacent or overlapping ranges for the same
// receiver under exactly the same seal and permission. Duplicated overlapping
// records are counted once. A contradictory overlap is reported without
// producing a merged material.
func MergeDisclosures(first, second Disclosure) (*Disclosure, error) {
	if first.Grant != second.Grant {
		return nil, fmt.Errorf("%w: grants differ", ErrIncompatibleDisclosure)
	}
	if err := validateSummary(first.Seal); err != nil {
		return nil, err
	}
	if err := validateSummary(second.Seal); err != nil {
		return nil, err
	}
	if !sameSealBasis(first.Seal, second.Seal) {
		return nil, fmt.Errorf("%w: seal basis differs for source %q", ErrIncompatibleDisclosure, first.Seal.Source)
	}
	if err := validateProofShape(first.Seal, first.Proof); err != nil {
		return nil, err
	}
	if err := validateProofShape(second.Seal, second.Proof); err != nil {
		return nil, err
	}
	if rangesOverlap(first.Proof, second.Proof) {
		if err := requireSameOverlap(first.Proof, second.Proof); err != nil {
			return nil, err
		}
	}
	if err := first.Verify(); err != nil {
		return nil, err
	}
	if err := second.Verify(); err != nil {
		return nil, err
	}
	if !rangesAdjacentOrOverlap(first.Proof, second.Proof) {
		return nil, fmt.Errorf("%w: ranges are neither adjacent nor overlapping", ErrIncompatibleDisclosure)
	}

	start := minUint64(first.Proof.StartSeq, second.Proof.StartSeq)
	end := maxUint64(first.Proof.EndSeq, second.Proof.EndSeq)
	recordsBySeq := make(map[uint64]Record, end-start+1)
	stepsBySeq := make(map[uint64][]MerkleProofStep, end-start+1)
	var firstPrevious []byte
	addProof := func(proof RangeProof) {
		for i, record := range proof.Records {
			seq := proof.StartSeq + uint64(i)
			if _, exists := recordsBySeq[seq]; !exists {
				recordsBySeq[seq] = copyRecord(record)
				stepsBySeq[seq] = copyMerkleSteps(proof.MerkleSteps[i])
			}
			if proof.StartSeq == start && len(proof.FirstPrevious) > 0 {
				firstPrevious = append([]byte(nil), proof.FirstPrevious...)
			}
		}
	}
	addProof(first.Proof)
	addProof(second.Proof)

	merged := RangeProof{
		Version:       2,
		Source:        first.Proof.Source,
		StartSeq:      start,
		EndSeq:        end,
		SealedCount:   first.Proof.SealedCount,
		FirstPrevious: firstPrevious,
		Records:       make([]Record, 0, end-start+1),
		MerkleSteps:   make([][]MerkleProofStep, 0, end-start+1),
	}
	for seq := start; seq <= end; seq++ {
		merged.Records = append(merged.Records, recordsBySeq[seq])
		merged.MerkleSteps = append(merged.MerkleSteps, stepsBySeq[seq])
	}
	if err := VerifyRangeProof(first.Seal, merged); err != nil {
		return nil, err
	}
	basis := mergeSealBases(first.InheritedSeals, second.InheritedSeals, first.Seal)
	return &Disclosure{
		Version:        2,
		Grant:          copyGrant(first.Grant),
		Seal:           copySeal(first.Seal),
		Proof:          merged,
		InheritedSeals: basis,
		ReleasedAt:     time.Now().UTC(),
	}, nil
}

// Verify checks the cryptographic material and its receiver-specific boundary.
func (d Disclosure) Verify() error {
	if d.Version != 2 {
		return fmt.Errorf("%w: unsupported disclosure version", ErrDisclosureGrant)
	}
	if err := validateGrant(d.Grant); err != nil {
		return err
	}
	return VerifyRangeProof(d.Seal, d.Proof)
}

// VerifyForReceiver fails a material that was released to another receiver or
// under another permission.
func (d Disclosure) VerifyForReceiver(grant DisclosureGrant) error {
	if d.Grant != normalizeGrant(grant) {
		return fmt.Errorf("%w: material was not released to this receiver", ErrDisclosureGrant)
	}
	return d.Verify()
}

// VisibleCount returns the number of records included in the receiver's grant.
func (d Disclosure) VisibleCount() uint64 { return d.Proof.EndSeq - d.Proof.StartSeq + 1 }

// OutsideVisibleCount returns sealed records that exist but are outside this
// receiver's interval. They are hidden, not missing.
func (d Disclosure) OutsideVisibleCount() uint64 {
	return d.Proof.SealedCount - d.VisibleCount()
}

func validateGrant(grant DisclosureGrant) error {
	grant = normalizeGrant(grant)
	if grant.Recipient == "" {
		return fmt.Errorf("%w: recipient is required", ErrDisclosureGrant)
	}
	return nil
}

func normalizeGrant(grant DisclosureGrant) DisclosureGrant {
	if grant.Permission == "" {
		grant.Permission = grant.Recipient
	}
	return grant
}

func copyGrant(grant DisclosureGrant) DisclosureGrant { return grant }

func copySeal(summary SealSummary) SealSummary {
	summary.LastHash = append([]byte(nil), summary.LastHash...)
	summary.MerkleRoot = append([]byte(nil), summary.MerkleRoot...)
	return summary
}

func copySeals(summaries []SealSummary) []SealSummary {
	out := make([]SealSummary, 0, len(summaries))
	for _, summary := range summaries {
		out = append(out, copySeal(summary))
	}
	return out
}

func copyRecord(record Record) Record {
	record.RecordHash = append([]byte(nil), record.RecordHash...)
	record.Event.Payload = append([]byte(nil), record.Event.Payload...)
	return record
}

func copyMerkleSteps(steps []MerkleProofStep) []MerkleProofStep {
	out := make([]MerkleProofStep, len(steps))
	for i, step := range steps {
		out[i] = MerkleProofStep{Hash: append([]byte(nil), step.Hash...), Left: step.Left}
	}
	return out
}

func copyProof(proof RangeProof) RangeProof {
	records := proof.Records
	stepsByRecord := proof.MerkleSteps
	proof.FirstPrevious = append([]byte(nil), proof.FirstPrevious...)
	proof.Records = make([]Record, len(records))
	for i, record := range records {
		proof.Records[i] = copyRecord(record)
	}
	proof.MerkleSteps = make([][]MerkleProofStep, len(stepsByRecord))
	for i, steps := range stepsByRecord {
		proof.MerkleSteps[i] = copyMerkleSteps(steps)
	}
	return proof
}

func sameSealBasis(a, b SealSummary) bool {
	return a.Version == b.Version && a.Source == b.Source && a.RecordCount == b.RecordCount &&
		bytes.Equal(a.LastHash, b.LastHash) && bytes.Equal(a.MerkleRoot, b.MerkleRoot)
}

func containsSeal(summaries []SealSummary, summary SealSummary) bool {
	for _, candidate := range summaries {
		if sameSealBasis(candidate, summary) {
			return true
		}
	}
	return false
}

func mergeSealBases(first, second []SealSummary, current SealSummary) []SealSummary {
	out := copySeals(first)
	for _, summary := range second {
		if !containsSeal(out, summary) {
			out = append(out, copySeal(summary))
		}
	}
	if !containsSeal(out, current) {
		out = append(out, copySeal(current))
	}
	return out
}

func rangesOverlap(a, b RangeProof) bool {
	return a.StartSeq <= b.EndSeq && b.StartSeq <= a.EndSeq
}

func rangesAdjacentOrOverlap(a, b RangeProof) bool {
	return rangesOverlap(a, b) || a.EndSeq+1 == b.StartSeq || b.EndSeq+1 == a.StartSeq
}

func validateProofShape(summary SealSummary, proof RangeProof) error {
	if proof.Version != 2 || proof.Source != summary.Source || proof.SealedCount != summary.RecordCount {
		return &TamperError{Kind: TamperWrongSource, Message: "range proof does not match the external seal summary"}
	}
	if proof.StartSeq == 0 || proof.EndSeq < proof.StartSeq || proof.EndSeq > proof.SealedCount {
		return &TamperError{Kind: TamperMissingRange, RecordSeq: proof.StartSeq, Message: "range proof has an invalid sealed interval"}
	}
	count := int(proof.EndSeq - proof.StartSeq + 1)
	if len(proof.Records) != count || len(proof.MerkleSteps) != count {
		return &TamperError{Kind: TamperMissingRange, RecordSeq: proof.StartSeq, Message: "range proof omits a required sequence number"}
	}
	return nil
}

func requireSameOverlap(a, b RangeProof) error {
	left := maxUint64(a.StartSeq, b.StartSeq)
	right := minUint64(a.EndSeq, b.EndSeq)
	recordA := make(map[uint64]Record)
	recordB := make(map[uint64]Record)
	for i, record := range a.Records {
		recordA[a.StartSeq+uint64(i)] = record
	}
	for i, record := range b.Records {
		recordB[b.StartSeq+uint64(i)] = record
	}
	for seq := left; seq <= right; seq++ {
		firstRecord := recordA[seq]
		secondRecord := recordB[seq]
		if !bytes.Equal(firstRecord.RecordHash, secondRecord.RecordHash) {
			return fmt.Errorf("%w: source %q seq %d has different sealed hashes", ErrDisclosureConflict, a.Source, seq)
		}
	}
	return nil
}

func minUint64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func maxUint64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
