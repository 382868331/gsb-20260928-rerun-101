package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrBeyondAuthorization reports an attempt to derive, verify, or deliver
// material outside the range, content, or onward-transfer limits of the
// authorization it claims to inherit. Holding broader material under the
// same source name never widens what this authorization permits.
var ErrBeyondAuthorization = errors.New("beyond the authorized scope")

// ErrOnwardDenied reports a re-disclosure attempt under an authorization
// that does not allow onward transfer.
var ErrOnwardDenied = errors.New("authorization does not allow onward transfer")

// Authorization is an externally issued permission bound to one seal and
// one recipient. It limits the source, the sequence range, the visible
// event types (empty means all types), and whether the recipient may pass
// derived material on. The authorization itself is retained outside the
// audited file, like the seal summary.
type Authorization struct {
	Version     uint64    `json:"version"`
	ID          string    `json:"id"`
	SealID      string    `json:"seal_id"`
	Source      string    `json:"source"`
	Recipient   string    `json:"recipient"`
	StartSeq    uint64    `json:"start_seq"`
	EndSeq      uint64    `json:"end_seq"`
	Types       []string  `json:"types,omitempty"`
	AllowOnward bool      `json:"allow_onward"`
	IssuedAt    time.Time `json:"issued_at"`
}

// AuthorizationID returns the stable identifier of an authorization. When
// the caller did not assign one, it is derived from the canonical content
// so identical authorizations deduplicate and different ones never collide.
func AuthorizationID(a Authorization) string {
	if a.ID != "" {
		return a.ID
	}
	canonical := struct {
		SealID      string   `json:"seal_id"`
		Source      string   `json:"source"`
		Recipient   string   `json:"recipient"`
		StartSeq    uint64   `json:"start_seq"`
		EndSeq      uint64   `json:"end_seq"`
		Types       []string `json:"types,omitempty"`
		AllowOnward bool     `json:"allow_onward"`
		IssuedAt    string   `json:"issued_at"`
	}{
		SealID:      a.SealID,
		Source:      a.Source,
		Recipient:   a.Recipient,
		StartSeq:    a.StartSeq,
		EndSeq:      a.EndSeq,
		Types:       a.Types,
		AllowOnward: a.AllowOnward,
		IssuedAt:    a.IssuedAt.UTC().Format(timeFormat),
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", sha256Hash(data))
}

func validateAuthorization(a Authorization) error {
	if a.SealID == "" || a.Source == "" || a.Recipient == "" {
		return fmt.Errorf("%w: authorization must name seal, source, and recipient", ErrBeyondAuthorization)
	}
	if a.StartSeq == 0 || a.EndSeq < a.StartSeq {
		return fmt.Errorf("%w: authorization range is empty", ErrInvalidRange)
	}
	return nil
}

func typeAllowed(types []string, eventType string) bool {
	if len(types) == 0 {
		return true
	}
	for _, allowed := range types {
		if allowed == eventType {
			return true
		}
	}
	return false
}

// ReDisclosure is material a recipient passes on to a further recipient
// under an explicit authorization. SealID and AuthorizationID record which
// seal and which authorization the material inherits; neither a matching
// source name nor broader material held elsewhere can widen it.
type ReDisclosure struct {
	Version         uint64              `json:"version"`
	SealID          string              `json:"seal_id"`
	AuthorizationID string              `json:"authorization_id"`
	Source          string              `json:"source"`
	Recipient       string              `json:"recipient"`
	StartSeq        uint64              `json:"start_seq"`
	EndSeq          uint64              `json:"end_seq"`
	SealedCount     uint64              `json:"sealed_count"`
	ParentStart     uint64              `json:"parent_start"`
	ParentEnd       uint64              `json:"parent_end"`
	FirstPrevious   []byte              `json:"first_previous_hash,omitempty"`
	Records         []Record            `json:"records"`
	MerkleSteps     [][]MerkleProofStep `json:"merkle_steps"`
}

// DeriveReDisclosure verifies the parent disclosure against the externally
// retained seal summary, checks the authorization permits onward transfer
// of the requested sub-range to the new recipient, and extracts exactly
// that window. The derived window can never exceed the authorization, even
// when the holder possesses a broader parent disclosure.
func DeriveReDisclosure(summary SealSummary, parent Disclosure, auth Authorization, recipient string, startSeq, endSeq uint64) (*ReDisclosure, error) {
	if recipient == "" {
		return nil, errors.New("re-disclosure recipient is required")
	}
	if err := VerifyDisclosure(summary, parent); err != nil {
		return nil, err
	}
	if err := validateAuthorization(auth); err != nil {
		return nil, err
	}
	if auth.SealID != parent.SealID || auth.Source != parent.Source || auth.Recipient != parent.Recipient {
		return nil, fmt.Errorf("%w: authorization does not belong to this disclosure", ErrBeyondAuthorization)
	}
	if !auth.AllowOnward {
		return nil, ErrOnwardDenied
	}
	if startSeq == 0 || endSeq < startSeq {
		return nil, fmt.Errorf("%w: empty range", ErrInvalidRange)
	}
	if startSeq < auth.StartSeq || endSeq > auth.EndSeq {
		return nil, fmt.Errorf("%w: requested range %d-%d exceeds the authorized range %d-%d",
			ErrBeyondAuthorization, startSeq, endSeq, auth.StartSeq, auth.EndSeq)
	}
	if startSeq < parent.StartSeq || endSeq > parent.EndSeq {
		return nil, fmt.Errorf("%w: requested range %d-%d is not verifiable from the held window %d-%d",
			ErrInvalidRange, startSeq, endSeq, parent.StartSeq, parent.EndSeq)
	}
	offset := startSeq - parent.StartSeq
	count := endSeq - startSeq + 1
	records := make([]Record, 0, count)
	steps := make([][]MerkleProofStep, 0, count)
	for i := uint64(0); i < count; i++ {
		record := parent.Records[offset+i]
		if !typeAllowed(auth.Types, record.Event.Type) {
			return nil, fmt.Errorf("%w: record at seq %d has a type the authorization does not make visible",
				ErrBeyondAuthorization, startSeq+i)
		}
		records = append(records, record)
		steps = append(steps, parent.MerkleSteps[offset+i])
	}
	var firstPrevious []byte
	if startSeq == parent.StartSeq {
		firstPrevious = append([]byte(nil), parent.FirstPrevious...)
	} else {
		firstPrevious = append([]byte(nil), parent.Records[offset-1].RecordHash...)
	}
	return &ReDisclosure{
		Version:         3,
		SealID:          parent.SealID,
		AuthorizationID: AuthorizationID(auth),
		Source:          parent.Source,
		Recipient:       recipient,
		StartSeq:        startSeq,
		EndSeq:          endSeq,
		SealedCount:     parent.SealedCount,
		ParentStart:     parent.StartSeq,
		ParentEnd:       parent.EndSeq,
		FirstPrevious:   firstPrevious,
		Records:         records,
		MerkleSteps:     steps,
	}, nil
}

// VerifyReDisclosure checks a re-disclosed window against the seal summary
// and the authorization the new recipient independently trusts. Records
// outside [StartSeq, EndSeq] are invisible to this recipient and are never
// reported as missing; failures name sequence numbers only and never echo
// record content.
func VerifyReDisclosure(summary SealSummary, auth Authorization, rd ReDisclosure) error {
	if err := validateSummary(summary); err != nil {
		return err
	}
	if err := validateAuthorization(auth); err != nil {
		return err
	}
	if rd.Version != 3 || rd.SealID != summary.ID() || rd.Source != summary.Source || rd.SealedCount != summary.RecordCount {
		return &TamperError{Kind: TamperWrongSource, Message: "re-disclosure does not match the external seal summary it claims to inherit"}
	}
	if rd.AuthorizationID != AuthorizationID(auth) || auth.SealID != rd.SealID || auth.Source != rd.Source {
		return &TamperError{Kind: TamperWrongSource, Message: "re-disclosure does not match the authorization it claims to inherit"}
	}
	if !auth.AllowOnward {
		return ErrOnwardDenied
	}
	if rd.StartSeq == 0 || rd.EndSeq < rd.StartSeq {
		return &TamperError{Kind: TamperMissingRange, Message: "re-disclosed range is empty"}
	}
	if rd.StartSeq < auth.StartSeq || rd.EndSeq > auth.EndSeq {
		return fmt.Errorf("%w: disclosed range %d-%d exceeds the authorized range %d-%d",
			ErrBeyondAuthorization, rd.StartSeq, rd.EndSeq, auth.StartSeq, auth.EndSeq)
	}
	if rd.EndSeq > rd.SealedCount {
		return &TamperError{Kind: TamperMissingRange, RecordSeq: rd.SealedCount + 1, Message: "re-disclosed range extends past the sealed segment boundary"}
	}
	if len(rd.Records) != int(rd.EndSeq-rd.StartSeq+1) || len(rd.MerkleSteps) != len(rd.Records) {
		return &TamperError{Kind: TamperMissingRange, RecordSeq: rd.StartSeq, Message: "re-disclosure omits a sequence number inside the recipient's own window"}
	}
	var previous []byte
	for i, record := range rd.Records {
		seq := rd.StartSeq + uint64(i)
		if record.Seq != seq || record.Event.Source != rd.Source {
			kind := TamperWrongSource
			if record.Event.Source == rd.Source {
				kind = TamperMissingRange
			}
			return &TamperError{Kind: kind, RecordSeq: seq, Message: "re-disclosed record has the wrong sequence or source"}
		}
		if !typeAllowed(auth.Types, record.Event.Type) {
			return fmt.Errorf("%w: record at seq %d has a type the authorization does not make visible",
				ErrBeyondAuthorization, seq)
		}
		if i == 0 {
			previous = rd.FirstPrevious
		} else {
			previous = rd.Records[i-1].RecordHash
		}
		if !bytes.Equal(record.RecordHash, hashRecord(seq, previous, record.Event)) {
			return &TamperError{Kind: TamperRewrite, RecordSeq: seq, Message: "re-disclosed record hash does not match its content"}
		}
		if !verifyMerkleProof(summary.MerkleRoot, record.RecordHash, int(seq-1), rd.MerkleSteps[i]) {
			return &TamperError{Kind: TamperRewrite, RecordSeq: seq, Message: "re-disclosed record is not included in the sealed segment Merkle root"}
		}
	}
	if rd.EndSeq == rd.SealedCount && !bytes.Equal(rd.Records[len(rd.Records)-1].RecordHash, summary.LastHash) {
		return &TamperError{Kind: TamperSegmentReplacement, RecordSeq: rd.SealedCount, Message: "sealed final hash does not match"}
	}
	return nil
}

// MergeReDisclosures combines two re-disclosures only when they share the
// same seal basis, the same authorization, the same source, and the same
// recipient, and their windows are adjacent or overlapping. Material that
// merely looks identical under a different authorization is refused: equal
// content never merges into a wider permission without matching lineage.
func MergeReDisclosures(a, b ReDisclosure) (*ReDisclosure, error) {
	if a.SealID == "" || a.SealID != b.SealID || a.AuthorizationID == "" || a.AuthorizationID != b.AuthorizationID ||
		a.Source != b.Source || a.Recipient != b.Recipient || a.SealedCount != b.SealedCount || a.Version != b.Version {
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
	merged := &ReDisclosure{
		Version:         lo.Version,
		SealID:          lo.SealID,
		AuthorizationID: lo.AuthorizationID,
		Source:          lo.Source,
		Recipient:       lo.Recipient,
		StartSeq:        lo.StartSeq,
		EndSeq:          end,
		SealedCount:     lo.SealedCount,
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
	for _, d := range []ReDisclosure{lo, hi} {
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
