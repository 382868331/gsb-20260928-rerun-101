package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrUnauthorizedScope reports an attempt to derive or record a disclosure
// that crosses the boundary of the authorization it claims to inherit. The
// error only names sequence numbers and scope metadata; it never carries
// record content, so an unauthorized recipient learns nothing about the
// records it may not see.
var ErrUnauthorizedScope = errors.New("disclosure exceeds the authorized scope")

// ErrAuthorizationConflict reports an import whose identifier is already
// present with different content. Re-importing byte-identical material is a
// no-op; a conflicting identifier is always an explicit error.
var ErrAuthorizationConflict = errors.New("authorization conflicts with the stored record")

// ErrNoticeConflict reports a notice whose identifier is already present
// with different content.
var ErrNoticeConflict = errors.New("notice conflicts with the stored record")

// ErrAuthorizationRevoked reports use of an authorization after a revocation
// notice took effect. Transfers already recorded before the revocation stay
// on record; only new disclosures are refused.
var ErrAuthorizationRevoked = errors.New("authorization was revoked")

// UnauthorizedError identifies which boundary a derivation or transfer
// crossed. It carries sequence numbers and identifiers only, never record
// payloads, so error reporting cannot leak invisible content.
type UnauthorizedError struct {
	AuthID   string
	Reason   string
	StartSeq uint64
	EndSeq   uint64
}

func (e *UnauthorizedError) Error() string {
	return fmt.Sprintf("%s: authorization %q does not cover seq %d-%d: %s",
		ErrUnauthorizedScope, e.AuthID, e.StartSeq, e.EndSeq, e.Reason)
}

func (e *UnauthorizedError) Unwrap() error { return ErrUnauthorizedScope }

// ContentScope restricts which event content an authorization makes visible.
// An empty Types list permits every event type; otherwise only the listed
// types may be disclosed. Record hashes cover the full event, so visibility
// is restricted by refusing to derive material containing other types, not
// by rewriting records.
type ContentScope struct {
	Types []string `json:"types,omitempty"`
}

// AllowsType reports whether one event type is visible under this scope.
func (c ContentScope) AllowsType(eventType string) bool {
	if len(c.Types) == 0 {
		return true
	}
	for _, allowed := range c.Types {
		if allowed == eventType {
			return true
		}
	}
	return false
}

// Covers reports whether other is a sub-scope of c: every type other permits
// must also be permitted by c.
func (c ContentScope) Covers(other ContentScope) bool {
	if len(c.Types) == 0 {
		return true
	}
	if len(other.Types) == 0 {
		return false
	}
	for _, eventType := range other.Types {
		if !c.AllowsType(eventType) {
			return false
		}
	}
	return true
}

func (c ContentScope) equal(other ContentScope) bool {
	if len(c.Types) != len(other.Types) {
		return false
	}
	for i := range c.Types {
		if c.Types[i] != other.Types[i] {
			return false
		}
	}
	return true
}

// Authorization is an explicit, externally issued grant over one sealed
// segment. It binds a source, a sequence range, the visible content, and
// whether the recipient may pass material on. A same-named source or a
// wider grant held by the same party never widens another authorization;
// only this exact grant justifies a disclosure derived from it.
type Authorization struct {
	ID            string       `json:"id"`
	SealID        string       `json:"seal_id"`
	Source        string       `json:"source"`
	Grantor       string       `json:"grantor"`
	Recipient     string       `json:"recipient"`
	StartSeq      uint64       `json:"start_seq"`
	EndSeq        uint64       `json:"end_seq"`
	Content       ContentScope `json:"content"`
	AllowDelegate bool         `json:"allow_delegate"`
	IssuedAt      time.Time    `json:"issued_at"`
}

func (a Authorization) coversRange(startSeq, endSeq uint64) bool {
	return startSeq >= a.StartSeq && endSeq <= a.EndSeq
}

func (a Authorization) validate() error {
	if a.ID == "" || a.SealID == "" || a.Source == "" || a.Recipient == "" {
		return errors.New("authorization id, seal, source, and recipient are required")
	}
	if a.StartSeq == 0 || a.EndSeq < a.StartSeq {
		return fmt.Errorf("%w: authorization %q has an empty range", ErrInvalidRange, a.ID)
	}
	return nil
}

func (a Authorization) fingerprint() string {
	data, err := json.Marshal(a)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// Redisclose derives a re-disclosure for a new recipient from a disclosure
// the caller already holds, under an explicit sub-authorization. The result
// names the seal (SealID) and the authorization (AuthID) it inherits; the
// parent window is recorded so verifiers see exactly which material it was
// narrowed from. Holding a wider disclosure or a same-named source never
// widens the result: only subAuth, itself bounded by auth, justifies the
// derived window.
func Redisclose(summary SealSummary, auth, subAuth Authorization, parent Disclosure, startSeq, endSeq uint64) (*Disclosure, error) {
	if err := auth.validate(); err != nil {
		return nil, err
	}
	if err := subAuth.validate(); err != nil {
		return nil, err
	}
	if err := VerifyDisclosure(summary, parent); err != nil {
		return nil, err
	}
	if startSeq == 0 || endSeq < startSeq {
		return nil, fmt.Errorf("%w: empty range", ErrInvalidRange)
	}
	if auth.Recipient != parent.Recipient || auth.SealID != parent.SealID || auth.Source != parent.Source {
		return nil, &UnauthorizedError{AuthID: auth.ID, Reason: "authorization does not match the held disclosure's seal, source, and recipient", StartSeq: startSeq, EndSeq: endSeq}
	}
	if !auth.AllowDelegate {
		return nil, &UnauthorizedError{AuthID: auth.ID, Reason: "authorization does not permit further delegation", StartSeq: startSeq, EndSeq: endSeq}
	}
	if subAuth.Grantor != auth.Recipient || subAuth.SealID != auth.SealID || subAuth.Source != auth.Source {
		return nil, &UnauthorizedError{AuthID: subAuth.ID, Reason: "sub-authorization must be issued by the held authorization's recipient over the same seal and source", StartSeq: startSeq, EndSeq: endSeq}
	}
	if !auth.coversRange(subAuth.StartSeq, subAuth.EndSeq) {
		return nil, &UnauthorizedError{AuthID: subAuth.ID, Reason: "sub-authorization range exceeds the held authorization", StartSeq: subAuth.StartSeq, EndSeq: subAuth.EndSeq}
	}
	if !auth.Content.Covers(subAuth.Content) {
		return nil, &UnauthorizedError{AuthID: subAuth.ID, Reason: "sub-authorization content scope exceeds the held authorization", StartSeq: subAuth.StartSeq, EndSeq: subAuth.EndSeq}
	}
	if !subAuth.coversRange(startSeq, endSeq) {
		return nil, &UnauthorizedError{AuthID: subAuth.ID, Reason: "requested range is outside the sub-authorization", StartSeq: startSeq, EndSeq: endSeq}
	}
	if startSeq < parent.StartSeq || endSeq > parent.EndSeq {
		return nil, fmt.Errorf("%w: requested range %d-%d is not visible in the held disclosure window %d-%d",
			ErrInvalidRange, startSeq, endSeq, parent.StartSeq, parent.EndSeq)
	}
	offset := startSeq - parent.StartSeq
	count := endSeq - startSeq + 1
	records := make([]Record, 0, count)
	steps := make([][]MerkleProofStep, 0, count)
	for i := uint64(0); i < count; i++ {
		record := parent.Records[offset+i]
		if !subAuth.Content.AllowsType(record.Event.Type) {
			return nil, &UnauthorizedError{AuthID: subAuth.ID, Reason: "record type is not visible under the sub-authorization", StartSeq: record.Seq, EndSeq: record.Seq}
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
	return &Disclosure{
		Version:       2,
		SealID:        parent.SealID,
		AuthID:        subAuth.ID,
		Source:        parent.Source,
		Recipient:     subAuth.Recipient,
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

// DisclosureFingerprint identifies one exact disclosure: its seal basis,
// authorization, recipient, window, and record hashes. Re-importing a
// disclosure with the same fingerprint never adds permission.
func DisclosureFingerprint(d Disclosure) string {
	type identity struct {
		SealID    string   `json:"seal_id"`
		AuthID    string   `json:"auth_id"`
		Source    string   `json:"source"`
		Recipient string   `json:"recipient"`
		StartSeq  uint64   `json:"start_seq"`
		EndSeq    uint64   `json:"end_seq"`
		Hashes    [][]byte `json:"hashes"`
	}
	id := identity{SealID: d.SealID, AuthID: d.AuthID, Source: d.Source, Recipient: d.Recipient, StartSeq: d.StartSeq, EndSeq: d.EndSeq}
	for _, record := range d.Records {
		id.Hashes = append(id.Hashes, record.RecordHash)
	}
	data, err := json.Marshal(id)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// NoticeKind classifies a notice that changes an authorization over time.
type NoticeKind string

const (
	// NoticeSupplement widens the authorized scope going forward.
	NoticeSupplement NoticeKind = "supplement"
	// NoticeNarrow shrinks the authorized scope going forward.
	NoticeNarrow NoticeKind = "narrow"
	// NoticeRevoke voids the authorization for future disclosures.
	NoticeRevoke NoticeKind = "revoke"
)

// Notice records one time-stamped change to an authorization. EffectiveAt
// is the time basis the change applies from; offline material evaluated
// later is reported against the scope effective at the relevant time, and
// earlier verification records stay on file.
type Notice struct {
	ID          string         `json:"id"`
	AuthID      string         `json:"auth_id"`
	Kind        NoticeKind     `json:"kind"`
	EffectiveAt time.Time      `json:"effective_at"`
	Scope       *Authorization `json:"scope,omitempty"`
}

// TransferRecord is the durable trace of one actual delivery: which
// authorization justified it, which disclosure was delivered, and the exact
// window that was handed over. Records are never removed, so material
// delivered before a narrow or revoke notice remains visible as a past fact.
type TransferRecord struct {
	AuthID       string    `json:"auth_id"`
	DisclosureID string    `json:"disclosure_id"`
	Recipient    string    `json:"recipient"`
	StartSeq     uint64    `json:"start_seq"`
	EndSeq       uint64    `json:"end_seq"`
	RecordedAt   time.Time `json:"recorded_at"`
}

// VerificationRecord keeps one historical verification of offline material
// together with the time basis it was evaluated under. Later notices add new
// records; they never rewrite or delete older ones.
type VerificationRecord struct {
	DisclosureID string    `json:"disclosure_id"`
	BasisTime    time.Time `json:"basis_time"`
	InScope      bool      `json:"in_scope"`
	Detail       string    `json:"detail,omitempty"`
	RecordedAt   time.Time `json:"recorded_at"`
}
