package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"
)

// Ledger is the durable record of authorizations, notices, actual
// transfers, and historical verifications. It is stored outside the audited
// file, next to the seal summaries. Reopening a ledger preserves every
// transfer with the authorization and scope that justified it at the time.
type Ledger struct {
	path           string
	authorizations map[string]Authorization
	notices        map[string]Notice
	transfers      []TransferRecord
	verifications  []VerificationRecord
}

type ledgerFile struct {
	Version        uint64                   `json:"version"`
	Authorizations map[string]Authorization `json:"authorizations"`
	Notices        map[string]Notice        `json:"notices"`
	Transfers      []TransferRecord         `json:"transfers"`
	Verifications  []VerificationRecord     `json:"verifications"`
}

// OpenLedger loads a ledger from path, creating an empty one when the file
// does not exist yet.
func OpenLedger(path string) (*Ledger, error) {
	l := &Ledger{
		path:           path,
		authorizations: make(map[string]Authorization),
		notices:        make(map[string]Notice),
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return l, nil
		}
		return nil, err
	}
	var file ledgerFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("invalid ledger file: %w", err)
	}
	if file.Version != 2 {
		return nil, errors.New("unsupported ledger version")
	}
	for id, auth := range file.Authorizations {
		l.authorizations[id] = auth
	}
	for id, notice := range file.Notices {
		l.notices[id] = notice
	}
	l.transfers = file.Transfers
	l.verifications = file.Verifications
	return l, nil
}

func (l *Ledger) save() error {
	file := ledgerFile{
		Version:        2,
		Authorizations: l.authorizations,
		Notices:        l.notices,
		Transfers:      l.transfers,
		Verifications:  l.verifications,
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}

// ImportAuthorization stores a new authorization. Re-importing identical
// content is a no-op and never widens anything; the same ID with different
// content is a conflict.
func (l *Ledger) ImportAuthorization(auth Authorization) (bool, error) {
	if err := auth.validate(); err != nil {
		return false, err
	}
	existing, ok := l.authorizations[auth.ID]
	if ok {
		if existing.fingerprint() == auth.fingerprint() {
			return false, nil
		}
		return false, fmt.Errorf("%w: %q", ErrAuthorizationConflict, auth.ID)
	}
	l.authorizations[auth.ID] = auth
	return true, l.save()
}

// ImportNotice stores a notice about an existing authorization. Identical
// re-imports are no-ops; conflicting IDs are rejected. A supplement must
// widen the scope effective at its own time, a narrow must shrink it, so a
// notice can never smuggle in permission the timeline does not support.
func (l *Ledger) ImportNotice(notice Notice) (bool, error) {
	if notice.ID == "" || notice.AuthID == "" {
		return false, errors.New("notice id and authorization id are required")
	}
	if _, ok := l.authorizations[notice.AuthID]; !ok {
		return false, fmt.Errorf("notice %q references unknown authorization %q", notice.ID, notice.AuthID)
	}
	switch notice.Kind {
	case NoticeRevoke:
		if notice.Scope != nil {
			return false, errors.New("revocation notice must not carry a scope")
		}
	case NoticeSupplement, NoticeNarrow:
		if notice.Scope == nil {
			return false, errors.New("scope-changing notice must carry the new scope")
		}
		scope := *notice.Scope
		if err := scope.validate(); err != nil {
			return false, err
		}
		base := l.authorizations[notice.AuthID]
		if scope.ID != base.ID || scope.SealID != base.SealID || scope.Source != base.Source || scope.Recipient != base.Recipient {
			return false, fmt.Errorf("notice %q scope must keep the authorization's id, seal, source, and recipient", notice.ID)
		}
		current, err := l.effectiveScope(notice.AuthID, notice.EffectiveAt)
		if err != nil && !errors.Is(err, ErrAuthorizationRevoked) {
			return false, err
		}
		if errors.Is(err, ErrAuthorizationRevoked) {
			return false, fmt.Errorf("%w: notice %q predates or matches a revocation", ErrAuthorizationRevoked, notice.ID)
		}
		if notice.Kind == NoticeSupplement && !scopeCovers(scope, *current) {
			return false, fmt.Errorf("supplement notice %q does not widen the scope effective at its own time", notice.ID)
		}
		if notice.Kind == NoticeNarrow && !scopeCovers(*current, scope) {
			return false, fmt.Errorf("narrow notice %q does not shrink the scope effective at its own time", notice.ID)
		}
	default:
		return false, fmt.Errorf("unknown notice kind %q", notice.Kind)
	}
	existing, ok := l.notices[notice.ID]
	if ok {
		if noticesEqual(existing, notice) {
			return false, nil
		}
		return false, fmt.Errorf("%w: %q", ErrNoticeConflict, notice.ID)
	}
	l.notices[notice.ID] = notice
	return true, l.save()
}

func scopeCovers(outer, inner Authorization) bool {
	delegateOK := outer.AllowDelegate || !inner.AllowDelegate
	return outer.coversRange(inner.StartSeq, inner.EndSeq) && outer.Content.Covers(inner.Content) && delegateOK
}

func noticesEqual(a, b Notice) bool {
	if a.ID != b.ID || a.AuthID != b.AuthID || a.Kind != b.Kind || !a.EffectiveAt.Equal(b.EffectiveAt) {
		return false
	}
	if a.Scope == nil || b.Scope == nil {
		return a.Scope == nil && b.Scope == nil
	}
	return a.Scope.fingerprint() == b.Scope.fingerprint()
}

// EffectiveScope returns the scope of one authorization at a given time
// basis: the base grant with every notice effective at or before that time
// applied in chronological order. A revoked authorization reports
// ErrAuthorizationRevoked for that time; transfers already recorded earlier
// remain in the ledger regardless.
func (l *Ledger) EffectiveScope(authID string, at time.Time) (*Authorization, error) {
	if _, ok := l.authorizations[authID]; !ok {
		return nil, fmt.Errorf("unknown authorization %q", authID)
	}
	return l.effectiveScope(authID, at)
}

func (l *Ledger) effectiveScope(authID string, at time.Time) (*Authorization, error) {
	base, ok := l.authorizations[authID]
	if !ok {
		return nil, fmt.Errorf("unknown authorization %q", authID)
	}
	var applicable []Notice
	for _, notice := range l.notices {
		if notice.AuthID == authID && !notice.EffectiveAt.After(at) {
			applicable = append(applicable, notice)
		}
	}
	sort.Slice(applicable, func(i, j int) bool {
		if applicable[i].EffectiveAt.Equal(applicable[j].EffectiveAt) {
			return applicable[i].ID < applicable[j].ID
		}
		return applicable[i].EffectiveAt.Before(applicable[j].EffectiveAt)
	})
	current := base
	for _, notice := range applicable {
		switch notice.Kind {
		case NoticeRevoke:
			return nil, fmt.Errorf("%w: %q revoked at %s", ErrAuthorizationRevoked, authID, notice.EffectiveAt.UTC().Format(time.RFC3339Nano))
		case NoticeSupplement, NoticeNarrow:
			current = *notice.Scope
		}
	}
	return &current, nil
}

// RecordTransfer registers one actual delivery of a disclosure under an
// authorization, evaluated at the delivery time. The disclosure must carry
// that authorization's ID, and its window, recipient, and content must fit
// the scope effective at that moment. Re-recording the exact same delivery
// is a no-op and never adds permission.
func (l *Ledger) RecordTransfer(authID string, d Disclosure, at time.Time) error {
	scope, err := l.effectiveScope(authID, at)
	if err != nil {
		return err
	}
	if d.AuthID != "" && d.AuthID != authID {
		return &UnauthorizedError{AuthID: authID, Reason: "disclosure inherits a different authorization; look-alike material under another grant adds no permission", StartSeq: d.StartSeq, EndSeq: d.EndSeq}
	}
	if d.AuthID != authID {
		return &UnauthorizedError{AuthID: authID, Reason: "disclosure inherits a different authorization", StartSeq: d.StartSeq, EndSeq: d.EndSeq}
	}
	if d.SealID != scope.SealID || d.Source != scope.Source || d.Recipient != scope.Recipient {
		return &UnauthorizedError{AuthID: authID, Reason: "disclosure does not match the authorization's seal, source, and recipient", StartSeq: d.StartSeq, EndSeq: d.EndSeq}
	}
	if !scope.coversRange(d.StartSeq, d.EndSeq) {
		return &UnauthorizedError{AuthID: authID, Reason: "disclosed window exceeds the scope effective at the delivery time", StartSeq: d.StartSeq, EndSeq: d.EndSeq}
	}
	for _, record := range d.Records {
		if !scope.Content.AllowsType(record.Event.Type) {
			return &UnauthorizedError{AuthID: authID, Reason: "disclosed record type is outside the scope effective at the delivery time", StartSeq: record.Seq, EndSeq: record.Seq}
		}
	}
	fingerprint := DisclosureFingerprint(d)
	for _, transfer := range l.transfers {
		if transfer.DisclosureID == fingerprint && transfer.AuthID == authID {
			return nil
		}
	}
	l.transfers = append(l.transfers, TransferRecord{
		AuthID:       authID,
		DisclosureID: fingerprint,
		Recipient:    d.Recipient,
		StartSeq:     d.StartSeq,
		EndSeq:       d.EndSeq,
		RecordedAt:   at.UTC(),
	})
	return l.save()
}

// RecordVerification keeps a historical verification result for offline
// material together with the time basis it was evaluated under. Old records
// are never rewritten; a notice arriving later simply produces a new record
// at its own basis.
func (l *Ledger) RecordVerification(d Disclosure, basis time.Time, inScope bool, detail string) error {
	l.verifications = append(l.verifications, VerificationRecord{
		DisclosureID: DisclosureFingerprint(d),
		BasisTime:    basis.UTC(),
		InScope:      inScope,
		Detail:       detail,
		RecordedAt:   time.Now().UTC(),
	})
	return l.save()
}

// Transfers returns the recorded deliveries in the order they happened.
// Deliveries made before a narrow or revoke notice stay listed: the ledger
// does not pretend already-delivered material disappeared.
func (l *Ledger) Transfers() []TransferRecord {
	out := make([]TransferRecord, len(l.transfers))
	copy(out, l.transfers)
	return out
}

// Verifications returns every recorded verification, oldest first.
func (l *Ledger) Verifications() []VerificationRecord {
	out := make([]VerificationRecord, len(l.verifications))
	copy(out, l.verifications)
	return out
}
