package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"
)

// ErrUnknownAuthorization reports a delivery or query against an
// authorization the registry has never seen a grant notice for.
var ErrUnknownAuthorization = errors.New("unknown authorization")

// ErrRevoked reports a disclosure attempt under an authorization whose
// effective scope is withdrawn at the requested time basis.
var ErrRevoked = errors.New("authorization is revoked at this time basis")

// ErrAuthorizationBindingMismatch reports a supplementary notice that
// reuses an authorization ID already bound to a different seal, source,
// or recipient. Such notices are rejected and change nothing.
var ErrAuthorizationBindingMismatch = errors.New("authorization notice does not match the established seal, source, and recipient")

// NoticeKind classifies how a notice changes an authorization's effective
// scope over time.
type NoticeKind string

const (
	// NoticeGrant establishes or supplements an authorization.
	NoticeGrant NoticeKind = "grant"
	// NoticeNarrow intersects the effective scope with a smaller window.
	NoticeNarrow NoticeKind = "narrow"
	// NoticeRevoke withdraws the authorization from its effective time on.
	NoticeRevoke NoticeKind = "revoke"
)

// Notice is one caller-supplied authorization event. EffectiveAt is the
// time basis the notice takes effect under; RecordedAt is when this
// registry learned of it, which may be later for offline recipients.
// Importing the same notice ID twice changes nothing.
type Notice struct {
	ID              string         `json:"id"`
	Kind            NoticeKind     `json:"kind"`
	AuthorizationID string         `json:"authorization_id"`
	EffectiveAt     time.Time      `json:"effective_at"`
	RecordedAt      time.Time      `json:"recorded_at"`
	Authorization   *Authorization `json:"authorization,omitempty"`
	Narrow          *NarrowSpec    `json:"narrow,omitempty"`
}

// NarrowSpec describes the reduced scope a narrow notice imposes. The
// effective scope becomes the intersection of the previous scope and this
// specification; an empty Types list keeps the previous type restriction.
type NarrowSpec struct {
	StartSeq    uint64   `json:"start_seq"`
	EndSeq      uint64   `json:"end_seq"`
	Types       []string `json:"types,omitempty"`
	AllowOnward bool     `json:"allow_onward"`
}

// Scope is the effective permission of one authorization at one time
// basis. Revoked scopes report Revoked and carry no usable window.
type Scope struct {
	StartSeq    uint64   `json:"start_seq"`
	EndSeq      uint64   `json:"end_seq"`
	Types       []string `json:"types,omitempty"`
	AllowOnward bool     `json:"allow_onward"`
	Revoked     bool     `json:"revoked"`
}

// Delivery records one actual transfer: who sent what window to whom, when
// it happened, and the effective scope it was checked against. Past
// deliveries stay on record even after later narrowing or revocation.
type Delivery struct {
	AuthorizationID string    `json:"authorization_id"`
	SealID          string    `json:"seal_id"`
	Source          string    `json:"source"`
	From            string    `json:"from"`
	To              string    `json:"to"`
	StartSeq        uint64    `json:"start_seq"`
	EndSeq          uint64    `json:"end_seq"`
	DeliveredAt     time.Time `json:"delivered_at"`
	Basis           Scope     `json:"basis"`
}

// VerificationRecord keeps one past verification together with the time
// basis it was made under, so late-arriving notices never rewrite history.
type VerificationRecord struct {
	AuthorizationID string    `json:"authorization_id"`
	SealID          string    `json:"seal_id"`
	CheckedAt       time.Time `json:"checked_at"`
	BasisAt         time.Time `json:"basis_at"`
	StartSeq        uint64    `json:"start_seq"`
	EndSeq          uint64    `json:"end_seq"`
	Result          string    `json:"result"`
}

// Registry tracks notices, actual deliveries, and verification records for
// re-disclosures. It holds no record content; it only reasons about
// authorization scopes and time bases.
type Registry struct {
	notices       []Notice
	noticeIDs     map[string]struct{}
	deliveries    []Delivery
	deliveryIDs   map[string]struct{}
	verifications []VerificationRecord
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		noticeIDs:   make(map[string]struct{}),
		deliveryIDs: make(map[string]struct{}),
	}
}

// ImportNotice records a notice. Re-importing a notice with an already
// known ID is a no-op and never adds permission. The notice is stamped
// with RecordedAt so offline recipients show when they learned of it.
func (r *Registry) ImportNotice(n Notice, recordedAt time.Time) (bool, error) {
	if n.ID == "" {
		return false, errors.New("notice ID is required")
	}
	if n.AuthorizationID == "" {
		return false, errors.New("notice must name an authorization")
	}
	switch n.Kind {
	case NoticeGrant:
		if n.Authorization == nil {
			return false, errors.New("grant notice must carry the authorization")
		}
		if err := validateAuthorization(*n.Authorization); err != nil {
			return false, err
		}
		if err := r.checkAuthorizationBinding(n.AuthorizationID, *n.Authorization); err != nil {
			return false, err
		}
	case NoticeNarrow:
		if n.Narrow == nil || n.Narrow.StartSeq == 0 || n.Narrow.EndSeq < n.Narrow.StartSeq {
			return false, fmt.Errorf("%w: narrow notice range is empty", ErrInvalidRange)
		}
	case NoticeRevoke:
	default:
		return false, fmt.Errorf("unknown notice kind %q", n.Kind)
	}
	if _, seen := r.noticeIDs[n.ID]; seen {
		return false, nil
	}
	n.RecordedAt = recordedAt.UTC()
	n.EffectiveAt = n.EffectiveAt.UTC()
	r.notices = append(r.notices, n)
	r.noticeIDs[n.ID] = struct{}{}
	return true, nil
}

// checkAuthorizationBinding ensures a grant notice for an authorization ID
// that already has a grant on record names the same seal, source, and
// recipient. A supplementary grant pointing at a different seal, source,
// or recipient is refused so it can never widen, shift, or revoke the
// established scope.
func (r *Registry) checkAuthorizationBinding(authorizationID string, a Authorization) error {
	for _, existing := range r.notices {
		if existing.Kind != NoticeGrant || existing.AuthorizationID != authorizationID || existing.Authorization == nil {
			continue
		}
		bound := existing.Authorization
		if bound.SealID != a.SealID || bound.Source != a.Source || bound.Recipient != a.Recipient {
			return fmt.Errorf("%w: authorization %s is bound to seal %s source %s recipient %s",
				ErrAuthorizationBindingMismatch, authorizationID, bound.SealID, bound.Source, bound.Recipient)
		}
	}
	return nil
}

// EffectiveScopeAt computes the scope of one authorization under the given
// time basis, applying every imported notice whose EffectiveAt is not
// later than that basis, in effect order. Notices that arrived later still
// count for the bases they took effect at, so an offline recipient can
// show the status under the corresponding time basis once it catches up.
func (r *Registry) EffectiveScopeAt(authorizationID string, basis time.Time) (Scope, error) {
	relevant := make([]Notice, 0, len(r.notices))
	for _, n := range r.notices {
		if n.AuthorizationID == authorizationID && !n.EffectiveAt.After(basis.UTC()) {
			relevant = append(relevant, n)
		}
	}
	sort.SliceStable(relevant, func(i, j int) bool {
		return relevant[i].EffectiveAt.Before(relevant[j].EffectiveAt)
	})
	var scope Scope
	known := false
	for _, n := range relevant {
		switch n.Kind {
		case NoticeGrant:
			a := n.Authorization
			if !known || scope.Revoked {
				scope = Scope{
					StartSeq:    a.StartSeq,
					EndSeq:      a.EndSeq,
					Types:       append([]string(nil), a.Types...),
					AllowOnward: a.AllowOnward,
				}
			} else {
				scope = unionScope(scope, Scope{
					StartSeq:    a.StartSeq,
					EndSeq:      a.EndSeq,
					Types:       a.Types,
					AllowOnward: a.AllowOnward,
				})
			}
			known = true
		case NoticeNarrow:
			if !known || scope.Revoked {
				continue
			}
			scope = intersectScope(scope, *n.Narrow)
		case NoticeRevoke:
			scope = Scope{Revoked: true}
			known = true
		}
	}
	if !known {
		return Scope{}, ErrUnknownAuthorization
	}
	return scope, nil
}

func unionScope(a, b Scope) Scope {
	out := a
	if b.StartSeq < out.StartSeq {
		out.StartSeq = b.StartSeq
	}
	if b.EndSeq > out.EndSeq {
		out.EndSeq = b.EndSeq
	}
	out.Types = unionTypes(a.Types, b.Types)
	out.AllowOnward = a.AllowOnward || b.AllowOnward
	return out
}

func unionTypes(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, t := range append(append([]string(nil), a...), b...) {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func intersectScope(scope Scope, n NarrowSpec) Scope {
	out := scope
	if n.StartSeq > out.StartSeq {
		out.StartSeq = n.StartSeq
	}
	if n.EndSeq < out.EndSeq {
		out.EndSeq = n.EndSeq
	}
	if len(n.Types) > 0 {
		out.Types = intersectTypes(scope.Types, n.Types)
	}
	out.AllowOnward = scope.AllowOnward && n.AllowOnward
	if out.EndSeq < out.StartSeq {
		out = Scope{Revoked: true}
	}
	return out
}

func intersectTypes(a, b []string) []string {
	if len(a) == 0 {
		return append([]string(nil), b...)
	}
	allowed := make(map[string]struct{}, len(b))
	for _, t := range b {
		allowed[t] = struct{}{}
	}
	var out []string
	for _, t := range a {
		if _, ok := allowed[t]; ok {
			out = append(out, t)
		}
	}
	return out
}

func deliveryKey(d Delivery) string {
	return fmt.Sprintf("%s|%s|%s|%d|%d|%s", d.AuthorizationID, d.To, d.SealID, d.StartSeq, d.EndSeq, d.DeliveredAt.UTC().Format(timeFormat))
}

// RecordDelivery checks a re-disclosure against the scope effective at the
// delivery time and, when permitted, records the actual transfer. A
// delivery that crosses the scope effective at its own time is refused;
// deliveries already recorded stay on record regardless of later notices.
// Recording the identical delivery twice changes nothing.
func (r *Registry) RecordDelivery(rd ReDisclosure, from string, deliveredAt time.Time) (*Delivery, error) {
	scope, err := r.EffectiveScopeAt(rd.AuthorizationID, deliveredAt)
	if err != nil {
		return nil, err
	}
	if scope.Revoked {
		return nil, fmt.Errorf("%w: no delivery of seq %d-%d is permitted", ErrRevoked, rd.StartSeq, rd.EndSeq)
	}
	if rd.StartSeq < scope.StartSeq || rd.EndSeq > scope.EndSeq {
		return nil, fmt.Errorf("%w: delivery of seq %d-%d exceeds the scope %d-%d effective at %s",
			ErrBeyondAuthorization, rd.StartSeq, rd.EndSeq, scope.StartSeq, scope.EndSeq, deliveredAt.UTC().Format(timeFormat))
	}
	d := Delivery{
		AuthorizationID: rd.AuthorizationID,
		SealID:          rd.SealID,
		Source:          rd.Source,
		From:            from,
		To:              rd.Recipient,
		StartSeq:        rd.StartSeq,
		EndSeq:          rd.EndSeq,
		DeliveredAt:     deliveredAt.UTC(),
		Basis:           scope,
	}
	key := deliveryKey(d)
	if _, seen := r.deliveryIDs[key]; seen {
		return &d, nil
	}
	r.deliveries = append(r.deliveries, d)
	r.deliveryIDs[key] = struct{}{}
	return &d, nil
}

// RecordVerification appends a verification record tagged with the time
// basis it relied on. Old records are never rewritten, so a late-arriving
// narrow or revoke notice changes future answers without erasing what was
// verified under an earlier basis.
func (r *Registry) RecordVerification(rec VerificationRecord) {
	rec.CheckedAt = rec.CheckedAt.UTC()
	rec.BasisAt = rec.BasisAt.UTC()
	r.verifications = append(r.verifications, rec)
}

// Deliveries returns every recorded delivery for one authorization in the
// order they happened, including ones made before later narrowing or
// revocation.
func (r *Registry) Deliveries(authorizationID string) []Delivery {
	var out []Delivery
	for _, d := range r.deliveries {
		if d.AuthorizationID == authorizationID {
			out = append(out, d)
		}
	}
	return out
}

// Verifications returns every recorded verification for one authorization.
func (r *Registry) Verifications(authorizationID string) []VerificationRecord {
	var out []VerificationRecord
	for _, v := range r.verifications {
		if v.AuthorizationID == authorizationID {
			out = append(out, v)
		}
	}
	return out
}

type registryFile struct {
	Notices       []Notice             `json:"notices"`
	Deliveries    []Delivery           `json:"deliveries"`
	Verifications []VerificationRecord `json:"verifications"`
}

// SaveRegistry persists the registry so that, after a restart, every
// transfer still traces back to the authorization and scope that were
// effective when it happened.
func (r *Registry) SaveRegistry(path string) error {
	data, err := json.MarshalIndent(registryFile{
		Notices:       r.notices,
		Deliveries:    r.deliveries,
		Verifications: r.verifications,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// LoadRegistry restores a registry saved by SaveRegistry.
func LoadRegistry(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file registryFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	r := NewRegistry()
	for _, n := range file.Notices {
		if _, seen := r.noticeIDs[n.ID]; seen {
			continue
		}
		if n.Kind == NoticeGrant && n.Authorization != nil {
			if err := r.checkAuthorizationBinding(n.AuthorizationID, *n.Authorization); err != nil {
				return nil, err
			}
		}
		r.notices = append(r.notices, n)
		r.noticeIDs[n.ID] = struct{}{}
	}
	for _, d := range file.Deliveries {
		key := deliveryKey(d)
		if _, seen := r.deliveryIDs[key]; seen {
			continue
		}
		r.deliveries = append(r.deliveries, d)
		r.deliveryIDs[key] = struct{}{}
	}
	r.verifications = append(r.verifications, file.Verifications...)
	return r, nil
}
