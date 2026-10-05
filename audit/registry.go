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
	bindings      map[string]authBinding
	deliveries    []Delivery
	deliveryIDs   map[string]struct{}
	verifications []VerificationRecord
	decisions     []BatchDecision
	decisionIDs   map[string]int
	withdrawn     map[string]struct{}
}

// authBinding records the seal, source, and recipient an authorization ID
// was established for. Supplementary notices for the same authorization ID
// must stay within that binding; the same ID can never be re-pointed at a
// different seal, source, or recipient.
type authBinding struct {
	SealID    string `json:"seal_id"`
	Source    string `json:"source"`
	Recipient string `json:"recipient"`
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		noticeIDs:   make(map[string]struct{}),
		bindings:    make(map[string]authBinding),
		deliveryIDs: make(map[string]struct{}),
		decisionIDs: make(map[string]int),
		withdrawn:   make(map[string]struct{}),
	}
}

// ImportNotice records a notice. Re-importing a notice with an already
// known ID is a no-op and never adds permission. The notice is stamped
// with RecordedAt so offline recipients show when they learned of it.
func (r *Registry) ImportNotice(n Notice, recordedAt time.Time) (bool, error) {
	if _, w := r.withdrawn[n.ID]; w {
		return false, fmt.Errorf("%w: %q", ErrNoticeWithdrawn, n.ID)
	}
	if err := validateNotice(n); err != nil {
		return false, err
	}
	if _, seen := r.noticeIDs[n.ID]; seen {
		return false, nil
	}
	if n.Kind == NoticeGrant {
		b := authBinding{
			SealID:    n.Authorization.SealID,
			Source:    n.Authorization.Source,
			Recipient: n.Authorization.Recipient,
		}
		if existing, ok := r.bindings[n.AuthorizationID]; ok && existing != b {
			return false, fmt.Errorf(
				"%w: authorization %q is bound to seal %q source %q recipient %q, refusing grant for seal %q source %q recipient %q",
				ErrBeyondAuthorization, n.AuthorizationID,
				existing.SealID, existing.Source, existing.Recipient,
				b.SealID, b.Source, b.Recipient,
			)
		}
	}
	n.RecordedAt = recordedAt.UTC()
	n.EffectiveAt = n.EffectiveAt.UTC()
	r.notices = append(r.notices, n)
	r.noticeIDs[n.ID] = struct{}{}
	if n.Kind == NoticeGrant {
		r.bindings[n.AuthorizationID] = authBinding{
			SealID:    n.Authorization.SealID,
			Source:    n.Authorization.Source,
			Recipient: n.Authorization.Recipient,
		}
	}
	return true, nil
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
	binding, bound := r.bindings[authorizationID]
	var scope Scope
	known := false
	for _, n := range relevant {
		switch n.Kind {
		case NoticeGrant:
			// A grant notice that does not match the authorization's original
			// binding can never widen it. ImportNotice rejects such notices,
			// but records persisted by older builds are ignored here as well so
			// reopening a registry stays consistent.
			if bound && (authBinding{
				SealID:    n.Authorization.SealID,
				Source:    n.Authorization.Source,
				Recipient: n.Authorization.Recipient,
			} != binding) {
				continue
			}
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
	Decisions     []BatchDecision      `json:"decisions,omitempty"`
	Withdrawn     []string             `json:"withdrawn,omitempty"`
}

// SaveRegistry persists the registry so that, after a restart, every
// transfer still traces back to the authorization and scope that were
// effective when it happened.
func (r *Registry) SaveRegistry(path string) error {
	data, err := json.MarshalIndent(registryFile{
		Notices:       r.notices,
		Deliveries:    r.deliveries,
		Verifications: r.verifications,
		Decisions:     r.decisions,
		Withdrawn:     sortedKeys(r.withdrawn),
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
			b := authBinding{
				SealID:    n.Authorization.SealID,
				Source:    n.Authorization.Source,
				Recipient: n.Authorization.Recipient,
			}
			if existing, ok := r.bindings[n.AuthorizationID]; ok && existing != b {
				// A grant that would re-bind the authorization to a different
				// seal, source, or recipient is never replayed into scope
				// computation; the original binding wins.
				continue
			}
			r.bindings[n.AuthorizationID] = b
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
	for _, d := range file.Decisions {
		if _, seen := r.decisionIDs[d.ID]; seen {
			continue
		}
		r.decisions = append(r.decisions, d)
		r.decisionIDs[d.ID] = len(r.decisions) - 1
	}
	for _, id := range file.Withdrawn {
		r.withdrawn[id] = struct{}{}
	}
	return r, nil
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
