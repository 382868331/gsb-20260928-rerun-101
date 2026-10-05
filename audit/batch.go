package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// ErrNoticeDismissed reports an import attempt for a notice the maintainer
// previously dismissed from a pending batch. Dismissal is final: a late
// re-confirmation of the same notice never re-enables it.
var ErrNoticeDismissed = errors.New("notice was dismissed and stays out of scope")

// NoticeStatus classifies one notice inside a batch preview.
type NoticeStatus string

const (
	// StatusAcceptable means the notice can be imported on its own merits.
	StatusAcceptable NoticeStatus = "acceptable"
	// StatusDuplicate means the notice ID is already imported; importing
	// again changes nothing.
	StatusDuplicate NoticeStatus = "duplicate"
	// StatusMissingPrerequisite means the notice narrows or revokes an
	// authorization this registry has no grant for, neither imported nor
	// earlier in the same batch.
	StatusMissingPrerequisite NoticeStatus = "missing_prerequisite"
	// StatusIdentityConflict means the notice is a grant that would re-bind
	// its authorization ID to a different seal, source, or recipient.
	StatusIdentityConflict NoticeStatus = "identity_conflict"
	// StatusInvalid means the notice is malformed and can never be imported
	// as-is.
	StatusInvalid NoticeStatus = "invalid"
	// StatusDismissed means the maintainer dismissed this notice from an
	// earlier batch; it stays pending and is never re-enabled.
	StatusDismissed NoticeStatus = "dismissed"
)

// NoticeAssessment keeps one notice's original text together with the
// per-notice outcome and, for non-acceptable notices, the reason it stays
// pending. One acceptable notice never releases the rest of the batch.
type NoticeAssessment struct {
	Notice Notice       `json:"notice"`
	Status NoticeStatus `json:"status"`
	Reason string       `json:"reason,omitempty"`
}

// BatchPreview is a dry-run of importing a batch of notices. It changes no
// authorization scope; it only classifies each notice so the maintainer
// can review identity ownership and time relationships before committing.
type BatchPreview struct {
	Assessments []NoticeAssessment `json:"assessments"`
}

// Acceptable returns the assessments that may be committed now.
func (p *BatchPreview) Acceptable() []NoticeAssessment {
	var out []NoticeAssessment
	for _, a := range p.Assessments {
		if a.Status == StatusAcceptable {
			out = append(out, a)
		}
	}
	return out
}

// Pending returns the assessments that stay out of scope, each with its
// original notice text and the reason it was not accepted.
func (p *BatchPreview) Pending() []NoticeAssessment {
	var out []NoticeAssessment
	for _, a := range p.Assessments {
		if a.Status != StatusAcceptable && a.Status != StatusDuplicate {
			out = append(out, a)
		}
	}
	return out
}

// validateNoticeShape checks a notice is well-formed without touching
// registry state.
func validateNoticeShape(n Notice) error {
	if n.ID == "" {
		return errors.New("notice ID is required")
	}
	if n.AuthorizationID == "" {
		return errors.New("notice must name an authorization")
	}
	switch n.Kind {
	case NoticeGrant:
		if n.Authorization == nil {
			return errors.New("grant notice must carry the authorization")
		}
		if err := validateAuthorization(*n.Authorization); err != nil {
			return err
		}
	case NoticeNarrow:
		if n.Narrow == nil || n.Narrow.StartSeq == 0 || n.Narrow.EndSeq < n.Narrow.StartSeq {
			return fmt.Errorf("%w: narrow notice range is empty", ErrInvalidRange)
		}
	case NoticeRevoke:
	default:
		return fmt.Errorf("unknown notice kind %q", n.Kind)
	}
	return nil
}

// PreviewImport classifies each notice of a batch without importing any of
// them. Notices are evaluated in batch order against the registry state
// plus the acceptable notices earlier in the same batch, so a grant and
// its follow-up narrow in one batch both preview as acceptable while a
// narrow with no grant anywhere stays pending as missing_prerequisite.
func (r *Registry) PreviewImport(notices []Notice) *BatchPreview {
	seen := make(map[string]struct{}, len(notices))
	grants := make(map[string]struct{}, len(r.bindings))
	for id := range r.bindings {
		grants[id] = struct{}{}
	}
	bindings := make(map[string]authBinding, len(r.bindings))
	for id, b := range r.bindings {
		bindings[id] = b
	}
	preview := &BatchPreview{}
	for _, n := range notices {
		a := NoticeAssessment{Notice: n}
		if err := validateNoticeShape(n); err != nil {
			a.Status = StatusInvalid
			a.Reason = err.Error()
		} else if r.isDismissed(n.ID) {
			a.Status = StatusDismissed
			a.Reason = "notice was dismissed from an earlier batch and stays out of scope"
		} else if r.hasNotice(n.ID) {
			a.Status = StatusDuplicate
			a.Reason = "notice ID already imported"
		} else if _, ok := seen[n.ID]; ok {
			a.Status = StatusDuplicate
			a.Reason = "notice ID appears earlier in this batch"
		} else {
			switch n.Kind {
			case NoticeGrant:
				b := authBinding{
					SealID:    n.Authorization.SealID,
					Source:    n.Authorization.Source,
					Recipient: n.Authorization.Recipient,
				}
				if existing, ok := bindings[n.AuthorizationID]; ok && existing != b {
					a.Status = StatusIdentityConflict
					a.Reason = fmt.Sprintf(
						"authorization %q is bound to seal %q source %q recipient %q; grant names seal %q source %q recipient %q",
						n.AuthorizationID,
						existing.SealID, existing.Source, existing.Recipient,
						b.SealID, b.Source, b.Recipient,
					)
					break
				}
				a.Status = StatusAcceptable
				bindings[n.AuthorizationID] = b
				grants[n.AuthorizationID] = struct{}{}
			case NoticeNarrow, NoticeRevoke:
				if _, ok := grants[n.AuthorizationID]; !ok {
					a.Status = StatusMissingPrerequisite
					a.Reason = fmt.Sprintf("no grant for authorization %q is imported or earlier in this batch", n.AuthorizationID)
					break
				}
				a.Status = StatusAcceptable
			}
		}
		if a.Status != StatusInvalid {
			seen[n.ID] = struct{}{}
		}
		preview.Assessments = append(preview.Assessments, a)
	}
	return preview
}

// ImportDecision records the outcome of committing one batch preview:
// which notices were accepted, which stayed pending and why. Decisions are
// append-only; supplementing prerequisites or re-selecting a scope later
// produces a new decision without rewriting earlier ones, and historical
// deliveries stay on record either way.
type ImportDecision struct {
	ID        string             `json:"id"`
	DecidedAt time.Time          `json:"decided_at"`
	Accepted  []string           `json:"accepted,omitempty"`
	Pending   []NoticeAssessment `json:"pending,omitempty"`
}

// decisionID derives a stable identifier from the batch outcome so
// re-confirming the identical batch folds into the existing decision
// instead of appending a duplicate. A notice already imported reports as
// duplicate on re-confirmation; that is the same outcome as acceptable,
// so both normalize to one status.
func decisionID(assessments []NoticeAssessment) string {
	entries := make([]string, 0, len(assessments))
	for _, a := range assessments {
		status := a.Status
		if status == StatusDuplicate {
			status = StatusAcceptable
		}
		entries = append(entries, a.Notice.ID+"|"+string(status))
	}
	sort.Strings(entries)
	canonical := struct {
		Entries []string `json:"entries"`
	}{Entries: entries}
	data, err := json.Marshal(canonical)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", sha256Hash(data))
}

// CommitPreview imports the acceptable notices of a preview and records an
// ImportDecision. Pending notices keep their original text and reason and
// are not imported; one acceptable notice never releases them. Committing
// the same batch outcome again returns the existing decision and changes
// no scope, because every accepted notice is imported idempotently.
func (r *Registry) CommitPreview(preview *BatchPreview, decidedAt time.Time) (*ImportDecision, error) {
	var accepted []string
	var pending []NoticeAssessment
	for _, a := range preview.Assessments {
		switch a.Status {
		case StatusAcceptable:
			if _, err := r.ImportNotice(a.Notice, decidedAt); err != nil {
				return nil, fmt.Errorf("commit notice %q: %w", a.Notice.ID, err)
			}
			accepted = append(accepted, a.Notice.ID)
		case StatusDuplicate:
			// Already imported; no decision content to add.
		default:
			pending = append(pending, a)
		}
	}
	id := decisionID(preview.Assessments)
	for i := range r.decisions {
		if r.decisions[i].ID == id {
			return &r.decisions[i], nil
		}
	}
	r.decisions = append(r.decisions, ImportDecision{
		ID:        id,
		DecidedAt: decidedAt.UTC(),
		Accepted:  accepted,
		Pending:   pending,
	})
	return &r.decisions[len(r.decisions)-1], nil
}

// DismissNotices marks pending notice IDs as dismissed. A dismissed notice
// is never imported afterwards: late re-confirmation of the same notice ID
// is refused, so a dismissed supplement cannot silently come back into
// scope.
func (r *Registry) DismissNotices(noticeIDs ...string) {
	for _, id := range noticeIDs {
		if id == "" {
			continue
		}
		r.dismissed[id] = struct{}{}
	}
}

// Decisions returns every recorded import decision in the order they were
// made, including ones superseded by later supplements.
func (r *Registry) Decisions() []ImportDecision {
	return append([]ImportDecision(nil), r.decisions...)
}

func (r *Registry) isDismissed(id string) bool {
	_, ok := r.dismissed[id]
	return ok
}

func (r *Registry) hasNotice(id string) bool {
	_, ok := r.noticeIDs[id]
	return ok
}
