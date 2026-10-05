package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrNoticeWithdrawn reports an attempt to import or adopt a notice the
// maintainer already withdrew from a pending batch. Withdrawal is final:
// a late confirmation of the same notice never re-enables it.
var ErrNoticeWithdrawn = errors.New("notice was withdrawn and cannot be re-enabled")

// ErrUnknownBatch reports an adoption or withdrawal against a batch
// decision the registry has never previewed.
var ErrUnknownBatch = errors.New("unknown batch decision")

// NoticeStatus classifies one notice inside a batch preview.
type NoticeStatus string

const (
	// NoticeAcceptable means the notice can be imported on its own.
	NoticeAcceptable NoticeStatus = "acceptable"
	// NoticeDuplicate means the notice ID is already imported or appears
	// earlier in the same batch; importing it again changes nothing.
	NoticeDuplicate NoticeStatus = "duplicate"
	// NoticeMissingPrerequisite means the notice narrows or revokes an
	// authorization this registry has no grant for, neither imported nor
	// earlier in the same batch.
	NoticeMissingPrerequisite NoticeStatus = "missing_prerequisite"
	// NoticeIdentityConflict means the notice is a grant that re-points an
	// already bound authorization ID at a different seal, source, or
	// recipient.
	NoticeIdentityConflict NoticeStatus = "identity_conflict"
	// NoticeInvalid means the notice fails basic validation.
	NoticeInvalid NoticeStatus = "invalid"
	// NoticeWithdrawn means the maintainer withdrew this notice from a
	// previous decision; it stays on record but can never be adopted.
	NoticeWithdrawn NoticeStatus = "withdrawn"
)

// NoticeAssessment keeps one notice exactly as submitted together with
// the preview verdict and, for disputed notices, the reason it is held.
type NoticeAssessment struct {
	Notice Notice       `json:"notice"`
	Status NoticeStatus `json:"status"`
	Reason string       `json:"reason,omitempty"`
}

// BatchDecision is the recorded outcome of previewing one batch of
// supplementary notices. Previewing never changes the effective scope;
// only AdoptBatch imports, and only the notices listed as acceptable.
// Decisions are kept so a later batch that supplies missing prerequisites
// becomes a new decision alongside, never a rewrite of, this one.
type BatchDecision struct {
	ID          string             `json:"id"`
	CreatedAt   time.Time          `json:"created_at"`
	Assessments []NoticeAssessment `json:"assessments"`
	Adopted     []string           `json:"adopted,omitempty"`
	Withdrawn   []string           `json:"withdrawn,omitempty"`
}

// Pending returns the assessments still awaiting a maintainer ruling:
// everything neither acceptable nor a harmless duplicate.
func (d BatchDecision) Pending() []NoticeAssessment {
	var out []NoticeAssessment
	for _, a := range d.Assessments {
		switch a.Status {
		case NoticeAcceptable, NoticeDuplicate:
		default:
			out = append(out, a)
		}
	}
	return out
}

// batchID derives a stable decision identifier from the batch content, so
// previewing the identical batch twice returns the same decision instead
// of piling up duplicates.
func batchID(notices []Notice) string {
	canonical := make([]Notice, 0, len(notices))
	for _, n := range notices {
		n.EffectiveAt = n.EffectiveAt.UTC()
		n.RecordedAt = n.RecordedAt.UTC()
		canonical = append(canonical, n)
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", sha256Hash(data))
}

// validateNotice checks one notice the same way ImportNotice does, without
// touching registry state.
func validateNotice(n Notice) error {
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
		return validateAuthorization(*n.Authorization)
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

// PreviewBatch assesses a batch of supplementary notices against the
// current registry without importing anything. Each notice is classified
// on its own: one acceptable notice never clears the rest of the batch.
// Previewing the identical batch again returns the existing decision.
func (r *Registry) PreviewBatch(notices []Notice, previewedAt time.Time) (*BatchDecision, error) {
	if len(notices) == 0 {
		return nil, errors.New("batch is empty")
	}
	id := batchID(notices)
	if idx, ok := r.decisionIDs[id]; ok {
		return &r.decisions[idx], nil
	}
	seen := make(map[string]struct{}, len(r.noticeIDs)+len(notices))
	for k := range r.noticeIDs {
		seen[k] = struct{}{}
	}
	bindings := make(map[string]authBinding, len(r.bindings))
	for k, v := range r.bindings {
		bindings[k] = v
	}
	decision := BatchDecision{
		ID:        id,
		CreatedAt: previewedAt.UTC(),
	}
	for _, n := range notices {
		assessment := NoticeAssessment{Notice: n}
		if _, w := r.withdrawn[n.ID]; w {
			assessment.Status = NoticeWithdrawn
			assessment.Reason = "notice was withdrawn from an earlier batch and stays out of scope"
		} else if _, s := seen[n.ID]; s {
			assessment.Status = NoticeDuplicate
			assessment.Reason = "notice ID already known; importing again changes nothing"
		} else if err := validateNotice(n); err != nil {
			assessment.Status = NoticeInvalid
			assessment.Reason = err.Error()
		} else {
			switch n.Kind {
			case NoticeGrant:
				b := authBinding{
					SealID:    n.Authorization.SealID,
					Source:    n.Authorization.Source,
					Recipient: n.Authorization.Recipient,
				}
				if existing, ok := bindings[n.AuthorizationID]; ok && existing != b {
					assessment.Status = NoticeIdentityConflict
					assessment.Reason = fmt.Sprintf(
						"authorization %q is bound to seal %q source %q recipient %q, refusing grant for seal %q source %q recipient %q",
						n.AuthorizationID,
						existing.SealID, existing.Source, existing.Recipient,
						b.SealID, b.Source, b.Recipient,
					)
					break
				}
				bindings[n.AuthorizationID] = b
				assessment.Status = NoticeAcceptable
			default:
				if _, ok := bindings[n.AuthorizationID]; !ok {
					assessment.Status = NoticeMissingPrerequisite
					assessment.Reason = fmt.Sprintf(
						"authorization %q has no grant in the registry or earlier in this batch",
						n.AuthorizationID,
					)
					break
				}
				assessment.Status = NoticeAcceptable
			}
		}
		if assessment.Status == NoticeAcceptable || assessment.Status == NoticeDuplicate {
			seen[n.ID] = struct{}{}
		}
		decision.Assessments = append(decision.Assessments, assessment)
	}
	r.decisions = append(r.decisions, decision)
	r.decisionIDs[id] = len(r.decisions) - 1
	return &r.decisions[len(r.decisions)-1], nil
}

// AdoptBatch imports the notices the maintainer confirms from a previewed
// batch. Only notices assessed acceptable are imported; every other notice
// keeps its original text and pending reason in the decision. Confirming
// the same batch twice never applies a notice twice, and a notice the
// maintainer withdrew is refused even if it arrives again later.
func (r *Registry) AdoptBatch(decisionID string, noticeIDs []string, recordedAt time.Time) ([]string, error) {
	idx, ok := r.decisionIDs[decisionID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownBatch, decisionID)
	}
	decision := &r.decisions[idx]
	byID := make(map[string]*NoticeAssessment, len(decision.Assessments))
	for i := range decision.Assessments {
		byID[decision.Assessments[i].Notice.ID] = &decision.Assessments[i]
	}
	for _, id := range noticeIDs {
		a, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("notice %q is not part of batch %q", id, decisionID)
		}
		if _, w := r.withdrawn[id]; w {
			return nil, fmt.Errorf("%w: %q", ErrNoticeWithdrawn, id)
		}
		if a.Status != NoticeAcceptable && a.Status != NoticeDuplicate {
			return nil, fmt.Errorf("notice %q is %s (%s) and cannot be adopted with this batch", id, a.Status, a.Reason)
		}
	}
	var adopted []string
	for _, id := range noticeIDs {
		a := byID[id]
		switch a.Status {
		case NoticeAcceptable:
			inserted, err := r.ImportNotice(a.Notice, recordedAt)
			if err != nil {
				return nil, err
			}
			if inserted {
				adopted = append(adopted, id)
			}
		case NoticeDuplicate:
			// Already imported; confirming again changes nothing.
		}
	}
	for _, id := range adopted {
		known := false
		for _, prev := range decision.Adopted {
			if prev == id {
				known = true
				break
			}
		}
		if !known {
			decision.Adopted = append(decision.Adopted, id)
		}
	}
	return adopted, nil
}

// WithdrawPending marks notices from a previewed batch as withdrawn. The
// original notices and their pending reasons stay on record, but neither
// AdoptBatch nor ImportNotice will ever accept them again, so a late
// confirmation cannot re-enable what the maintainer ruled out.
func (r *Registry) WithdrawPending(decisionID string, noticeIDs []string) error {
	idx, ok := r.decisionIDs[decisionID]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownBatch, decisionID)
	}
	decision := &r.decisions[idx]
	byID := make(map[string]int, len(decision.Assessments))
	for i := range decision.Assessments {
		byID[decision.Assessments[i].Notice.ID] = i
	}
	for _, id := range noticeIDs {
		i, ok := byID[id]
		if !ok {
			return fmt.Errorf("notice %q is not part of batch %q", id, decisionID)
		}
		if _, w := r.withdrawn[id]; w {
			continue
		}
		r.withdrawn[id] = struct{}{}
		decision.Assessments[i].Status = NoticeWithdrawn
		decision.Assessments[i].Reason = "withdrawn by maintainer; late confirmations cannot re-enable it"
		decision.Withdrawn = append(decision.Withdrawn, id)
	}
	return nil
}

// Decisions returns every recorded batch decision in preview order,
// including ones whose notices were later adopted or withdrawn.
func (r *Registry) Decisions() []BatchDecision {
	return append([]BatchDecision(nil), r.decisions...)
}
