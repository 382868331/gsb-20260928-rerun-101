package audit

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func batchTime(day int) time.Time {
	return time.Date(2026, 1, day, 12, 0, 0, 0, time.UTC)
}

func grantNotice(id, authID, sealID string, start, end uint64, eff time.Time) Notice {
	return Notice{
		ID:              id,
		Kind:            NoticeGrant,
		AuthorizationID: authID,
		EffectiveAt:     eff,
		Authorization: &Authorization{
			ID:          authID,
			SealID:      sealID,
			Source:      "alpha",
			Recipient:   "bob",
			StartSeq:    start,
			EndSeq:      end,
			AllowOnward: true,
			IssuedAt:    eff,
		},
	}
}

func narrowNotice(id, authID string, start, end uint64, eff time.Time) Notice {
	return Notice{
		ID:              id,
		Kind:            NoticeNarrow,
		AuthorizationID: authID,
		EffectiveAt:     eff,
		Narrow:          &NarrowSpec{StartSeq: start, EndSeq: end, AllowOnward: true},
	}
}

func revokeNotice(id, authID string, eff time.Time) Notice {
	return Notice{ID: id, Kind: NoticeRevoke, AuthorizationID: authID, EffectiveAt: eff}
}

func assessmentStatus(p *BatchPreview, id string) NoticeStatus {
	for _, a := range p.Assessments {
		if a.Notice.ID == id {
			return a.Status
		}
	}
	return ""
}

func TestPreviewImportClassifiesEachNotice(t *testing.T) {
	r := NewRegistry()
	if _, err := r.ImportNotice(grantNotice("g1", "auth-1", "seal-1", 1, 10, batchTime(1)), batchTime(2)); err != nil {
		t.Fatal(err)
	}
	batch := []Notice{
		grantNotice("g2", "auth-2", "seal-2", 1, 5, batchTime(2)),                          // acceptable
		grantNotice("g1", "auth-1", "seal-1", 1, 10, batchTime(1)),                         // duplicate
		narrowNotice("n1", "auth-9", 1, 3, batchTime(2)),                                   // missing prerequisite
		grantNotice("g3", "auth-1", "seal-OTHER", 1, 10, batchTime(2)),                     // identity conflict across seals
		{ID: "", Kind: NoticeRevoke, AuthorizationID: "auth-1", EffectiveAt: batchTime(2)}, // invalid
		grantNotice("g2", "auth-2", "seal-2", 1, 5, batchTime(2)),                          // duplicate within batch
	}
	p := r.PreviewImport(batch)
	want := map[string]NoticeStatus{
		"g2": StatusAcceptable,
		"g1": StatusDuplicate,
		"n1": StatusMissingPrerequisite,
		"g3": StatusIdentityConflict,
	}
	for id, status := range want {
		if got := assessmentStatus(p, id); got != status {
			t.Fatalf("notice %s: got %s, want %s", id, got, status)
		}
	}
	if got := assessmentStatus(p, ""); got != StatusInvalid {
		t.Fatalf("empty-ID notice: got %s, want %s", got, StatusInvalid)
	}
	// Preview must not change scope.
	scope, err := r.EffectiveScopeAt("auth-2", batchTime(3))
	if !errors.Is(err, ErrUnknownAuthorization) {
		t.Fatalf("preview leaked into scope: %v %+v", err, scope)
	}
	// Pending entries keep original text and reason.
	pending := p.Pending()
	if len(pending) != 3 {
		t.Fatalf("pending count = %d, want 3", len(pending))
	}
	for _, a := range pending {
		if a.Reason == "" {
			t.Fatalf("pending notice %q has no reason", a.Notice.ID)
		}
	}
}

func TestCommitPreviewPartialAndNewDecisionOnSupplement(t *testing.T) {
	r := NewRegistry()
	batch := []Notice{
		grantNotice("g1", "auth-1", "seal-1", 1, 10, batchTime(1)),
		narrowNotice("n1", "auth-2", 1, 3, batchTime(2)), // no grant for auth-2 yet
	}
	first, err := r.CommitPreview(r.PreviewImport(batch), batchTime(3))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Accepted) != 1 || first.Accepted[0] != "g1" {
		t.Fatalf("accepted = %v, want [g1]", first.Accepted)
	}
	if len(first.Pending) != 1 || first.Pending[0].Notice.ID != "n1" {
		t.Fatalf("pending = %+v, want n1 retained", first.Pending)
	}
	if first.Pending[0].Notice.Narrow == nil {
		t.Fatal("pending notice lost its original content")
	}
	// The legal grant must not release the pending narrow.
	if _, err := r.EffectiveScopeAt("auth-2", batchTime(4)); !errors.Is(err, ErrUnknownAuthorization) {
		t.Fatalf("one legal notice released the batch: %v", err)
	}
	// Re-confirming the same batch folds into the same decision, no scope change.
	again, err := r.CommitPreview(r.PreviewImport(batch), batchTime(4))
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != first.ID || len(r.Decisions()) != 1 {
		t.Fatalf("re-confirmation duplicated decision: %v vs %v, %d decisions", again.ID, first.ID, len(r.Decisions()))
	}
	// Supplement the prerequisite later: a new decision is recorded, the
	// earlier one is kept.
	second, err := r.CommitPreview(r.PreviewImport([]Notice{
		grantNotice("g2", "auth-2", "seal-2", 1, 8, batchTime(1)),
		narrowNotice("n1", "auth-2", 1, 3, batchTime(2)),
	}), batchTime(5))
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == first.ID || len(r.Decisions()) != 2 {
		t.Fatalf("supplement did not produce a new decision: %d decisions", len(r.Decisions()))
	}
	scope, err := r.EffectiveScopeAt("auth-2", batchTime(6))
	if err != nil {
		t.Fatal(err)
	}
	if scope.StartSeq != 1 || scope.EndSeq != 3 {
		t.Fatalf("scope = %+v, want 1-3 after grant+narrow", scope)
	}
}

func TestDismissedNoticeNeverReenabled(t *testing.T) {
	r := NewRegistry()
	batch := []Notice{
		grantNotice("g1", "auth-1", "seal-1", 1, 10, batchTime(1)),
		grantNotice("g2", "auth-1", "seal-OTHER", 1, 20, batchTime(2)), // identity conflict
	}
	decision, err := r.CommitPreview(r.PreviewImport(batch), batchTime(3))
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.Pending) != 1 || decision.Pending[0].Notice.ID != "g2" {
		t.Fatalf("pending = %+v", decision.Pending)
	}
	r.DismissNotices("g2")
	// Late re-confirmation of the dismissed notice is refused.
	if _, err := r.ImportNotice(grantNotice("g2", "auth-1", "seal-OTHER", 1, 20, batchTime(2)), batchTime(4)); !errors.Is(err, ErrNoticeDismissed) {
		t.Fatalf("late import got %v, want ErrNoticeDismissed", err)
	}
	if got := assessmentStatus(r.PreviewImport([]Notice{grantNotice("g2", "auth-1", "seal-OTHER", 1, 20, batchTime(2))}), "g2"); got != StatusDismissed {
		t.Fatalf("re-preview got %s, want dismissed", got)
	}
	scope, err := r.EffectiveScopeAt("auth-1", batchTime(5))
	if err != nil {
		t.Fatal(err)
	}
	if scope.EndSeq != 10 {
		t.Fatalf("scope = %+v, dismissed notice widened it", scope)
	}
}

func TestWidenNarrowRevokeAndReopenConsistency(t *testing.T) {
	r := NewRegistry()
	// Legal widen (1-5 then 1-10), then narrow to 2-4, then an out-of-order
	// revoke whose EffectiveAt predates the narrow but arrives later.
	if _, err := r.ImportNotice(grantNotice("g1", "auth-1", "seal-1", 1, 5, batchTime(1)), batchTime(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ImportNotice(grantNotice("g2", "auth-1", "seal-1", 1, 10, batchTime(2)), batchTime(2)); err != nil {
		t.Fatal(err)
	}
	// Delivery under the widened scope stays on record.
	rd := ReDisclosure{
		AuthorizationID: "auth-1",
		SealID:          "seal-1",
		Source:          "alpha",
		Recipient:       "carol",
		StartSeq:        6,
		EndSeq:          8,
	}
	if _, err := r.RecordDelivery(rd, "bob", batchTime(3)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ImportNotice(narrowNotice("n1", "auth-1", 2, 4, batchTime(4)), batchTime(4)); err != nil {
		t.Fatal(err)
	}
	// Out-of-order revoke: effective before the narrow, recorded after it.
	if _, err := r.ImportNotice(revokeNotice("r1", "auth-1", batchTime(3)), batchTime(5)); err != nil {
		t.Fatal(err)
	}
	scope, err := r.EffectiveScopeAt("auth-1", batchTime(6))
	if err != nil {
		t.Fatal(err)
	}
	if !scope.Revoked {
		t.Fatalf("scope = %+v, want revoked", scope)
	}
	// Historical delivery under the earlier basis is untouched.
	deliveries := r.Deliveries("auth-1")
	if len(deliveries) != 1 || deliveries[0].EndSeq != 8 || deliveries[0].Basis.EndSeq != 10 {
		t.Fatalf("deliveries = %+v, want the 6-8 delivery under the 1-10 basis", deliveries)
	}
	// Reopen and continue: persisted state matches, new decisions append.
	path := filepath.Join(t.TempDir(), "registry.json")
	if _, err := r.CommitPreview(r.PreviewImport([]Notice{grantNotice("g3", "auth-3", "seal-3", 1, 2, batchTime(5))}), batchTime(6)); err != nil {
		t.Fatal(err)
	}
	r.DismissNotices("never")
	if err := r.SaveRegistry(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	loadedScope, err := loaded.EffectiveScopeAt("auth-1", batchTime(6))
	if err != nil {
		t.Fatal(err)
	}
	if !loadedScope.Revoked || loadedScope.StartSeq != scope.StartSeq || loadedScope.EndSeq != scope.EndSeq {
		t.Fatalf("reopened scope = %+v, want %+v", loadedScope, scope)
	}
	if len(loaded.Deliveries("auth-1")) != 1 || len(loaded.Decisions()) != 1 {
		t.Fatalf("reopened history lost deliveries or decisions")
	}
	if _, err := loaded.ImportNotice(grantNotice("never", "auth-9", "seal-9", 1, 2, batchTime(6)), batchTime(7)); !errors.Is(err, ErrNoticeDismissed) {
		t.Fatalf("dismissal lost across reopen: %v", err)
	}
	// Continue processing after reopen: new grant previews and commits.
	decision, err := loaded.CommitPreview(loaded.PreviewImport([]Notice{grantNotice("g4", "auth-4", "seal-4", 1, 3, batchTime(7))}), batchTime(8))
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.Accepted) != 1 || len(loaded.Decisions()) != 2 {
		t.Fatalf("post-reopen decision = %+v, total %d", decision, len(loaded.Decisions()))
	}
	if _, err := loaded.EffectiveScopeAt("auth-4", batchTime(9)); err != nil {
		t.Fatalf("post-reopen grant not effective: %v", err)
	}
}
