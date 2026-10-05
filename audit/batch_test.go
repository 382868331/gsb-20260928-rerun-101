package audit

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

var batchBase = time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)

func batchGrant(id, authID, sealID string, start, end uint64, eff time.Time) Notice {
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

func batchNarrow(id, authID string, start, end uint64, eff time.Time) Notice {
	return Notice{
		ID:              id,
		Kind:            NoticeNarrow,
		AuthorizationID: authID,
		EffectiveAt:     eff,
		Narrow:          &NarrowSpec{StartSeq: start, EndSeq: end, AllowOnward: true},
	}
}

func batchRevoke(id, authID string, eff time.Time) Notice {
	return Notice{ID: id, Kind: NoticeRevoke, AuthorizationID: authID, EffectiveAt: eff}
}

func assessmentByID(t *testing.T, d *BatchDecision, id string) NoticeAssessment {
	t.Helper()
	for _, a := range d.Assessments {
		if a.Notice.ID == id {
			return a
		}
	}
	t.Fatalf("decision %s has no assessment for notice %s", d.ID, id)
	return NoticeAssessment{}
}

func TestPreviewBatchClassifiesEachNotice(t *testing.T) {
	r := NewRegistry()
	if _, err := r.ImportNotice(batchGrant("g0", "auth-1", "seal-1", 1, 5, batchBase), batchBase); err != nil {
		t.Fatal(err)
	}
	batch := []Notice{
		batchGrant("g1", "auth-2", "seal-2", 1, 9, batchBase.Add(time.Hour)),           // acceptable
		batchGrant("g0", "auth-1", "seal-1", 1, 5, batchBase),                            // duplicate
		batchNarrow("n1", "auth-9", 1, 3, batchBase.Add(time.Hour)),                      // missing prerequisite
		batchGrant("g2", "auth-1", "seal-OTHER", 1, 5, batchBase.Add(2*time.Hour)),       // identity conflict across seals
		{ID: "bad", Kind: NoticeRevoke},                                                  // invalid: no authorization ID
	}
	d, err := r.PreviewBatch(batch, batchBase.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]NoticeStatus{
		"g1":  NoticeAcceptable,
		"g0":  NoticeDuplicate,
		"n1":  NoticeMissingPrerequisite,
		"g2":  NoticeIdentityConflict,
		"bad": NoticeInvalid,
	}
	for id, status := range want {
		if got := assessmentByID(t, d, id).Status; got != status {
			t.Errorf("notice %s: got %s, want %s", id, got, status)
		}
	}
	// Preview must not change the effective scope.
	if _, err := r.EffectiveScopeAt("auth-2", batchBase.Add(4*time.Hour)); !errors.Is(err, ErrUnknownAuthorization) {
		t.Fatalf("preview leaked grant into scope: %v", err)
	}
	if pending := d.Pending(); len(pending) != 3 {
		t.Fatalf("pending count = %d, want 3", len(pending))
	}
}

func TestAdoptBatchAcceptsOnlyUndisputed(t *testing.T) {
	r := NewRegistry()
	batch := []Notice{
		batchGrant("g1", "auth-1", "seal-1", 1, 5, batchBase),
		batchNarrow("n1", "auth-9", 1, 3, batchBase),
	}
	d, err := r.PreviewBatch(batch, batchBase)
	if err != nil {
		t.Fatal(err)
	}
	// The legal notice cannot carry the whole batch through.
	if _, err := r.AdoptBatch(d.ID, []string{"g1", "n1"}, batchBase); err == nil {
		t.Fatal("adopting a disputed notice with the batch must fail")
	}
	adopted, err := r.AdoptBatch(d.ID, []string{"g1"}, batchBase)
	if err != nil {
		t.Fatal(err)
	}
	if len(adopted) != 1 || adopted[0] != "g1" {
		t.Fatalf("adopted = %v, want [g1]", adopted)
	}
	// The disputed notice keeps its original text and pending reason.
	a := assessmentByID(t, d, "n1")
	if a.Status != NoticeMissingPrerequisite || a.Reason == "" || a.Notice.Narrow == nil {
		t.Fatalf("disputed notice lost its record: %+v", a)
	}
	if _, err := r.EffectiveScopeAt("auth-9", batchBase.Add(time.Hour)); !errors.Is(err, ErrUnknownAuthorization) {
		t.Fatalf("disputed notice entered scope: %v", err)
	}
	// Re-confirming the same batch does not modify the scope twice.
	again, err := r.AdoptBatch(d.ID, []string{"g1"}, batchBase)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("second confirmation adopted %v, want nothing", again)
	}
	if len(r.notices) != 1 {
		t.Fatalf("registry holds %d notices, want 1", len(r.notices))
	}
}

func TestFollowUpBatchSuppliesPrerequisite(t *testing.T) {
	r := NewRegistry()
	first, err := r.PreviewBatch([]Notice{
		batchNarrow("n1", "auth-1", 2, 4, batchBase.Add(2*time.Hour)),
	}, batchBase)
	if err != nil {
		t.Fatal(err)
	}
	// Later the missing grant arrives: a new decision is generated.
	second, err := r.PreviewBatch([]Notice{
		batchGrant("g1", "auth-1", "seal-1", 1, 5, batchBase),
		batchNarrow("n1", "auth-1", 2, 4, batchBase.Add(2*time.Hour)),
	}, batchBase.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == first.ID {
		t.Fatal("follow-up batch must produce a new decision")
	}
	if got := assessmentByID(t, second, "n1").Status; got != NoticeAcceptable {
		t.Fatalf("n1 with prerequisite in batch: got %s, want acceptable", got)
	}
	if _, err := r.AdoptBatch(second.ID, []string{"g1", "n1"}, batchBase.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	scope, err := r.EffectiveScopeAt("auth-1", batchBase.Add(4*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if scope.StartSeq != 2 || scope.EndSeq != 4 {
		t.Fatalf("scope = %d-%d, want 2-4", scope.StartSeq, scope.EndSeq)
	}
	// Both decisions stay on record.
	if len(r.Decisions()) != 2 {
		t.Fatalf("decisions = %d, want 2", len(r.Decisions()))
	}
}

func TestWithdrawnNoticeStaysOut(t *testing.T) {
	r := NewRegistry()
	d, err := r.PreviewBatch([]Notice{
		batchGrant("g1", "auth-1", "seal-1", 1, 5, batchBase),
		batchGrant("g2", "auth-2", "seal-2", 1, 9, batchBase),
	}, batchBase)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.AdoptBatch(d.ID, []string{"g1"}, batchBase); err != nil {
		t.Fatal(err)
	}
	if err := r.WithdrawPending(d.ID, []string{"g2"}); err != nil {
		t.Fatal(err)
	}
	// A late confirmation of the withdrawn notice must not re-enable it.
	if _, err := r.AdoptBatch(d.ID, []string{"g2"}, batchBase.Add(time.Hour)); !errors.Is(err, ErrNoticeWithdrawn) {
		t.Fatalf("late adopt got %v, want ErrNoticeWithdrawn", err)
	}
	if _, err := r.ImportNotice(batchGrant("g2", "auth-2", "seal-2", 1, 9, batchBase), batchBase.Add(time.Hour)); !errors.Is(err, ErrNoticeWithdrawn) {
		t.Fatalf("late import got %v, want ErrNoticeWithdrawn", err)
	}
	if _, err := r.EffectiveScopeAt("auth-2", batchBase.Add(2*time.Hour)); !errors.Is(err, ErrUnknownAuthorization) {
		t.Fatalf("withdrawn notice entered scope: %v", err)
	}
	// A fresh batch containing the withdrawn notice reports it as withdrawn.
	d2, err := r.PreviewBatch([]Notice{
		batchGrant("g2", "auth-2", "seal-2", 1, 9, batchBase),
	}, batchBase.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got := assessmentByID(t, d2, "g2").Status; got != NoticeWithdrawn {
		t.Fatalf("re-preview of withdrawn notice: got %s, want withdrawn", got)
	}
}

func TestBatchScopeHistoryAndOutOfOrderRevoke(t *testing.T) {
	r := NewRegistry()
	// Legal expansion: grant 1-5, then a supplementary grant widening to 1-9.
	d, err := r.PreviewBatch([]Notice{
		batchGrant("g1", "auth-1", "seal-1", 1, 5, batchBase),
		batchGrant("g2", "auth-1", "seal-1", 1, 9, batchBase.Add(time.Hour)),
	}, batchBase)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.AdoptBatch(d.ID, []string{"g1", "g2"}, batchBase); err != nil {
		t.Fatal(err)
	}
	// A delivery under the widened scope stays on record forever.
	rd := ReDisclosure{AuthorizationID: "auth-1", SealID: "seal-1", Source: "alpha", Recipient: "carol", StartSeq: 6, EndSeq: 9}
	if _, err := r.RecordDelivery(rd, "bob", batchBase.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Then the scope is narrowed back to 1-5.
	if _, err := r.ImportNotice(batchNarrow("n1", "auth-1", 1, 5, batchBase.Add(3*time.Hour)), batchBase.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	scope, err := r.EffectiveScopeAt("auth-1", batchBase.Add(4*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if scope.StartSeq != 1 || scope.EndSeq != 5 {
		t.Fatalf("narrowed scope = %d-%d, want 1-5", scope.StartSeq, scope.EndSeq)
	}
	// The historical delivery under the earlier basis is untouched.
	deliveries := r.Deliveries("auth-1")
	if len(deliveries) != 1 || deliveries[0].EndSeq != 9 || deliveries[0].Basis.EndSeq != 9 {
		t.Fatalf("delivery history rewritten: %+v", deliveries)
	}
	// Out-of-order revoke: recorded late but effective before the narrow.
	if _, err := r.ImportNotice(batchRevoke("rv1", "auth-1", batchBase.Add(90*time.Minute)), batchBase.Add(5*time.Hour)); err != nil {
		t.Fatal(err)
	}
	scope, err = r.EffectiveScopeAt("auth-1", batchBase.Add(4*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !scope.Revoked {
		t.Fatal("late-recorded revoke must apply from its effective time")
	}
	// A basis before the revoke still shows the widened scope.
	scope, err = r.EffectiveScopeAt("auth-1", batchBase.Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if scope.Revoked || scope.EndSeq != 5 {
		t.Fatalf("early basis scope = %+v, want 1-5 not revoked", scope)
	}
	if got := len(r.Deliveries("auth-1")); got != 1 {
		t.Fatalf("revoke erased deliveries: %d", got)
	}
}

func TestBatchDecisionsSurviveReopen(t *testing.T) {
	r := NewRegistry()
	d, err := r.PreviewBatch([]Notice{
		batchGrant("g1", "auth-1", "seal-1", 1, 5, batchBase),
		batchGrant("g2", "auth-2", "seal-2", 1, 9, batchBase),
	}, batchBase)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.AdoptBatch(d.ID, []string{"g1"}, batchBase); err != nil {
		t.Fatal(err)
	}
	if err := r.WithdrawPending(d.ID, []string{"g2"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "registry.json")
	if err := r.SaveRegistry(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	// Re-previewing the same batch after reopen returns the same decision.
	again, err := loaded.PreviewBatch([]Notice{
		batchGrant("g1", "auth-1", "seal-1", 1, 5, batchBase),
		batchGrant("g2", "auth-2", "seal-2", 1, 9, batchBase),
	}, batchBase.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != d.ID {
		t.Fatal("same batch after reopen must map to the same decision")
	}
	if got := assessmentByID(t, again, "g2").Status; got != NoticeWithdrawn {
		t.Fatalf("withdrawn status lost across reopen: %s", got)
	}
	// Processing continues: the withdrawn notice stays out, new notices work.
	if _, err := loaded.AdoptBatch(d.ID, []string{"g2"}, batchBase.Add(time.Hour)); !errors.Is(err, ErrNoticeWithdrawn) {
		t.Fatalf("late adopt after reopen got %v, want ErrNoticeWithdrawn", err)
	}
	d2, err := loaded.PreviewBatch([]Notice{
		batchGrant("g3", "auth-3", "seal-3", 1, 4, batchBase),
	}, batchBase.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loaded.AdoptBatch(d2.ID, []string{"g3"}, batchBase.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	scope, err := loaded.EffectiveScopeAt("auth-3", batchBase.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if scope.EndSeq != 4 {
		t.Fatalf("scope after reopen = %+v, want 1-4", scope)
	}
	if len(loaded.Decisions()) != 2 {
		t.Fatalf("decisions after reopen = %d, want 2", len(loaded.Decisions()))
	}
}
