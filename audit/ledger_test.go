package audit

import (
	"errors"
	"testing"
	"time"
)

func ledgerFixture(t *testing.T) (*Ledger, string, *SealSummary, Disclosure, Authorization, time.Time) {
	t.Helper()
	summary, held, auth := rediscloseFixture(t)
	path := t.TempDir() + "/ledger.json"
	ledger, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	auth.IssuedAt = base
	return ledger, path, summary, held, auth, base
}

func TestLedgerImportIsIdempotentAndConflictChecked(t *testing.T) {
	ledger, _, _, _, auth, _ := ledgerFixture(t)
	added, err := ledger.ImportAuthorization(auth)
	if err != nil || !added {
		t.Fatalf("first import must add the authorization: added=%v err=%v", added, err)
	}
	added, err = ledger.ImportAuthorization(auth)
	if err != nil || added {
		t.Fatalf("re-importing the identical authorization must be a no-op: added=%v err=%v", added, err)
	}
	widened := auth
	widened.EndSeq = 6
	if _, err := ledger.ImportAuthorization(widened); !errors.Is(err, ErrAuthorizationConflict) {
		t.Fatalf("same id with a wider scope must conflict, got %v", err)
	}
}

func TestLedgerNoticesAndTimeBasedScope(t *testing.T) {
	ledger, _, _, _, auth, base := ledgerFixture(t)
	if _, err := ledger.ImportAuthorization(auth); err != nil {
		t.Fatal(err)
	}

	// Supplement widens the range going forward.
	wider := auth
	wider.EndSeq = 6
	supplement := Notice{ID: "n1", AuthID: auth.ID, Kind: NoticeSupplement, EffectiveAt: base.Add(time.Hour), Scope: &wider}
	added, err := ledger.ImportNotice(supplement)
	if err != nil || !added {
		t.Fatalf("supplement import: added=%v err=%v", added, err)
	}
	if added, err := ledger.ImportNotice(supplement); err != nil || added {
		t.Fatalf("re-importing the same notice must not add permission: added=%v err=%v", added, err)
	}
	conflicting := supplement
	conflicting.EffectiveAt = base.Add(2 * time.Hour)
	if _, err := ledger.ImportNotice(conflicting); !errors.Is(err, ErrNoticeConflict) {
		t.Fatalf("same notice id with different content must conflict, got %v", err)
	}

	// Before the supplement the old scope applies; after it the wider one.
	scope, err := ledger.EffectiveScope(auth.ID, base.Add(30*time.Minute))
	if err != nil || scope.EndSeq != 5 {
		t.Fatalf("scope before supplement must stay 2-5, got %+v err=%v", scope, err)
	}
	scope, err = ledger.EffectiveScope(auth.ID, base.Add(90*time.Minute))
	if err != nil || scope.EndSeq != 6 {
		t.Fatalf("scope after supplement must widen to 2-6, got %+v err=%v", scope, err)
	}

	// Narrow shrinks it again from a later time.
	narrower := auth
	narrower.EndSeq = 4
	narrow := Notice{ID: "n2", AuthID: auth.ID, Kind: NoticeNarrow, EffectiveAt: base.Add(2 * time.Hour), Scope: &narrower}
	if _, err := ledger.ImportNotice(narrow); err != nil {
		t.Fatal(err)
	}
	scope, err = ledger.EffectiveScope(auth.ID, base.Add(3*time.Hour))
	if err != nil || scope.EndSeq != 4 {
		t.Fatalf("scope after narrow must shrink to 2-4, got %+v err=%v", scope, err)
	}

	// A narrow that tries to widen is rejected.
	sneaky := auth
	sneaky.EndSeq = 9
	if _, err := ledger.ImportNotice(Notice{ID: "n3", AuthID: auth.ID, Kind: NoticeNarrow, EffectiveAt: base.Add(3 * time.Hour), Scope: &sneaky}); err == nil {
		t.Fatal("a narrow notice that widens the scope must be rejected")
	}

	// Revocation voids future use but keeps earlier evaluations valid.
	revoke := Notice{ID: "n4", AuthID: auth.ID, Kind: NoticeRevoke, EffectiveAt: base.Add(4 * time.Hour)}
	if _, err := ledger.ImportNotice(revoke); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.EffectiveScope(auth.ID, base.Add(5*time.Hour)); !errors.Is(err, ErrAuthorizationRevoked) {
		t.Fatalf("scope after revocation must report revocation, got %v", err)
	}
	if _, err := ledger.EffectiveScope(auth.ID, base.Add(3*time.Hour)); err != nil {
		t.Fatalf("past time bases must remain answerable after revocation: %v", err)
	}
}

func TestLedgerTransfersKeepHistoryAcrossRevocationAndReopen(t *testing.T) {
	ledger, path, summary, held, auth, base := ledgerFixture(t)
	if _, err := ledger.ImportAuthorization(auth); err != nil {
		t.Fatal(err)
	}
	sub := subAuth(auth, "auth-t1", "auditor-b", 2, 3)
	derived, err := Redisclose(*summary, auth, sub, held, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	// Record the actual delivery under the sub-authorization.
	if _, err := ledger.ImportAuthorization(sub); err != nil {
		t.Fatal(err)
	}
	if err := ledger.RecordTransfer(sub.ID, *derived, base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Re-importing the same disclosure adds nothing.
	if err := ledger.RecordTransfer(sub.ID, *derived, base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := len(ledger.Transfers()); got != 1 {
		t.Fatalf("duplicate delivery must not add a record, got %d transfers", got)
	}
	// A delivery outside the authorized window is refused.
	over := *derived
	over.EndSeq = 4
	if err := ledger.RecordTransfer(sub.ID, over, base.Add(time.Hour)); !errors.Is(err, ErrUnauthorizedScope) {
		t.Fatalf("delivery beyond the authorized window must fail, got %v", err)
	}

	// Revoke the sub-authorization; the past delivery stays on record.
	revoke := Notice{ID: "nr", AuthID: sub.ID, Kind: NoticeRevoke, EffectiveAt: base.Add(2 * time.Hour)}
	if _, err := ledger.ImportNotice(revoke); err != nil {
		t.Fatal(err)
	}
	if err := ledger.RecordTransfer(sub.ID, *derived, base.Add(3*time.Hour)); !errors.Is(err, ErrAuthorizationRevoked) {
		t.Fatalf("new deliveries after revocation must fail, got %v", err)
	}

	// Reopen from disk: history and time-based state survive.
	reopened, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	transfers := reopened.Transfers()
	if len(transfers) != 1 || transfers[0].AuthID != sub.ID || transfers[0].StartSeq != 2 || transfers[0].EndSeq != 3 {
		t.Fatalf("reopened ledger must trace the delivery to its authorization and window, got %+v", transfers)
	}
	if _, err := reopened.EffectiveScope(sub.ID, base.Add(3*time.Hour)); !errors.Is(err, ErrAuthorizationRevoked) {
		t.Fatalf("revocation must survive reopen, got %v", err)
	}
	if scope, err := reopened.EffectiveScope(sub.ID, base.Add(time.Hour)); err != nil || scope.EndSeq != 3 {
		t.Fatalf("pre-revocation scope must survive reopen, got %+v err=%v", scope, err)
	}
}

func TestLedgerOfflineVerificationRecordsKeepOldBasis(t *testing.T) {
	ledger, _, summary, held, auth, base := ledgerFixture(t)
	if _, err := ledger.ImportAuthorization(auth); err != nil {
		t.Fatal(err)
	}
	sub := subAuth(auth, "auth-v1", "auditor-b", 2, 5)
	if _, err := ledger.ImportAuthorization(sub); err != nil {
		t.Fatal(err)
	}
	derived, err := Redisclose(*summary, auth, sub, held, 2, 5)
	if err != nil {
		t.Fatal(err)
	}

	// Offline material verified while the full window was authorized.
	if err := ledger.RecordVerification(*derived, base.Add(time.Hour), true, "verified while 2-5 was authorized"); err != nil {
		t.Fatal(err)
	}
	// A narrow notice arrives later; the material is re-evaluated under the
	// new basis and the old record stays.
	narrower := sub
	narrower.EndSeq = 3
	if _, err := ledger.ImportNotice(Notice{ID: "nv", AuthID: sub.ID, Kind: NoticeNarrow, EffectiveAt: base.Add(2 * time.Hour), Scope: &narrower}); err != nil {
		t.Fatal(err)
	}
	scope, err := ledger.EffectiveScope(sub.ID, base.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	inScope := scope.coversRange(derived.StartSeq, derived.EndSeq)
	if inScope {
		t.Fatal("window 2-5 must be out of scope after the narrow to 2-3")
	}
	if err := ledger.RecordVerification(*derived, base.Add(3*time.Hour), inScope, "re-evaluated after narrow notice"); err != nil {
		t.Fatal(err)
	}
	records := ledger.Verifications()
	if len(records) != 2 || !records[0].InScope || records[1].InScope {
		t.Fatalf("both time-basis verification records must be kept, got %+v", records)
	}
}
