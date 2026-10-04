package audit

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var reBase = time.Unix(1701000000, 0).UTC()

func setupReDisclosure(t *testing.T) (SealSummary, Disclosure) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for i := 1; i <= 8; i++ {
		eventType := "note"
		if i == 4 || i == 6 {
			eventType = "secret"
		}
		if _, err := store.Append(Event{
			ID:         "ev-" + strings.Repeat("x", i),
			Source:     "camera-a",
			Type:       eventType,
			OccurredAt: reBase.Add(time.Duration(i) * time.Minute),
			Payload:    []byte("classified-payload"),
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	summary, err := store.Seal("camera-a")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := store.BuildRangeProof("camera-a", 1, 8)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := NarrowDisclosure(*summary, *proof, "bob", 1, 8)
	if err != nil {
		t.Fatal(err)
	}
	return *summary, *parent
}

func onwardAuth(summary SealSummary) Authorization {
	return Authorization{
		SealID:      summary.ID(),
		Source:      "camera-a",
		Recipient:   "bob",
		StartSeq:    2,
		EndSeq:      7,
		AllowOnward: true,
		IssuedAt:    reBase,
	}
}

func noteOnlyAuth(summary SealSummary) Authorization {
	auth := onwardAuth(summary)
	auth.Types = []string{"note"}
	return auth
}

func TestReDisclosureDeriveAndVerify(t *testing.T) {
	summary, parent := setupReDisclosure(t)
	auth := onwardAuth(summary)

	rd, err := DeriveReDisclosure(summary, parent, auth, "carol", 3, 5)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if rd.SealID != summary.ID() || rd.AuthorizationID != AuthorizationID(auth) {
		t.Fatal("re-disclosure must name the seal and authorization it inherits")
	}
	if rd.Recipient != "carol" || rd.StartSeq != 3 || rd.EndSeq != 5 {
		t.Fatalf("unexpected window %d-%d for %q", rd.StartSeq, rd.EndSeq, rd.Recipient)
	}
	if err := VerifyReDisclosure(summary, auth, *rd); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// A supplementary adjacent window under the same authorization merges.
	rd2, err := DeriveReDisclosure(summary, parent, auth, "carol", 6, 7)
	if err != nil {
		t.Fatalf("derive supplement: %v", err)
	}
	merged, err := MergeReDisclosures(*rd, *rd2)
	if err != nil {
		t.Fatalf("merge supplement: %v", err)
	}
	if merged.StartSeq != 3 || merged.EndSeq != 7 {
		t.Fatalf("merged window %d-%d, want 3-7", merged.StartSeq, merged.EndSeq)
	}
	if err := VerifyReDisclosure(summary, auth, *merged); err != nil {
		t.Fatalf("merged window must verify under its own authorization: %v", err)
	}

	// The same window presented under a note-only authorization crosses the
	// visible-content limit at seq 4; the error names the sequence number
	// only and never echoes record content.
	noteOnly := noteOnlyAuth(summary)
	crossing := *merged
	crossing.AuthorizationID = AuthorizationID(noteOnly)
	err = VerifyReDisclosure(summary, noteOnly, crossing)
	if !errors.Is(err, ErrBeyondAuthorization) {
		t.Fatalf("window crossing the visible-content limit: %v", err)
	}
	if strings.Contains(err.Error(), "classified-payload") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("error leaks unauthorized content: %v", err)
	}
}

func TestReDisclosureCannotExceedAuthorization(t *testing.T) {
	summary, parent := setupReDisclosure(t)
	auth := onwardAuth(summary)

	// The holder's parent covers 1-8, but the authorization only covers 2-7.
	if _, err := DeriveReDisclosure(summary, parent, auth, "carol", 1, 7); !errors.Is(err, ErrBeyondAuthorization) {
		t.Fatalf("broader held material must not widen the authorization: %v", err)
	}
	if _, err := DeriveReDisclosure(summary, parent, auth, "carol", 2, 8); !errors.Is(err, ErrBeyondAuthorization) {
		t.Fatalf("range past the authorization must fail: %v", err)
	}

	// Same source name, different seal: the authorization does not apply.
	other := auth
	other.SealID = "some-other-seal"
	if _, err := DeriveReDisclosure(summary, parent, other, "carol", 3, 5); !errors.Is(err, ErrBeyondAuthorization) {
		t.Fatalf("matching source name alone must not authorize: %v", err)
	}

	// Onward transfer not allowed.
	noOnward := auth
	noOnward.AllowOnward = false
	if _, err := DeriveReDisclosure(summary, parent, noOnward, "carol", 3, 5); !errors.Is(err, ErrOnwardDenied) {
		t.Fatalf("onward transfer must be denied: %v", err)
	}

	// A record inside the window has a type the authorization hides.
	noteOnly := noteOnlyAuth(summary)
	if _, err := DeriveReDisclosure(summary, parent, noteOnly, "carol", 3, 4); !errors.Is(err, ErrBeyondAuthorization) {
		t.Fatalf("hidden event type must not be derivable: %v", err)
	}
}

func TestVerifyReDisclosureRejectsWrongLineage(t *testing.T) {
	summary, parent := setupReDisclosure(t)
	auth := onwardAuth(summary)
	rd, err := DeriveReDisclosure(summary, parent, auth, "carol", 3, 5)
	if err != nil {
		t.Fatal(err)
	}

	// A different authorization for the same source and range must not
	// verify material that names the original authorization.
	other := auth
	other.ID = "other-auth"
	if err := VerifyReDisclosure(summary, other, *rd); err == nil {
		t.Fatal("verification under a different authorization must fail")
	}

	// Identical-looking material under two authorizations must not merge.
	rdOther, err := DeriveReDisclosure(summary, parent, auth, "carol", 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	rdOther.AuthorizationID = "other-auth"
	if _, err := MergeReDisclosures(*rd, *rdOther); !errors.Is(err, ErrDisclosureMismatch) {
		t.Fatalf("cross-authorization merge must be refused: %v", err)
	}

	// Window outside the recipient's view is invisible, never missing.
	trimmed := *rd
	trimmed.StartSeq = 4
	trimmed.Records = trimmed.Records[1:]
	trimmed.MerkleSteps = trimmed.MerkleSteps[1:]
	trimmed.FirstPrevious = rd.Records[0].RecordHash
	if err := VerifyReDisclosure(summary, auth, trimmed); err != nil {
		t.Fatalf("narrower window must still verify: %v", err)
	}
}

func TestRegistryNoticeTimeline(t *testing.T) {
	summary, parent := setupReDisclosure(t)
	auth := onwardAuth(summary)
	authID := AuthorizationID(auth)
	reg := NewRegistry()

	t1 := reBase.Add(time.Hour)
	t2 := reBase.Add(2 * time.Hour)
	t3 := reBase.Add(3 * time.Hour)

	grant := Notice{
		ID:              "n1",
		Kind:            NoticeGrant,
		AuthorizationID: authID,
		EffectiveAt:     t1,
		Authorization:   &auth,
	}
	added, err := reg.ImportNotice(grant, t1)
	if err != nil || !added {
		t.Fatalf("import grant: added=%v err=%v", added, err)
	}
	// Re-importing the same notice adds nothing.
	added, err = reg.ImportNotice(grant, t1.Add(time.Minute))
	if err != nil || added {
		t.Fatalf("duplicate notice must be a no-op: added=%v err=%v", added, err)
	}

	rd, err := DeriveReDisclosure(summary, parent, auth, "carol", 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.RecordDelivery(*rd, "bob", t1.Add(30*time.Minute)); err != nil {
		t.Fatalf("delivery within scope: %v", err)
	}
	reg.RecordVerification(VerificationRecord{
		AuthorizationID: authID,
		SealID:          rd.SealID,
		CheckedAt:       t1.Add(30 * time.Minute),
		BasisAt:         t1.Add(30 * time.Minute),
		StartSeq:        3,
		EndSeq:          5,
		Result:          "ok",
	})

	// The authorization is later narrowed to 3-4, effective at t2.
	narrow := Notice{
		ID:              "n2",
		Kind:            NoticeNarrow,
		AuthorizationID: authID,
		EffectiveAt:     t2,
		Narrow:          &NarrowSpec{StartSeq: 3, EndSeq: 4, AllowOnward: true},
	}
	if _, err := reg.ImportNotice(narrow, t2); err != nil {
		t.Fatal(err)
	}

	// Under the t1 basis the scope is still the original 2-7.
	scope, err := reg.EffectiveScopeAt(authID, t1.Add(45*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if scope.StartSeq != 2 || scope.EndSeq != 7 || scope.Revoked {
		t.Fatalf("t1 basis scope = %+v, want 2-7", scope)
	}
	// Under the t3 basis the scope has narrowed.
	scope, err = reg.EffectiveScopeAt(authID, t3)
	if err != nil {
		t.Fatal(err)
	}
	if scope.StartSeq != 3 || scope.EndSeq != 4 {
		t.Fatalf("t3 basis scope = %+v, want 3-4", scope)
	}

	// A new delivery of seq 5 after the narrowing is refused, but the
	// earlier delivery of 3-5 stays on record.
	rdLate, err := DeriveReDisclosure(summary, parent, auth, "carol", 5, 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.RecordDelivery(*rdLate, "bob", t3); !errors.Is(err, ErrBeyondAuthorization) {
		t.Fatalf("delivery past the narrowed scope must fail: %v", err)
	}
	deliveries := reg.Deliveries(authID)
	if len(deliveries) != 1 || deliveries[0].EndSeq != 5 {
		t.Fatalf("past deliveries must remain on record: %+v", deliveries)
	}

	// Revocation effective at t3 blocks future deliveries without erasing
	// the past ones.
	revoke := Notice{ID: "n3", Kind: NoticeRevoke, AuthorizationID: authID, EffectiveAt: t3}
	if _, err := reg.ImportNotice(revoke, t3); err != nil {
		t.Fatal(err)
	}
	rdOK, err := DeriveReDisclosure(summary, parent, auth, "carol", 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.RecordDelivery(*rdOK, "bob", t3.Add(time.Minute)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("delivery after revocation must fail: %v", err)
	}
	if got := len(reg.Deliveries(authID)); got != 1 {
		t.Fatalf("revocation must not erase past deliveries, got %d", got)
	}

	// Persist and reload: every transfer still traces to its then-valid
	// authorization and scope, and old verification records survive.
	path := filepath.Join(t.TempDir(), "registry.json")
	if err := reg.SaveRegistry(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	loadedDeliveries := loaded.Deliveries(authID)
	if len(loadedDeliveries) != 1 || loadedDeliveries[0].Basis.EndSeq != 7 {
		t.Fatalf("reloaded deliveries lost their basis: %+v", loadedDeliveries)
	}
	if got := len(loaded.Verifications(authID)); got != 1 {
		t.Fatalf("verification records must survive reload, got %d", got)
	}
	scope, err = loaded.EffectiveScopeAt(authID, t3)
	if err != nil || !scope.Revoked {
		t.Fatalf("reloaded scope at t3 = %+v, err=%v, want revoked", scope, err)
	}
	if _, err := loaded.RecordDelivery(*rdOK, "bob", t3.Add(2*time.Minute)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("reloaded registry must still refuse delivery: %v", err)
	}
}

func TestRegistryOfflineNoticeTimeBasis(t *testing.T) {
	summary, parent := setupReDisclosure(t)
	auth := onwardAuth(summary)
	authID := AuthorizationID(auth)
	reg := NewRegistry()

	t1 := reBase.Add(time.Hour)
	t2 := reBase.Add(2 * time.Hour)
	tOffline := reBase.Add(24 * time.Hour)

	if _, err := reg.ImportNotice(Notice{
		ID:              "g1",
		Kind:            NoticeGrant,
		AuthorizationID: authID,
		EffectiveAt:     t1,
		Authorization:   &auth,
	}, t1); err != nil {
		t.Fatal(err)
	}
	rd, err := DeriveReDisclosure(summary, parent, auth, "carol", 5, 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.RecordDelivery(*rd, "bob", t2); err != nil {
		t.Fatal(err)
	}
	reg.RecordVerification(VerificationRecord{
		AuthorizationID: authID,
		SealID:          rd.SealID,
		CheckedAt:       t2,
		BasisAt:         t2,
		StartSeq:        5,
		EndSeq:          5,
		Result:          "ok",
	})

	// A revocation effective at t1 only reaches this offline holder much
	// later. Once imported, the status under the t2 basis shows revoked,
	// while the old verification record keeps its original basis.
	revoke := Notice{ID: "r1", Kind: NoticeRevoke, AuthorizationID: authID, EffectiveAt: t1}
	if _, err := reg.ImportNotice(revoke, tOffline); err != nil {
		t.Fatal(err)
	}
	scope, err := reg.EffectiveScopeAt(authID, t2)
	if err != nil {
		t.Fatal(err)
	}
	if !scope.Revoked {
		t.Fatalf("scope under the t2 basis must show revoked, got %+v", scope)
	}
	records := reg.Verifications(authID)
	if len(records) != 1 || !records[0].BasisAt.Equal(t2) || records[0].Result != "ok" {
		t.Fatalf("old verification record must be retained unchanged: %+v", records)
	}
	if got := len(reg.Deliveries(authID)); got != 1 {
		t.Fatalf("delivered material must not pretend to disappear, got %d deliveries", got)
	}
}

func TestRegistryRejectsCrossSealSourceSupplements(t *testing.T) {
	summary, parent := setupReDisclosure(t)
	auth := onwardAuth(summary)
	authID := AuthorizationID(auth)
	reg := NewRegistry()

	t1 := reBase.Add(time.Hour)
	t2 := reBase.Add(2 * time.Hour)

	if _, err := reg.ImportNotice(Notice{
		ID:              "g1",
		Kind:            NoticeGrant,
		AuthorizationID: authID,
		EffectiveAt:     t1,
		Authorization:   &auth,
	}, t1); err != nil {
		t.Fatal(err)
	}
	rd, err := DeriveReDisclosure(summary, parent, auth, "carol", 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.RecordDelivery(*rd, "bob", t1.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		mutate func(a *Authorization)
	}{
		{"different seal", func(a *Authorization) { a.SealID = "seal-other" }},
		{"different source", func(a *Authorization) { a.Source = "camera-b" }},
		{"different recipient", func(a *Authorization) { a.Recipient = "mallory" }},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			foreign := auth
			tc.mutate(&foreign)
			foreign.StartSeq = 1
			foreign.EndSeq = 8
			added, err := reg.ImportNotice(Notice{
				ID:              "foreign-" + tc.name,
				Kind:            NoticeGrant,
				AuthorizationID: authID,
				EffectiveAt:     t2,
				Authorization:   &foreign,
			}, t2)
			if !errors.Is(err, ErrAuthorizationBindingMismatch) {
				t.Fatalf("case %d: expected binding mismatch, got added=%v err=%v", i, added, err)
			}
			if added {
				t.Fatalf("case %d: mismatched notice must not be imported", i)
			}
		})
	}

	// The established scope, deliveries, and non-revoked status are
	// untouched by the rejected supplements.
	scope, err := reg.EffectiveScopeAt(authID, t2.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if scope.Revoked || scope.StartSeq != 2 || scope.EndSeq != 7 {
		t.Fatalf("rejected supplements must not change the scope, got %+v", scope)
	}
	deliveries := reg.Deliveries(authID)
	if len(deliveries) != 1 || deliveries[0].StartSeq != 3 || deliveries[0].EndSeq != 5 {
		t.Fatalf("rejected supplements must not change deliveries, got %+v", deliveries)
	}

	// A legitimate supplement under the same binding still widens the
	// scope, and narrowing plus revocation still apply in order.
	wider := auth
	wider.StartSeq = 1
	wider.EndSeq = 8
	if _, err := reg.ImportNotice(Notice{
		ID:              "g2",
		Kind:            NoticeGrant,
		AuthorizationID: authID,
		EffectiveAt:     t2,
		Authorization:   &wider,
	}, t2); err != nil {
		t.Fatalf("same-binding supplement must be accepted: %v", err)
	}
	t3 := reBase.Add(3 * time.Hour)
	if _, err := reg.ImportNotice(Notice{
		ID:              "n2",
		Kind:            NoticeNarrow,
		AuthorizationID: authID,
		EffectiveAt:     t3,
		Narrow:          &NarrowSpec{StartSeq: 2, EndSeq: 6, AllowOnward: true},
	}, t3); err != nil {
		t.Fatal(err)
	}
	t4 := reBase.Add(4 * time.Hour)
	if _, err := reg.ImportNotice(Notice{
		ID:              "r1",
		Kind:            NoticeRevoke,
		AuthorizationID: authID,
		EffectiveAt:     t4,
	}, t4); err != nil {
		t.Fatal(err)
	}
	scope, err = reg.EffectiveScopeAt(authID, t3.Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if scope.Revoked || scope.StartSeq != 2 || scope.EndSeq != 6 {
		t.Fatalf("narrowed scope = %+v, want 2-6", scope)
	}
	scope, err = reg.EffectiveScopeAt(authID, t4.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !scope.Revoked {
		t.Fatalf("scope after revocation = %+v, want revoked", scope)
	}

	// Persistence keeps the binding enforcement after a reload.
	path := filepath.Join(t.TempDir(), "registry.json")
	if err := reg.SaveRegistry(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	foreign := auth
	foreign.Source = "camera-b"
	if _, err := loaded.ImportNotice(Notice{
		ID:              "foreign-after-reload",
		Kind:            NoticeGrant,
		AuthorizationID: authID,
		EffectiveAt:     t4.Add(time.Hour),
		Authorization:   &foreign,
	}, t4.Add(time.Hour)); !errors.Is(err, ErrAuthorizationBindingMismatch) {
		t.Fatalf("reloaded registry must still reject cross-source supplements: %v", err)
	}
	scope, err = loaded.EffectiveScopeAt(authID, t4.Add(time.Minute))
	if err != nil || !scope.Revoked {
		t.Fatalf("reloaded scope = %+v, err=%v, want revoked", scope, err)
	}
	if got := len(loaded.Deliveries(authID)); got != 1 {
		t.Fatalf("reloaded deliveries changed, got %d", got)
	}
}
