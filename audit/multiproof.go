package audit

import (
	"errors"
	"fmt"
)

// ErrEmptyRangeSet reports a combined verification request that declares no
// source ranges at all. An empty declaration has no positive answer, so it is
// rejected instead of silently passing.
var ErrEmptyRangeSet = errors.New("range proof set is empty")

// VerifyRangeProofSet verifies one range proof per independent source against
// the externally retained seal summary for that same source. Every proof must
// match exactly one summary and every summary exactly one proof; a declared
// source without its proof, or a proof without its summary, is a reported
// gap rather than a skipped check.
//
// The set deliberately says nothing about cross-source ordering. Each source
// chain is numbered and verified independently, and event timestamps are
// caller-supplied content, not a trusted global clock: a successful result
// must not be read as "events from source A happened before events from
// source B".
func VerifyRangeProofSet(summaries []SealSummary, proofs []RangeProof) error {
	if len(proofs) == 0 {
		return ErrEmptyRangeSet
	}
	summaryBySource := make(map[string]SealSummary, len(summaries))
	for _, summary := range summaries {
		if err := validateSummary(summary); err != nil {
			return err
		}
		if _, duplicate := summaryBySource[summary.Source]; duplicate {
			return &TamperError{Kind: TamperWrongSource, Message: fmt.Sprintf("duplicate seal summary for source %q", summary.Source)}
		}
		summaryBySource[summary.Source] = summary
	}
	verified := make(map[string]bool, len(proofs))
	for _, proof := range proofs {
		summary, ok := summaryBySource[proof.Source]
		if !ok {
			return &TamperError{Kind: TamperWrongSource, Message: fmt.Sprintf("range proof for source %q has no matching seal summary", proof.Source)}
		}
		if verified[proof.Source] {
			return &TamperError{Kind: TamperWrongSource, Message: fmt.Sprintf("duplicate range proof for source %q", proof.Source)}
		}
		verified[proof.Source] = true
		if err := VerifyRangeProof(summary, proof); err != nil {
			return err
		}
	}
	for _, summary := range summaries {
		if !verified[summary.Source] {
			return &TamperError{Kind: TamperMissingRange, Message: fmt.Sprintf("declared source %q has no range proof", summary.Source)}
		}
	}
	return nil
}
