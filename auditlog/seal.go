package auditlog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// SummaryVersion is the on-disk summary format version.
const SummaryVersion = 1

// SealSummary is the externally saved fingerprint of a sealed batch.
// It must be stored somewhere other than the log file itself (another disk,
// object storage, a signed receipt, ...): a tail-truncated log is internally
// self-consistent and can only be exposed by comparing against this summary.
type SealSummary struct {
	Version        int       `json:"version"`
	BatchID        string    `json:"batch_id"`
	SealedAt       time.Time `json:"sealed_at_utc"`
	RecordCount    uint64    `json:"record_count"`
	LogLength      int64     `json:"log_length_bytes"`
	LastRecordHash string    `json:"last_record_hash_hex"`
	LogSHA256      string    `json:"log_sha256_hex"`
}

// Seal freezes the current end of the log into a summary. It does not modify
// the log; the returned summary is the receipt the caller stores externally.
func (l *Log) Seal(batchID string) (*SealSummary, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	data, err := os.ReadFile(l.path)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != l.length {
		return nil, errors.New("auditlog: file changed outside this handle; reopen before sealing")
	}
	sum := sha256.Sum256(data)
	s := &SealSummary{
		Version:        SummaryVersion,
		BatchID:        batchID,
		SealedAt:       time.Now().UTC(),
		RecordCount:    l.index,
		LogLength:      l.length,
		LastRecordHash: hex.EncodeToString(zeroIfNil(l.lastHash)),
		LogSHA256:      hex.EncodeToString(sum[:]),
	}
	return s, nil
}

func zeroIfNil(h []byte) []byte {
	if h != nil {
		return h
	}
	return make([]byte, hashSize)
}

// WriteSummary saves a summary as pretty JSON.
func WriteSummary(path string, s *SealSummary) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

// ReadSummary loads a summary from JSON.
func ReadSummary(path string) (*SealSummary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s SealSummary
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	if s.Version != SummaryVersion {
		return nil, fmt.Errorf("auditlog: unsupported summary version %d", s.Version)
	}
	return &s, nil
}

// VerifyResult reports what was checked.
type VerifyResult struct {
	RecordCount   uint64
	LogLength     int64
	TailTruncated bool // only meaningful when a summary was provided
}

// VerifyChain replays the whole log, checking every frame checksum and the
// back-link chain. It detects rewriting, insertion and middle deletion.
// It cannot detect tail truncation: a truncated log still forms a valid
// prefix-chain. Use VerifyAgainstSummary for that.
func VerifyChain(path string) (*VerifyResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	count, err := replay(data)
	if err != nil {
		return nil, err
	}
	return &VerifyResult{RecordCount: count, LogLength: int64(len(data))}, nil
}

// VerifyAgainstSummary replays the chain and compares the result with the
// externally stored summary. This is the check that finds tail truncation
// (as well as rewriting, insertion and middle deletion).
func VerifyAgainstSummary(path string, s *SealSummary) (*VerifyResult, error) {
	res, err := VerifyChain(path)
	if err != nil {
		return res, err
	}
	var problems []string
	if res.RecordCount != s.RecordCount {
		if res.RecordCount < s.RecordCount {
			res.TailTruncated = res.LogLength < s.LogLength
			problems = append(problems, fmt.Sprintf("record count %d != sealed %d (records removed)", res.RecordCount, s.RecordCount))
		} else {
			problems = append(problems, fmt.Sprintf("record count %d != sealed %d (records added after seal)", res.RecordCount, s.RecordCount))
		}
	}
	if res.LogLength != s.LogLength {
		problems = append(problems, fmt.Sprintf("file length %d != sealed %d", res.LogLength, s.LogLength))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return res, err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != s.LogSHA256 {
		problems = append(problems, "whole-file SHA-256 differs from sealed summary")
	}
	// last-record hash chain comparison
	if len(data) > 0 {
		var lastH []byte
		off := int64(0)
		var prev []byte
		for off < int64(len(data)) {
			fl, h, env, complete, ferr := readFrame(data[off:])
			if ferr != nil || !complete {
				return res, &TamperError{Offset: off, Index: 0, Reason: "unreadable frame"}
			}
			if !equalHash(env.prevHash, prev) {
				return res, &TamperError{Offset: off, Index: 0, Reason: "chain broken"}
			}
			prev = h
			lastH = h
			off += fl
		}
		if hex.EncodeToString(zeroIfNil(lastH)) != s.LastRecordHash {
			problems = append(problems, "last record hash differs from sealed summary")
		}
	} else if s.RecordCount != 0 {
		problems = append(problems, "file is empty but summary records a non-empty batch")
	}
	if len(problems) > 0 {
		return res, fmt.Errorf("auditlog: sealed batch %q verification failed:\n  - %s", s.BatchID, joinProblems(problems))
	}
	return res, nil
}

func joinProblems(p []string) string {
	out := ""
	for i, s := range p {
		if i > 0 {
			out += "\n  - "
		}
		out += s
	}
	return out
}

// replay validates frames and chain links and returns the record count.
func replay(data []byte) (uint64, error) {
	off := int64(0)
	var idx uint64
	var prev []byte
	for off < int64(len(data)) {
		fl, h, env, complete, err := readFrame(data[off:])
		switch {
		case err != nil:
			return idx, &TamperError{Offset: off, Index: idx, Reason: err.Error()}
		case !complete:
			return idx, &TamperError{Offset: off, Index: idx, Reason: "truncated/torn frame"}
		}
		if !equalHash(env.prevHash, prev) {
			return idx, &TamperError{Offset: off, Index: idx, Reason: "previous-hash mismatch; a record was inserted, deleted or rewritten before this point"}
		}
		prev = h
		off += fl
		idx++
	}
	return idx, nil
}
