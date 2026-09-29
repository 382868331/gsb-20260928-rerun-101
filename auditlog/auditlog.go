// Package auditlog implements an append-only, tamper-evident event store.
//
// Every record is chained to the previous record with SHA-256, so rewriting,
// inserting or deleting a record anywhere except the tail breaks the chain.
// Tail truncation cannot be detected from the file itself: it is detected by
// comparing the log against a SealSummary that was saved elsewhere.
package auditlog

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Frame layout: magic(2) | payloadLen(4, LE) | payload | sha256(32).
// The checksum covers magic, payloadLen and payload.
const (
	magic0      = 0xA1
	magic1      = 0x7A
	headerSize  = 6
	hashSize    = sha256.Size
	overhead    = headerSize + hashSize
	maxPayload  = 16 << 20 // 16 MiB, guards against corrupted length fields
	payloadVers = 1
)

// Event is one audit record produced by the application. It describes an
// application-generated event; no host/user activity is collected here.
type Event struct {
	Time      time.Time
	EventType string
	Source    string
	ID        string // application-defined event id; may be empty
	Data      []byte // opaque payload
}

// Record is an Event plus its position in the log.
type Record struct {
	Event
	Index uint64 // zero-based position in source order
}

// Log is an opened append-only audit store.
type Log struct {
	mu       sync.Mutex
	f        *os.File
	path     string
	index    uint64 // number of intact records
	length   int64  // bytes occupied by intact records
	lastHash []byte // hash of the previous record (nil for empty)
}

// TamperError reports that the on-disk chain is broken.
type TamperError struct {
	Offset int64
	Index  uint64
	Reason string
}

func (e *TamperError) Error() string {
	return fmt.Sprintf("auditlog: tampering or corruption at record %d (offset %d): %s", e.Index, e.Offset, e.Reason)
}

// envelope is a decoded payload together with its back-link hash.
type envelope struct {
	event    Event
	prevHash []byte
}

// Create creates a new empty store at path. It fails if the file already exists.
func Create(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	return &Log{f: f, path: path}, nil
}

// Open opens an existing store, recovering from an interrupted write by
// dropping the unfinished trailing record. A broken frame anywhere before the
// tail is reported as tampering and is never silently discarded.
func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	l := &Log{f: f, path: path}
	if err := l.recover(); err != nil {
		f.Close()
		return nil, err
	}
	return l, nil
}

func (l *Log) recover() error {
	data, err := io.ReadAll(l.f)
	if err != nil {
		return err
	}
	off := int64(0)
	var idx uint64
	var prev []byte
	var goodEnd int64

	for off < int64(len(data)) {
		recEnd, h, env, complete, err := readFrame(data[off:])
		if err != nil {
			// A structurally bad frame is accepted only when the rest of the file
			// is physically short: that is an interrupted trailing write. Bad magic
			// with enough bytes present is tampering.
			if !physicallyShort(data, off) {
				return &TamperError{Offset: off, Index: idx, Reason: err.Error()}
			}
			break
		}
		if !complete {
			break // torn trailing frame
		}
		if !equalHash(env.prevHash, prev) {
			return &TamperError{Offset: off, Index: idx, Reason: "previous-hash mismatch; a record was inserted, deleted or rewritten before this point"}
		}
		prev = h
		goodEnd = off + recEnd
		off = goodEnd
		idx++
	}

	if goodEnd != int64(len(data)) {
		if err := l.f.Truncate(goodEnd); err != nil {
			return err
		}
	}
	l.length = goodEnd
	l.index = idx
	l.lastHash = prev
	if _, err := l.f.Seek(goodEnd, io.SeekStart); err != nil {
		return err
	}
	return nil
}

// physicallyShort reports whether the bytes from off look like a frame that did
// not finish being written (torn write) rather than a complete bad frame.
func physicallyShort(data []byte, off int64) bool {
	rest := data[off:]
	if len(rest) < headerSize {
		return true
	}
	n := int(binary.LittleEndian.Uint32(rest[2:6]))
	if n > maxPayload {
		// Corrupt length could itself be a torn write only if the file clearly
		// ends within the header region; a full header with a huge length and
		// no body indicates garbage, not a short write.
		return false
	}
	return len(rest) < headerSize+n+hashSize
}

// readFrame parses one frame. complete=false means a short trailing frame
// (interrupted write); a non-nil error means a structurally invalid frame.
func readFrame(b []byte) (frameLen int64, recHash []byte, env envelope, complete bool, err error) {
	if len(b) < headerSize {
		return 0, nil, envelope{}, false, nil
	}
	if b[0] != magic0 || b[1] != magic1 {
		return 0, nil, envelope{}, false, errors.New("bad frame magic")
	}
	n := int(binary.LittleEndian.Uint32(b[2:6]))
	if n > maxPayload {
		return 0, nil, envelope{}, false, fmt.Errorf("payload length %d exceeds limit", n)
	}
	end := headerSize + n + hashSize
	if len(b) < end {
		return 0, nil, envelope{}, false, nil
	}
	sum := sha256.Sum256(b[:headerSize+n])
	if !equalHash(sum[:], b[headerSize+n:end]) {
		return 0, nil, envelope{}, false, errors.New("frame checksum mismatch")
	}
	env2, err := decodePayload(b[headerSize : headerSize+n])
	if err != nil {
		return 0, nil, envelope{}, false, err
	}
	return int64(end), sum[:], env2, true, nil
}

// Append appends one event, chaining it to the previous record and fsync-ing.
func (l *Log) Append(ev Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(ev.EventType) > 65535 || len(ev.Source) > 65535 || len(ev.ID) > 65535 {
		return errors.New("auditlog: string field too long")
	}
	if len(ev.Data) > maxPayload {
		return errors.New("auditlog: data too large")
	}
	pl := encodePayload(ev, l.lastHash)
	frame := make([]byte, overhead+len(pl))
	frame[0], frame[1] = magic0, magic1
	binary.LittleEndian.PutUint32(frame[2:6], uint32(len(pl)))
	copy(frame[headerSize:], pl)
	sum := sha256.Sum256(frame[:headerSize+len(pl)])
	copy(frame[headerSize+len(pl):], sum[:])
	if _, err := l.f.Write(frame); err != nil {
		return err
	}
	if err := l.f.Sync(); err != nil {
		return err
	}
	l.length += int64(len(frame))
	l.index++
	l.lastHash = sum[:]
	return nil
}

// Count returns the number of intact records currently in the store.
func (l *Log) Count() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.index
}

// Length returns the byte offset after the last intact record.
func (l *Log) Length() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.length
}

// LastHash returns the hash of the last record (nil when the log is empty).
func (l *Log) LastHash() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lastHash == nil {
		return nil
	}
	h := make([]byte, len(l.lastHash))
	copy(h, l.lastHash)
	return h
}

// Path returns the store file path.
func (l *Log) Path() string { return l.path }

// Close closes the underlying file.
func (l *Log) Close() error { return l.f.Close() }

// Scan walks records in source (append) order and validates the chain.
func (l *Log) Scan(fn func(Record) error) error {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return err
	}
	off := int64(0)
	var idx uint64
	var prev []byte
	for off < int64(len(data)) {
		frameLen, h, env, complete, err := readFrame(data[off:])
		if err != nil || !complete {
			return &TamperError{Offset: off, Index: idx, Reason: "unreadable frame; run Verify for details"}
		}
		if !equalHash(env.prevHash, prev) {
			return &TamperError{Offset: off, Index: idx, Reason: "previous-hash mismatch; a record was inserted, deleted or rewritten before this point"}
		}
		if err := fn(Record{Event: env.event, Index: idx}); err != nil {
			return err
		}
		prev = h
		off += frameLen
		idx++
	}
	return nil
}

// payload encoding: version(1)|time(8)|type u16+bytes|source|id|data u32+bytes|prevHash(32).

func encodePayload(ev Event, prev []byte) []byte {
	b := make([]byte, 0, 256+len(ev.Data))
	b = append(b, payloadVers)
	b = binary.LittleEndian.AppendUint64(b, uint64(ev.Time.UnixNano()))
	b = appendString16(b, ev.EventType)
	b = appendString16(b, ev.Source)
	b = appendString16(b, ev.ID)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(ev.Data)))
	b = append(b, ev.Data...)
	if prev == nil {
		b = append(b, make([]byte, hashSize)...)
	} else {
		b = append(b, prev...)
	}
	return b
}

func appendString16(b []byte, s string) []byte {
	b = binary.LittleEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

func decodePayload(b []byte) (envelope, error) {
	if len(b) < 1+8+2 || b[0] != payloadVers {
		return envelope{}, errors.New("bad payload version")
	}
	pos := 1
	ts := int64(binary.LittleEndian.Uint64(b[pos : pos+8]))
	pos += 8
	readStr := func() (string, error) {
		if pos+2 > len(b) {
			return "", io.ErrUnexpectedEOF
		}
		n := int(binary.LittleEndian.Uint16(b[pos : pos+2]))
		pos += 2
		if pos+n > len(b) {
			return "", io.ErrUnexpectedEOF
		}
		s := string(b[pos : pos+n])
		pos += n
		return s, nil
	}
	et, err := readStr()
	if err != nil {
		return envelope{}, err
	}
	src, err := readStr()
	if err != nil {
		return envelope{}, err
	}
	id, err := readStr()
	if err != nil {
		return envelope{}, err
	}
	if pos+4 > len(b) {
		return envelope{}, io.ErrUnexpectedEOF
	}
	dn := int(binary.LittleEndian.Uint32(b[pos : pos+4]))
	pos += 4
	if pos+dn+hashSize > len(b) {
		return envelope{}, io.ErrUnexpectedEOF
	}
	data := make([]byte, dn)
	copy(data, b[pos:pos+dn])
	pos += dn
	prev := make([]byte, hashSize)
	copy(prev, b[pos:pos+hashSize])
	return envelope{
		event:    Event{Time: time.Unix(0, ts).UTC(), EventType: et, Source: src, ID: id, Data: data},
		prevHash: prev,
	}, nil
}

func equalHash(a, b []byte) bool {
	a = normalizeHash(a)
	b = normalizeHash(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// normalizeHash maps nil/empty to the canonical all-zero genesis hash.
func normalizeHash(h []byte) []byte {
	if len(h) == 0 {
		return make([]byte, hashSize)
	}
	return h
}
