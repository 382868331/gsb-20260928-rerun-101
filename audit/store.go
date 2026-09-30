package audit

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	frameMagic        uint32 = 0x41554431
	frameHeaderLength        = 8
	hashLength               = 32
)

var ErrNoRecord = errors.New("audit record not found")

// Event is supplied by the project that owns the audit log. The audit store
// does not collect desktop or user activity on its own.
type Event struct {
	ID         string    `json:"id"`
	Source     string    `json:"source"`
	Type       string    `json:"type"`
	OccurredAt time.Time `json:"occurred_at"`
	Payload    []byte    `json:"payload,omitempty"`
}

// Record is one immutable, hash-linked event. Seq values begin at one and
// preserve the order supplied by the calling project.
type Record struct {
	Seq          uint64 `json:"seq"`
	PreviousHash []byte `json:"previous_hash"`
	Event        Event  `json:"event"`
	RecordHash   []byte `json:"record_hash"`
}

type frameHeader struct {
	Magic  uint32
	Length uint32
}

type envelope struct {
	Version    uint64 `json:"version"`
	Seq        uint64 `json:"seq"`
	Previous   []byte `json:"previous_hash"`
	Event      Event  `json:"event"`
	RecordHash []byte `json:"record_hash"`
}

type canonicalEvent struct {
	ID         string `json:"id"`
	Source     string `json:"source"`
	Type       string `json:"type"`
	OccurredAt string `json:"occurred_at"`
	Payload    []byte `json:"payload,omitempty"`
}

type canonicalRecord struct {
	Version  uint64         `json:"version"`
	Seq      uint64         `json:"seq"`
	Previous []byte         `json:"previous_hash"`
	Event    canonicalEvent `json:"event"`
}

// Store is an append-only audit log. Its zero value is not usable; use Open.
type Store struct {
	path    string
	file    *os.File
	records []Record
	sources map[string][]Record
}

// Open opens an audit log and removes only an incomplete frame at the physical
// end of the file. Every complete, checksum-validated record before that frame
// remains available.
func Open(path string) (*Store, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}

	s := &Store{path: path, file: f, sources: make(map[string][]Record)}
	if err := s.recoverTail(); err != nil {
		f.Close()
		return nil, err
	}
	if err := s.load(); err != nil {
		f.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.file.Close()
}

// Path returns the storage path.
func (s *Store) Path() string { return s.path }

// Len returns the number of complete records currently stored.
func (s *Store) Len() int { return len(s.records) }

// Append adds one event in caller-supplied order.
func (s *Store) Append(event Event) (*Record, error) {
	records, err := s.AppendBatch([]Event{event})
	if err != nil {
		return nil, err
	}
	return &records[0], nil
}

// AppendBatch adds events without changing their order.
func (s *Store) AppendBatch(events []Event) ([]Record, error) {
	if len(events) == 0 {
		return nil, nil
	}

	appended := make([]Record, 0, len(events))
	for _, event := range events {
		normalized := normalizeEvent(event)
		if normalized.Source == "" {
			return nil, fmt.Errorf("audit event source is required")
		}
		sourceRecords := s.sources[normalized.Source]
		seq := uint64(len(sourceRecords) + 1)
		var previous []byte
		if len(sourceRecords) > 0 {
			previous = sourceRecords[len(sourceRecords)-1].RecordHash
		}
		recordHash := hashRecord(seq, previous, normalized)
		frame, err := encodeFrame(seq, previous, normalized, recordHash)
		if err != nil {
			return nil, err
		}
		if _, err := s.file.Write(frame); err != nil {
			return nil, err
		}
		if err := s.file.Sync(); err != nil {
			return nil, err
		}

		record := Record{Seq: seq, PreviousHash: append([]byte(nil), previous...), Event: normalized, RecordHash: recordHash}
		s.records = append(s.records, record)
		s.sources[normalized.Source] = append(sourceRecords, record)
		appended = append(appended, record)
	}
	return appended, nil
}

// Query returns records in source/append order. The returned slice is a copy
// and can be used safely after later appends.
func (s *Store) Query() []Record {
	out := make([]Record, len(s.records))
	copy(out, s.records)
	return out
}

// QuerySource returns records for one source in that source's sequence.
func (s *Store) QuerySource(source string) []Record {
	records := s.sources[source]
	out := make([]Record, len(records))
	copy(out, records)
	return out
}

// BuildRangeProof produces a proof for one source and inclusive sequence range.
// No records from other sources or outside the requested range are included.
func (s *Store) BuildRangeProof(source string, startSeq, endSeq uint64) (*RangeProof, error) {
	return buildRangeProof(s.sources[source], source, startSeq, endSeq)
}

// Seal seals the complete log at its current length. The application must store
// the returned summary outside the audited file.
func (s *Store) Seal(source string) (*SealSummary, error) {
	records := s.sources[source]
	if len(records) == 0 {
		return nil, ErrNoRecord
	}
	recordHashes := make([][]byte, len(records))
	for i := range records {
		recordHashes[i] = records[i].RecordHash
	}
	summary := SealSummary{
		Version:     1,
		Source:      source,
		RecordCount: uint64(len(records)),
		LastHash:    append([]byte(nil), records[len(records)-1].RecordHash...),
		MerkleRoot:  merkleRoot(recordHashes),
	}
	return &summary, nil
}

func (s *Store) recoverTail() error {
	info, err := s.file.Stat()
	if err != nil {
		return err
	}
	validEnd, recoverable, err := scanRecoverableTail(s.file)
	if err != nil {
		return err
	}
	if !recoverable {
		return fmt.Errorf("audit log corruption before physical end at byte %d", validEnd)
	}
	if validEnd == info.Size() {
		return nil
	}
	return s.file.Truncate(validEnd)
}

func scanRecoverableTail(r io.ReaderAt) (int64, bool, error) {
	var offset int64
	headerBytes := make([]byte, frameHeaderLength)
	for {
		n, err := r.ReadAt(headerBytes, offset)
		if err != nil {
			if (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) && n < frameHeaderLength && n >= 0 {
				return offset, true, nil
			}
			return 0, false, err
		}
		var header frameHeader
		if err := binary.Read(bytes.NewReader(headerBytes), binary.BigEndian, &header); err != nil {
			return 0, false, err
		}
		if header.Magic != frameMagic {
			return offset, false, nil
		}

		frameSize := int64(frameHeaderLength) + int64(header.Length) + hashLength
		frame := make([]byte, frameSize)
		n, err = r.ReadAt(frame, offset)
		if err != nil {
			if (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) && int64(n) < frameSize {
				return offset, true, nil
			}
			return 0, false, err
		}
		payload := frame[frameHeaderLength : frameHeaderLength+int64(header.Length)]
		storedDigest := frame[frameHeaderLength+int64(header.Length):]
		if !bytes.Equal(sha256Hash(payload), storedDigest) {
			return offset, false, nil
		}
		offset += frameSize
	}
}

func (s *Store) load() error {
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	records, sources, err := readRecords(s.file)
	if err != nil {
		return err
	}
	s.records = records
	s.sources = sources
	_, err = s.file.Seek(0, io.SeekEnd)
	return err
}

func encodeFrame(seq uint64, previous []byte, event Event, recordHash []byte) ([]byte, error) {
	payload, err := json.Marshal(envelope{
		Version:    1,
		Seq:        seq,
		Previous:   previous,
		Event:      normalizeEvent(event),
		RecordHash: recordHash,
	})
	if err != nil {
		return nil, err
	}
	if len(payload) > 0xffffffff { // Practically impossible, but keeps the frame contract explicit.
		return nil, fmt.Errorf("audit frame too large: %d bytes", len(payload))
	}

	var header bytes.Buffer
	if err := binary.Write(&header, binary.BigEndian, frameHeader{Magic: frameMagic, Length: uint32(len(payload))}); err != nil {
		return nil, err
	}
	digest := sha256Hash(payload)
	frame := make([]byte, 0, frameHeaderLength+len(payload)+hashLength)
	frame = append(frame, header.Bytes()...)
	frame = append(frame, payload...)
	frame = append(frame, digest...)
	return frame, nil
}

func readRecords(r io.Reader) ([]Record, map[string][]Record, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}

	var records []Record
	grouped := make(map[string][]Record)
	offset := 0
	for offset < len(data) {
		if len(data[offset:]) < frameHeaderLength {
			return nil, nil, fmt.Errorf("truncated audit frame header at byte %d", offset)
		}
		var header frameHeader
		if err := binary.Read(bytes.NewReader(data[offset:offset+frameHeaderLength]), binary.BigEndian, &header); err != nil {
			return nil, nil, err
		}
		if header.Magic != frameMagic {
			return nil, nil, fmt.Errorf("invalid audit frame magic at byte %d", offset)
		}
		end := offset + frameHeaderLength + int(header.Length) + hashLength
		if end > len(data) {
			return nil, nil, fmt.Errorf("truncated audit frame at byte %d", offset)
		}
		payload := data[offset+frameHeaderLength : offset+frameHeaderLength+int(header.Length)]
		storedDigest := data[offset+frameHeaderLength+int(header.Length) : end]
		if !bytes.Equal(sha256Hash(payload), storedDigest) {
			return nil, nil, fmt.Errorf("corrupt audit frame checksum at byte %d", offset)
		}

		var env envelope
		if err := json.Unmarshal(payload, &env); err != nil {
			return nil, nil, fmt.Errorf("invalid audit frame payload at byte %d: %w", offset, err)
		}
		expectedHash := hashRecord(env.Seq, env.Previous, env.Event)
		event := normalizeEvent(env.Event)
		sourceRecords := grouped[event.Source]
		if env.Seq != uint64(len(sourceRecords)+1) {
			return nil, nil, fmt.Errorf("source %q expected record %d, found %d at byte %d", event.Source, len(sourceRecords)+1, env.Seq, offset)
		}
		var expectedPrevious []byte
		if len(sourceRecords) > 0 {
			expectedPrevious = sourceRecords[len(sourceRecords)-1].RecordHash
		}
		if !bytes.Equal(env.Previous, expectedPrevious) {
			return nil, nil, fmt.Errorf("source %q record %d has an invalid previous hash", event.Source, env.Seq)
		}
		if !bytes.Equal(env.RecordHash, expectedHash) {
			return nil, nil, fmt.Errorf("record %d hash mismatch", env.Seq)
		}

		record := Record{
			Seq:          env.Seq,
			PreviousHash: append([]byte(nil), env.Previous...),
			Event:        normalizeEvent(env.Event),
			RecordHash:   append([]byte(nil), env.RecordHash...),
		}
		records = append(records, record)
		grouped[event.Source] = append(grouped[event.Source], record)
		offset = end
	}
	return records, grouped, nil
}

func normalizeEvent(event Event) Event {
	event.OccurredAt = event.OccurredAt.UTC()
	return event
}
