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
	Seq        uint64 `json:"seq"`
	Event      Event  `json:"event"`
	RecordHash []byte `json:"record_hash"`
}

type frameHeader struct {
	Magic  uint32
	Length uint32
}

type envelope struct {
	Version    uint64 `json:"version"`
	Source     string `json:"source"`
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
	Source   string         `json:"source"`
	Seq      uint64         `json:"seq"`
	Previous []byte         `json:"previous_hash"`
	Event    canonicalEvent `json:"event"`
}

type sourceState struct {
	records []Record
	last    []byte
}

// Store is an append-only audit log. Its zero value is not usable; use Open.
type Store struct {
	path    string
	file    *os.File
	records []Record
	sources map[string]*sourceState
}

// Open opens an audit log and removes only an incomplete frame at the physical
// end of the file. Every complete, checksum-validated record before that frame
// remains available.
func Open(path string) (*Store, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}

	s := &Store{path: path, file: f, sources: make(map[string]*sourceState)}
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
		event = normalizeEvent(event)
		if event.Source == "" {
			return nil, errors.New("audit event source is required")
		}
		state := s.sources[event.Source]
		if state == nil {
			state = &sourceState{}
			s.sources[event.Source] = state
		}
		seq := uint64(len(state.records) + 1)
		recordHash := hashRecord(seq, state.last, event)
		frame, err := encodeFrame(seq, state.last, event, recordHash)
		if err != nil {
			return nil, err
		}
		if _, err := s.file.Write(frame); err != nil {
			return nil, err
		}
		if err := s.file.Sync(); err != nil {
			return nil, err
		}

		record := Record{Seq: seq, Event: event, RecordHash: recordHash}
		s.records = append(s.records, record)
		state.records = append(state.records, record)
		state.last = recordHash
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

// QuerySource returns one source's independently numbered chain. Events from
// other sources are not included and do not affect these sequence numbers.
func (s *Store) QuerySource(source string) []Record {
	state := s.sources[source]
	if state == nil {
		return nil
	}
	out := make([]Record, len(state.records))
	copy(out, state.records)
	return out
}

// Seal seals one source's complete segment at its current length. The
// application must store the returned summary outside the audited file.
func (s *Store) Seal(source string) (*SealSummary, error) {
	state := s.sources[source]
	if state == nil || len(state.records) == 0 {
		return nil, ErrNoRecord
	}
	leaves := make([][]byte, len(state.records))
	for i, record := range state.records {
		leaves[i] = append([]byte(nil), record.RecordHash...)
	}
	summary := SealSummary{
		Version:     2,
		SealedAt:    time.Now().UTC(),
		Source:      source,
		RecordCount: uint64(len(state.records)),
		LastHash:    append([]byte(nil), state.last...),
		MerkleRoot:  merkleRoot(leaves),
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
	records, _, err := readRecords(s.file)
	if err != nil {
		return err
	}
	s.records = records
	s.sources = make(map[string]*sourceState)
	for _, record := range records {
		state := s.sources[record.Event.Source]
		if state == nil {
			state = &sourceState{}
			s.sources[record.Event.Source] = state
		}
		state.records = append(state.records, record)
		state.last = record.RecordHash
	}
	_, err = s.file.Seek(0, io.SeekEnd)
	return err
}

func encodeFrame(seq uint64, previous []byte, event Event, recordHash []byte) ([]byte, error) {
	payload, err := json.Marshal(envelope{
		Version:    2,
		Source:     event.Source,
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

func scanValidPrefix(r io.ReaderAt) (int64, error) {
	var offset int64
	headerBytes := make([]byte, frameHeaderLength)
	for {
		if _, err := r.ReadAt(headerBytes, offset); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return offset, nil
			}
			return 0, err
		}
		var header frameHeader
		if err := binary.Read(bytes.NewReader(headerBytes), binary.BigEndian, &header); err != nil {
			return 0, err
		}
		if header.Magic != frameMagic {
			return offset, nil
		}

		frameEnd := offset + frameHeaderLength + int64(header.Length) + hashLength
		frame := make([]byte, frameHeaderLength+int64(header.Length)+hashLength)
		n, err := r.ReadAt(frame, offset)
		if err != nil && !(errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
			return 0, err
		}
		if int64(n) < frameEnd-offset {
			return offset, nil
		}
		payload := frame[frameHeaderLength : frameHeaderLength+int64(header.Length)]
		storedDigest := frame[frameHeaderLength+int64(header.Length) : frameEnd-offset]
		if !bytes.Equal(sha256Hash(payload), storedDigest) {
			return offset, nil
		}
		offset = frameEnd
	}
}

func readRecords(r io.Reader) ([]Record, []byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}

	var records []Record
	previousBySource := make(map[string][]byte)
	countBySource := make(map[string]uint64)
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
		if env.Version != 2 || env.Source == "" || env.Source != env.Event.Source {
			return nil, nil, fmt.Errorf("invalid audit record source metadata at byte %d", offset)
		}
		previous := previousBySource[env.Source]
		expectedSeq := countBySource[env.Source] + 1
		expectedHash := hashRecord(env.Seq, env.Previous, normalizeEvent(env.Event))
		if env.Seq != expectedSeq {
			return nil, nil, fmt.Errorf("source %q expected record %d, found %d at byte %d", env.Source, expectedSeq, env.Seq, offset)
		}
		if !bytes.Equal(env.Previous, previous) {
			return nil, nil, fmt.Errorf("record %d has an invalid previous hash", env.Seq)
		}
		if !bytes.Equal(env.RecordHash, expectedHash) {
			return nil, nil, fmt.Errorf("record %d hash mismatch", env.Seq)
		}

		records = append(records, Record{
			Seq:        env.Seq,
			Event:      normalizeEvent(env.Event),
			RecordHash: append([]byte(nil), env.RecordHash...),
		})
		previousBySource[env.Source] = expectedHash
		countBySource[env.Source]++
		offset = end
	}
	return records, nil, nil
}

func normalizeEvent(event Event) Event {
	event.OccurredAt = event.OccurredAt.UTC()
	return event
}
