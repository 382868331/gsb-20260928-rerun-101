package audit

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

type TamperKind string

const (
	TamperRewrite            TamperKind = "rewrite"
	TamperInsertion          TamperKind = "insertion"
	TamperMiddleDeletion     TamperKind = "middle_deletion"
	TamperTailTruncation     TamperKind = "tail_truncation"
	TamperMissingRange       TamperKind = "missing_range"
	TamperWrongSource        TamperKind = "wrong_source"
	TamperSegmentReplacement TamperKind = "segment_replacement"
)

type TamperError struct {
	Kind       TamperKind
	RecordSeq  uint64
	ByteOffset int64
	Message    string
}

func (e *TamperError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s at record %d byte %d: %s", e.Kind, e.RecordSeq, e.ByteOffset, e.Message)
}

func readRecordsForVerification(r io.Reader) ([]Record, []byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}

	var records []Record
	previousBySource := make(map[string][]byte)
	countBySource := make(map[string]uint64)
	offset := 0
	for offset < len(data) {
		_, payload, storedDigest, next, err := readFrame(data, offset)
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(sha256Hash(payload), storedDigest) {
			return nil, nil, &TamperError{Kind: TamperRewrite, ByteOffset: int64(offset), Message: "frame checksum mismatch"}
		}

		var env envelope
		if err := json.Unmarshal(payload, &env); err != nil {
			return nil, nil, &TamperError{Kind: TamperRewrite, RecordSeq: 0, ByteOffset: int64(offset), Message: err.Error()}
		}
		if env.Version != 2 || env.Source == "" || env.Source != env.Event.Source {
			return nil, nil, &TamperError{Kind: TamperWrongSource, RecordSeq: env.Seq, ByteOffset: int64(offset), Message: "record source metadata mismatch"}
		}
		previous := previousBySource[env.Source]
		expectedSeq := countBySource[env.Source] + 1
		expectedHash := hashRecord(env.Seq, env.Previous, normalizeEvent(env.Event))
		switch {
		case env.Seq > expectedSeq:
			return nil, nil, &TamperError{Kind: TamperMiddleDeletion, RecordSeq: expectedSeq, ByteOffset: int64(offset), Message: "sequence number gap from a removed middle record"}
		case env.Seq < expectedSeq:
			return nil, nil, &TamperError{Kind: TamperInsertion, RecordSeq: env.Seq, ByteOffset: int64(offset), Message: "sequence number repeats after an inserted record"}
		case !bytes.Equal(env.Previous, previous):
			return nil, nil, &TamperError{Kind: TamperInsertion, RecordSeq: env.Seq, ByteOffset: int64(offset), Message: "record breaks the preceding hash link"}
		case !bytes.Equal(env.RecordHash, expectedHash):
			return nil, nil, &TamperError{Kind: TamperRewrite, RecordSeq: env.Seq, ByteOffset: int64(offset), Message: "record content hash mismatch"}
		}

		records = append(records, Record{Seq: env.Seq, Event: env.Event, RecordHash: append([]byte(nil), env.RecordHash...)})
		previousBySource[env.Source] = env.RecordHash
		countBySource[env.Source]++
		offset = next
	}
	return records, nil, nil
}

func readFrame(data []byte, offset int) (frameHeader, []byte, []byte, int, error) {
	if len(data[offset:]) < frameHeaderLength {
		return frameHeader{}, nil, nil, 0, &TamperError{Kind: TamperRewrite, ByteOffset: int64(offset), Message: "short frame header"}
	}
	var header frameHeader
	if err := binary.Read(bytes.NewReader(data[offset:offset+frameHeaderLength]), binary.BigEndian, &header); err != nil {
		return frameHeader{}, nil, nil, 0, err
	}
	if header.Magic != frameMagic {
		return frameHeader{}, nil, nil, 0, &TamperError{Kind: TamperRewrite, ByteOffset: int64(offset), Message: "invalid frame magic"}
	}
	end := offset + frameHeaderLength + int(header.Length) + hashLength
	if end > len(data) {
		return frameHeader{}, nil, nil, 0, &TamperError{Kind: TamperRewrite, ByteOffset: int64(offset), Message: "short frame body"}
	}
	payloadStart := offset + frameHeaderLength
	payloadEnd := payloadStart + int(header.Length)
	return header, data[payloadStart:payloadEnd], data[payloadEnd:end], end, nil
}
