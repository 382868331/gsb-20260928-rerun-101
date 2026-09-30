package audit

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type TamperKind string

const (
	TamperRewrite        TamperKind = "rewrite"
	TamperInsertion      TamperKind = "insertion"
	TamperMiddleDeletion TamperKind = "middle_deletion"
	TamperTailTruncation TamperKind = "tail_truncation"
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
