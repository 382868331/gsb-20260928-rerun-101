package audit

import (
	"crypto/sha256"
	"encoding/json"
)

func sha256Hash(data []byte) []byte {
	digest := sha256.Sum256(data)
	return digest[:]
}

func hashRecord(seq uint64, previous []byte, event Event) []byte {
	event = normalizeEvent(event)
	canonical := canonicalRecord{
		Version:  1,
		Seq:      seq,
		Previous: previous,
		Event: canonicalEvent{
			ID:         event.ID,
			Source:     event.Source,
			Type:       event.Type,
			OccurredAt: event.OccurredAt.Format(timeFormat),
			Payload:    event.Payload,
		},
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		panic(err)
	}
	return sha256Hash(data)
}
