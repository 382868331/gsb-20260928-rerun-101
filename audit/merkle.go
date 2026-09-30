package audit

import "bytes"

type MerkleProofStep struct {
	Hash []byte `json:"hash"`
	Left bool   `json:"left"`
}

func hashPair(left, right []byte) []byte {
	combined := make([]byte, 0, hashLength*2+1)
	combined = append(combined, 0x01)
	combined = append(combined, left...)
	combined = append(combined, right...)
	return sha256Hash(combined)
}

func merkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return bytes.Repeat([]byte{0}, hashLength)
	}
	level := leaves
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				duplicated := append([]byte(nil), level[i]...)
				next = append(next, hashPair(duplicated, duplicated))
				continue
			}
			next = append(next, hashPair(level[i], level[i+1]))
		}
		level = next
	}
	return append([]byte(nil), level[0]...)
}

func merkleProof(leaves [][]byte, index int) []MerkleProofStep {
	if index < 0 || index >= len(leaves) {
		return nil
	}
	level := leaves
	var proof []MerkleProofStep
	for len(level) > 1 {
		if index%2 == 0 {
			if index+1 < len(level) {
				proof = append(proof, MerkleProofStep{Hash: append([]byte(nil), level[index+1]...), Left: false})
			} else {
				proof = append(proof, MerkleProofStep{Hash: append([]byte(nil), level[index]...), Left: false})
			}
		} else {
			proof = append(proof, MerkleProofStep{Hash: append([]byte(nil), level[index-1]...), Left: true})
		}
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				duplicated := append([]byte(nil), level[i]...)
				next = append(next, hashPair(duplicated, duplicated))
				continue
			}
			next = append(next, hashPair(level[i], level[i+1]))
		}
		level = next
		index /= 2
	}
	return proof
}

func verifyMerkleProof(root, leaf []byte, index int, proof []MerkleProofStep) bool {
	current := append([]byte(nil), leaf...)
	for _, step := range proof {
		if len(step.Hash) != hashLength {
			return false
		}
		neighbor := append([]byte(nil), step.Hash...)
		if step.Left {
			current = hashPair(neighbor, current)
		} else {
			current = hashPair(current, neighbor)
		}
	}
	return bytes.Equal(current, root)
}
