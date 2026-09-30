package audit

import (
	"bytes"
	"crypto/sha256"
)

func merkleLeafHash(recordHash []byte) []byte {
	digest := sha256.New()
	digest.Write([]byte{0})
	digest.Write(recordHash)
	return digest.Sum(nil)
}

func merkleNodeHash(left, right []byte) []byte {
	digest := sha256.New()
	digest.Write([]byte{1})
	digest.Write(left)
	digest.Write(right)
	return digest.Sum(nil)
}

func merkleRoot(recordHashes [][]byte) []byte {
	if len(recordHashes) == 0 {
		return nil
	}
	layer := make([][]byte, len(recordHashes))
	for i, hash := range recordHashes {
		layer[i] = merkleLeafHash(append([]byte(nil), hash...))
	}
	for len(layer) > 1 {
		next := make([][]byte, 0, (len(layer)+1)/2)
		for i := 0; i < len(layer); i += 2 {
			left := layer[i]
			right := layer[i]
			if i+1 < len(layer) {
				right = layer[i+1]
			}
			next = append(next, merkleNodeHash(left, right))
		}
		layer = next
	}
	return layer[0]
}

func merkleProof(recordHashes [][]byte, index int) [][]byte {
	if index < 0 || index >= len(recordHashes) {
		return nil
	}
	layer := make([][]byte, len(recordHashes))
	for i, hash := range recordHashes {
		layer[i] = merkleLeafHash(append([]byte(nil), hash...))
	}
	var proof [][]byte
	for len(layer) > 1 {
		if index%2 == 0 {
			siblingIndex := index + 1
			if siblingIndex < len(layer) {
				proof = append(proof, append([]byte(nil), layer[siblingIndex]...))
			} else {
				proof = append(proof, append([]byte(nil), layer[index]...))
			}
		} else {
			proof = append(proof, append([]byte(nil), layer[index-1]...))
		}
		next := make([][]byte, 0, (len(layer)+1)/2)
		for i := 0; i < len(layer); i += 2 {
			left := layer[i]
			right := layer[i]
			if i+1 < len(layer) {
				right = layer[i+1]
			}
			next = append(next, merkleNodeHash(left, right))
		}
		index /= 2
		layer = next
	}
	return proof
}

func verifyMerkleProof(recordHash []byte, index int, proof [][]byte, root []byte) bool {
	hash := merkleLeafHash(recordHash)
	for _, sibling := range proof {
		if index%2 == 0 {
			hash = merkleNodeHash(hash, sibling)
		} else {
			hash = merkleNodeHash(sibling, hash)
		}
		index /= 2
	}
	return bytes.Equal(hash, root)
}
