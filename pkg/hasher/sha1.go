package hasher

import (
	"crypto/sha1"
	"encoding/hex"
)

type (
	Hasher interface {
		Hash(password string) string
		Compare(hash string, password string) bool
	}

	SHA1Hasher struct {
		salt string
	}
)

func NewSHA1Hasher(salt string) *SHA1Hasher {
	return &SHA1Hasher{
		salt: salt,
	}
}

func (h *SHA1Hasher) Hash(password string) string {
	hash := sha1.New()
	hash.Write([]byte(password))

	return hex.EncodeToString(hash.Sum([]byte(h.salt)))
}

func (h *SHA1Hasher) Compare(hash string, password string) bool {
	return h.Hash(password) == hash
}
