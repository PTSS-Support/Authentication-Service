package services

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// EncryptionService handles password and PIN encryption
type EncryptionService interface {
	HashPassword(password string) (string, error)
	VerifyPassword(hashedPassword, password string) (bool, error)
	HashPIN(pin string) (string, error)
	VerifyPIN(hashedPIN, pin string) (bool, error)
}

type encryptionService struct {
	// Argon2 parameters
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func NewEncryptionService() EncryptionService {
	return &encryptionService{
		memory:      64 * 1024, // 64MB
		iterations:  3,
		parallelism: 2,
		saltLength:  16,
		keyLength:   32,
	}
}

func (s *encryptionService) HashPassword(password string) (string, error) {
	salt := make([]byte, s.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		s.iterations,
		s.memory,
		s.parallelism,
		s.keyLength,
	)

	// Format: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		s.memory,
		s.iterations,
		s.parallelism,
		b64Salt,
		b64Hash,
	)

	return encodedHash, nil
}

func (s *encryptionService) VerifyPassword(hashedPassword, password string) (bool, error) {
	// Parse the stored hash string
	params, salt, hash, err := s.decodeHash(hashedPassword)
	if err != nil {
		return false, err
	}

	// Compute hash of provided password
	otherHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.iterations,
		params.memory,
		params.parallelism,
		params.keyLength,
	)

	// Compare hashes in constant time
	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}

// HashPIN uses the same algorithm as password hashing
func (s *encryptionService) HashPIN(pin string) (string, error) {
	return s.HashPassword(pin)
}

// VerifyPIN uses the same verification as passwords
func (s *encryptionService) VerifyPIN(hashedPIN, pin string) (bool, error) {
	return s.VerifyPassword(hashedPIN, pin)
}

// Helper struct for hash parameters
type hashParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	keyLength   uint32
}

// decodeHash parses an encoded hash string and returns the parameters, salt, and hash
func (s *encryptionService) decodeHash(encodedHash string) (*hashParams, []byte, []byte, error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 5 {
		return nil, nil, nil, fmt.Errorf("invalid hash format")
	}

	var version int
	var memory, iterations uint32
	var parallelism uint8
	_, err := fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid version in hash: %w", err)
	}

	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d",
		&memory,
		&iterations,
		&parallelism,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid parameters in hash: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid salt in hash: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid hash in hash: %w", err)
	}

	params := &hashParams{
		memory:      memory,
		iterations:  iterations,
		parallelism: parallelism,
		keyLength:   uint32(len(hash)),
	}

	return params, salt, hash, nil
}
