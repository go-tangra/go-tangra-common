package audit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
)

// GenerateECDSAKeyPair generates a new ECDSA key pair using P-256 curve
func GenerateECDSAKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ECDSA key failed: %w", err)
	}
	return privateKey, &privateKey.PublicKey, nil
}

// HashLog computes SHA-256 hash of the audit log (excluding hash and signature fields)
func HashLog(log *AuditLog) string {
	if log == nil {
		return ""
	}

	// Create a copy without hash and signature
	logCopy := *log
	logCopy.LogHash = ""
	logCopy.Signature = nil

	// Serialize to JSON for deterministic hashing
	rawBytes, err := json.Marshal(logCopy)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(rawBytes)
	return hex.EncodeToString(hash[:])
}

// SignLog generates an ECDSA signature for the audit log
func SignLog(log *AuditLog, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if log == nil || privateKey == nil {
		return nil, fmt.Errorf("log or private key is nil")
	}

	// Create sign content with critical fields
	sc := SignContent{
		TenantID:  log.TenantID,
		ClientID:  log.ClientID,
		Operation: log.Operation,
		Timestamp: log.Timestamp.UnixNano(),
		LogHash:   log.LogHash,
	}

	// Serialize sign content to JSON
	scBytes, err := json.Marshal(sc)
	if err != nil {
		return nil, fmt.Errorf("marshal sign content failed: %w", err)
	}

	// Hash the sign content
	scHash := sha256.Sum256(scBytes)

	// Sign with ECDSA
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, scHash[:])
	if err != nil {
		return nil, fmt.Errorf("ECDSA sign failed: %w", err)
	}

	// Encode to DER format
	return EncodeDER(r, s)
}

// VerifySignature verifies the ECDSA signature of an audit log
func VerifySignature(log *AuditLog, publicKey *ecdsa.PublicKey) (bool, error) {
	if log == nil || publicKey == nil || log.Signature == nil {
		return false, fmt.Errorf("log, public key, or signature is nil")
	}

	// Recreate the sign content
	sc := SignContent{
		TenantID:  log.TenantID,
		ClientID:  log.ClientID,
		Operation: log.Operation,
		Timestamp: log.Timestamp.UnixNano(),
		LogHash:   log.LogHash,
	}

	// Serialize and hash
	scBytes, err := json.Marshal(sc)
	if err != nil {
		return false, fmt.Errorf("marshal sign content failed: %w", err)
	}

	scHash := sha256.Sum256(scBytes)

	// Decode DER signature
	r, s, err := DecodeDER(log.Signature)
	if err != nil {
		return false, fmt.Errorf("decode DER failed: %w", err)
	}

	// Verify signature
	return ecdsa.Verify(publicKey, scHash[:], r, s), nil
}

// EncodeDER encodes ECDSA r, s values to DER format
func EncodeDER(r, s *big.Int) ([]byte, error) {
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Ensure positive integers (add 0x00 prefix if high bit is set)
	if len(rBytes) > 0 && rBytes[0]&0x80 != 0 {
		rBytes = append([]byte{0x00}, rBytes...)
	}
	if len(sBytes) > 0 && sBytes[0]&0x80 != 0 {
		sBytes = append([]byte{0x00}, sBytes...)
	}

	// Build DER structure
	der := make([]byte, 0, 6+len(rBytes)+len(sBytes))
	der = append(der, 0x30)                              // SEQUENCE tag
	der = append(der, byte(2+len(rBytes)+2+len(sBytes))) // total length
	der = append(der, 0x02)                              // INTEGER tag (r)
	der = append(der, byte(len(rBytes)))
	der = append(der, rBytes...)
	der = append(der, 0x02) // INTEGER tag (s)
	der = append(der, byte(len(sBytes)))
	der = append(der, sBytes...)

	return der, nil
}

// DecodeDER decodes DER format to ECDSA r, s values
func DecodeDER(der []byte) (*big.Int, *big.Int, error) {
	if len(der) < 8 {
		return nil, nil, fmt.Errorf("DER too short")
	}

	// Check SEQUENCE tag
	if der[0] != 0x30 {
		return nil, nil, fmt.Errorf("expected SEQUENCE tag")
	}

	// Parse total length
	totalLen := int(der[1])
	if len(der) < 2+totalLen {
		return nil, nil, fmt.Errorf("DER length mismatch")
	}

	// Parse r
	if der[2] != 0x02 {
		return nil, nil, fmt.Errorf("expected INTEGER tag for r")
	}
	rLen := int(der[3])
	if len(der) < 4+rLen {
		return nil, nil, fmt.Errorf("r length mismatch")
	}
	r := new(big.Int).SetBytes(der[4 : 4+rLen])

	// Parse s
	sOffset := 4 + rLen
	if len(der) < sOffset+2 {
		return nil, nil, fmt.Errorf("DER too short for s")
	}
	if der[sOffset] != 0x02 {
		return nil, nil, fmt.Errorf("expected INTEGER tag for s")
	}
	sLen := int(der[sOffset+1])
	if len(der) < sOffset+2+sLen {
		return nil, nil, fmt.Errorf("s length mismatch")
	}
	s := new(big.Int).SetBytes(der[sOffset+2 : sOffset+2+sLen])

	return r, s, nil
}

// HashString computes SHA-256 hash of a string
func HashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
