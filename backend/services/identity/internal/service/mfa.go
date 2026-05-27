package service

import (
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// MFAService handles TOTP-based MFA operations.
type MFAService struct {
	issuer string
}

// NewMFAService creates a MFAService.
func NewMFAService(issuer string) *MFAService {
	return &MFAService{issuer: issuer}
}

// GenerateSecret creates a new TOTP secret for a user.
// Returns the secret key and the provisioning URL for QR code generation.
func (s *MFAService) GenerateSecret(email string) (secret, url string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: email,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", "", fmt.Errorf("generate totp key: %w", err)
	}

	return key.Secret(), key.URL(), nil
}

// ValidateCode validates a TOTP code against a secret.
// Accepts codes from a 1-period window (±30 seconds) to allow clock drift.
func (s *MFAService) ValidateCode(secret, code string) bool {
	valid, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && valid
}
