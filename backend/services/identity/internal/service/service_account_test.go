package service

import (
	"testing"
	"time"

	"github.com/cyberradar/platform/services/identity/internal/model"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ownTenant   = uuid.MustParse("3f2504e0-4f89-11d3-9a0c-0305e82c3301")
	otherTenant = uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
)

func account(scope string) *model.ServiceAccount {
	return &model.ServiceAccount{TenantID: ownTenant, Scope: scope, Enabled: true}
}

func TestDecoyHashIsAValidBcryptHash(t *testing.T) {
	// If it is not, CompareHashAndPassword returns at once on a format error
	// and the timing equalisation it exists for does nothing — leaving the
	// endpoint able to tell an attacker which client_ids exist.
	if _, err := bcrypt.Cost(decoyHash); err != nil {
		t.Fatalf("decoyHash is not a bcrypt hash: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword(decoyHash, []byte("anything")); err != bcrypt.ErrMismatchedHashAndPassword {
		t.Errorf("comparing against decoyHash returned %v, want a plain mismatch", err)
	}
}

// ─── Tenant resolution ────────────────────────────────────────────────────────

func TestTenantScopedAccountGetsItsOwnTenant(t *testing.T) {
	got, err := resolveTenant(account(model.ScopeTenant), "")
	if err != nil {
		t.Fatalf("resolveTenant: %v", err)
	}
	if got != ownTenant {
		t.Errorf("tenant = %s, want %s", got, ownTenant)
	}
}

func TestTenantScopedAccountCannotActForAnotherTenant(t *testing.T) {
	// The isolation boundary for machines: an ingestion agent at one bank must
	// not be able to write events for another by naming its id.
	if _, err := resolveTenant(account(model.ScopeTenant), otherTenant.String()); err == nil {
		t.Error("a tenant-scoped account was given a token for another tenant")
	}
}

func TestTenantScopedAccountMayNameItsOwnTenant(t *testing.T) {
	got, err := resolveTenant(account(model.ScopeTenant), ownTenant.String())
	if err != nil {
		t.Fatalf("resolveTenant: %v", err)
	}
	if got != ownTenant {
		t.Errorf("tenant = %s, want %s", got, ownTenant)
	}
}

func TestPlatformAccountActsForTheTenantItNames(t *testing.T) {
	got, err := resolveTenant(account(model.ScopePlatform), otherTenant.String())
	if err != nil {
		t.Fatalf("resolveTenant: %v", err)
	}
	if got != otherTenant {
		t.Errorf("tenant = %s, want %s", got, otherTenant)
	}
}

func TestPlatformAccountMustNameATenant(t *testing.T) {
	// There is no "all tenants" token. A handler reading tenant_id off one
	// would have to invent a tenant, and that is how isolation is lost.
	if _, err := resolveTenant(account(model.ScopePlatform), ""); err == nil {
		t.Error("a platform account got a token naming no tenant")
	}
}

func TestPlatformAccountRejectsAMalformedTenant(t *testing.T) {
	if _, err := resolveTenant(account(model.ScopePlatform), "not-a-uuid"); err == nil {
		t.Error("a malformed tenant_id was accepted")
	}
}

// ─── Credential state ─────────────────────────────────────────────────────────

func TestUsableAcceptsALiveCredential(t *testing.T) {
	future := time.Now().Add(time.Hour)
	a := account(model.ScopeTenant)
	a.ExpiresAt = &future
	if reason := usable(a); reason != "" {
		t.Errorf("a live credential was refused: %s", reason)
	}
}

func TestUsableRefusesADisabledRevokedOrExpiredCredential(t *testing.T) {
	past := time.Now().Add(-time.Hour)

	disabled := account(model.ScopeTenant)
	disabled.Enabled = false

	revoked := account(model.ScopeTenant)
	revoked.RevokedAt = &past

	expired := account(model.ScopeTenant)
	expired.ExpiresAt = &past

	for name, a := range map[string]*model.ServiceAccount{
		"disabled": disabled, "revoked": revoked, "expired": expired,
	} {
		t.Run(name, func(t *testing.T) {
			if reason := usable(a); reason == "" {
				t.Error("credential accepted, want refusal")
			}
		})
	}
}

func TestACredentialWithNoExpiryIsStillUsable(t *testing.T) {
	// Rotation is an operational policy, enforced by setting expires_at at
	// creation; an account without one must not be refused outright.
	if reason := usable(account(model.ScopeTenant)); reason != "" {
		t.Errorf("refused: %s", reason)
	}
}
