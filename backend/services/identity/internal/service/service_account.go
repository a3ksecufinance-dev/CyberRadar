package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	pkgjwt "github.com/cyberradar/platform/internal/pkg/jwt"
	"github.com/cyberradar/platform/services/identity/internal/model"
	"github.com/cyberradar/platform/services/identity/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

// serviceTokenTTL is deliberately shorter than a person's session: a machine
// re-authenticates for free, and a shorter life narrows what a leaked token is
// worth. It also bounds revocation, since permissions travel in the token.
const serviceTokenTTL = 15 * time.Minute

// decoyHash is a valid bcrypt hash of a value nobody holds. An unknown
// client_id is compared against it so that "no such account" and "wrong
// secret" take the same time; otherwise the endpoint answers which client_ids
// exist.
var decoyHash = []byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")

// ServiceAccountService issues tokens to machines and manages their
// credentials.
type ServiceAccountService struct {
	repo     *repository.ServiceAccountRepository
	roleRepo *repository.RoleRepository
	jwtSvc   *pkgjwt.Signer
	logger   zerolog.Logger
}

// NewServiceAccountService creates a ServiceAccountService.
func NewServiceAccountService(
	repo *repository.ServiceAccountRepository,
	roleRepo *repository.RoleRepository,
	jwtSvc *pkgjwt.Signer,
	logger zerolog.Logger,
) *ServiceAccountService {
	return &ServiceAccountService{repo: repo, roleRepo: roleRepo, jwtSvc: jwtSvc, logger: logger}
}

// IssueToken exchanges a client credential for a short-lived access token.
func (s *ServiceAccountService) IssueToken(ctx context.Context, req *model.ServiceTokenRequest) (*model.ServiceTokenResponse, error) {
	unauthorized := apierrors.New(apierrors.KindUnauth, "invalid client credentials")

	account, err := s.repo.GetByClientID(ctx, req.ClientID)
	if err != nil {
		// Spend the same time as a real comparison before answering.
		_ = bcrypt.CompareHashAndPassword(decoyHash, []byte(req.ClientSecret))
		return nil, unauthorized
	}

	if reason := usable(account); reason != "" {
		s.logger.Warn().
			Str("client_id", account.ClientID).
			Str("reason", reason).
			Msg("service_token_denied")
		return nil, unauthorized
	}

	if err := bcrypt.CompareHashAndPassword([]byte(account.SecretHash), []byte(req.ClientSecret)); err != nil {
		s.logger.Warn().Str("client_id", account.ClientID).Msg("service_token_bad_secret")
		return nil, unauthorized
	}

	tenantID, err := resolveTenant(account, req.TenantID)
	if err != nil {
		s.logger.Warn().Err(err).Str("client_id", account.ClientID).Msg("service_token_tenant_refused")
		return nil, apierrors.New(apierrors.KindUnauth, err.Error())
	}

	// Roles and permissions come from identity_roles, exactly as for a person,
	// so the RBAC catalogue governs machines too.
	roles, err := s.roleRepo.GetRoleNamesByUser(ctx, account.IdentityID)
	if err != nil {
		s.logger.Warn().Err(err).Str("client_id", account.ClientID).Msg("service_account_roles_load_failed")
	}
	perms, err := s.roleRepo.GetPermissionsByUser(ctx, account.IdentityID)
	if err != nil {
		s.logger.Warn().Err(err).Str("client_id", account.ClientID).Msg("service_account_permissions_load_failed")
	}
	if len(perms) == 0 {
		// A credential that authenticates but is authorized for nothing is a
		// provisioning mistake, and every call it makes will 403 with no clue
		// why. Say it once, here.
		s.logger.Error().Str("client_id", account.ClientID).
			Msg("service_account_has_no_permissions")
	}

	pair, err := s.jwtSvc.GenerateServiceToken(pkgjwt.Subject{
		TenantID:    tenantID.String(),
		UserID:      account.IdentityID.String(),
		Roles:       roles,
		Permissions: perms,
		ServiceID:   account.ClientID,
	}, serviceTokenTTL)
	if err != nil {
		return nil, apierrors.Internal("generate service token", err)
	}

	if err := s.repo.TouchLastUsed(ctx, account.ID); err != nil {
		s.logger.Warn().Err(err).Str("client_id", account.ClientID).Msg("service_account_touch_failed")
	}

	// Logged at info for every issue, because a service token is the one
	// credential with no person behind it to notice it was used. A platform
	// account acting for a tenant other than its own is worth seeing in
	// particular — that is the broad grant in action.
	s.logger.Info().
		Str("client_id", account.ClientID).
		Str("scope", account.Scope).
		Str("tenant_id", tenantID.String()).
		Bool("cross_tenant", account.Scope == model.ScopePlatform).
		Msg("service_token_issued")

	return &model.ServiceTokenResponse{
		AccessToken: pair.AccessToken,
		TokenType:   pair.TokenType,
		ExpiresAt:   pair.ExpiresAt,
		ServiceID:   account.ClientID,
		TenantID:    tenantID.String(),
	}, nil
}

// usable reports why an account may not have a token, or "" if it may.
func usable(a *model.ServiceAccount) string {
	switch {
	case !a.Enabled:
		return "disabled"
	case a.RevokedAt != nil:
		return "revoked"
	case a.ExpiresAt != nil && a.ExpiresAt.Before(time.Now()):
		return "credential expired"
	default:
		return ""
	}
}

// resolveTenant decides which tenant the token is for.
//
// Every token names exactly one tenant — there is no "all tenants" token,
// because a handler reading tenant_id would then have to invent one, and that
// is how isolation is lost.
func resolveTenant(a *model.ServiceAccount, requested string) (uuid.UUID, error) {
	switch a.Scope {
	case model.ScopePlatform:
		if requested == "" {
			return uuid.Nil, fmt.Errorf("platform-scoped account must name the tenant it is acting for")
		}
		tid, err := uuid.Parse(requested)
		if err != nil {
			return uuid.Nil, fmt.Errorf("tenant_id is not a uuid")
		}
		return tid, nil

	default: // ScopeTenant
		if requested != "" && !strings.EqualFold(requested, a.TenantID.String()) {
			return uuid.Nil, fmt.Errorf("account is not permitted to act for another tenant")
		}
		return a.TenantID, nil
	}
}

// Create provisions a machine principal and returns its secret once.
func (s *ServiceAccountService) Create(
	ctx context.Context,
	tenantID, createdBy uuid.UUID,
	req *model.CreateServiceAccountRequest,
) (*model.CreateServiceAccountResponse, error) {
	secret, err := newClientSecret()
	if err != nil {
		return nil, apierrors.Internal("generate client secret", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return nil, apierrors.Internal("hash client secret", err)
	}

	var expiresAt *time.Time
	if req.ExpiresInDays > 0 {
		t := time.Now().AddDate(0, 0, req.ExpiresInDays)
		expiresAt = &t
	}

	account, err := s.repo.Create(ctx, tenantID, createdBy, req, string(hash), expiresAt)
	if err != nil {
		return nil, apierrors.Internal("create service account", err)
	}

	s.logger.Info().
		Str("client_id", account.ClientID).
		Str("scope", account.Scope).
		Str("tenant_id", tenantID.String()).
		Str("created_by", createdBy.String()).
		Msg("service_account_created")

	return &model.CreateServiceAccountResponse{
		ServiceAccount: *account,
		ClientSecret:   secret,
	}, nil
}

// List returns a tenant's service accounts.
func (s *ServiceAccountService) List(ctx context.Context, tenantID uuid.UUID) ([]*model.ServiceAccount, error) {
	accounts, err := s.repo.List(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("list service accounts", err)
	}
	return accounts, nil
}

// Revoke disables a credential.
func (s *ServiceAccountService) Revoke(ctx context.Context, tenantID, id uuid.UUID) error {
	if err := s.repo.Revoke(ctx, tenantID, id); err != nil {
		return apierrors.New(apierrors.KindNotFound, "service account not found")
	}
	s.logger.Warn().
		Str("service_account_id", id.String()).
		Str("tenant_id", tenantID.String()).
		Msg("service_account_revoked")
	return nil
}

// newClientSecret returns 32 bytes of randomness, URL-safe.
func newClientSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
