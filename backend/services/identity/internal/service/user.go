package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/identity/internal/model"
	"github.com/cyberradar/platform/services/identity/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

// UserService manages identity lifecycle.
type UserService struct {
	repo      *repository.UserRepository
	roleRepo  *repository.RoleRepository
	jwtSvc    *JWTService
	mfaSvc    *MFAService
	logger    zerolog.Logger
}

// NewUserService creates a UserService.
func NewUserService(
	repo *repository.UserRepository,
	roleRepo *repository.RoleRepository,
	jwtSvc *JWTService,
	mfaSvc *MFAService,
	logger zerolog.Logger,
) *UserService {
	return &UserService{
		repo:     repo,
		roleRepo: roleRepo,
		jwtSvc:   jwtSvc,
		mfaSvc:   mfaSvc,
		logger:   logger,
	}
}

// Login authenticates a user and returns a token pair.
// SECURITY: tenant_id comes from the database record, not from the request.
func (s *UserService) Login(ctx context.Context, tenantID uuid.UUID, req *model.LoginRequest) (*model.LoginResponse, error) {
	user, err := s.repo.GetByEmail(ctx, tenantID, req.Email)
	if err != nil {
		// Generic message — do not reveal whether email exists
		return nil, apierrors.New(apierrors.KindUnauth, "invalid credentials")
	}

	// Account locked?
	if user.Status == "disabled" {
		return nil, apierrors.New(apierrors.KindUnauth, "account is disabled")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		_ = s.repo.IncrementFailedLogin(ctx, user.ID)
		return nil, apierrors.New(apierrors.KindUnauth, "invalid credentials")
	}

	// MFA check
	if user.MFAEnabled {
		if req.MFACode == "" {
			// Signal to client that MFA is needed — do NOT issue a full token
			return &model.LoginResponse{MFARequired: true}, nil
		}
		if !s.mfaSvc.ValidateCode(user.MFASecret, req.MFACode) {
			return nil, apierrors.New(apierrors.KindUnauth, "invalid MFA code")
		}
	}

	// Reset failed login counter on success
	_ = s.repo.ResetFailedLogin(ctx, user.ID)
	_ = s.repo.UpdateLastActivity(ctx, user.ID)

	// Roles
	roles, err := s.roleRepo.GetRoleNamesByUser(ctx, user.ID)
	if err != nil {
		s.logger.Warn().Err(err).Str("user_id", user.ID.String()).Msg("failed to load roles")
	}

	isSuperAdmin := user.PrivilegeLevel == "super_admin"

	// Issue tokens
	pair, err := s.jwtSvc.GenerateTokenPair(
		user.TenantID.String(),
		user.ID.String(),
		user.Email,
		roles,
		isSuperAdmin,
	)
	if err != nil {
		return nil, apierrors.Internal("generate tokens", err)
	}

	// Persist refresh token hash
	tokenHash := hashToken(pair.RefreshToken)
	_ = s.repo.SaveRefreshToken(ctx, user.ID, user.TenantID, tokenHash, pair.ExpiresAt)

	user.Roles = roles

	return &model.LoginResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		ExpiresAt:    pair.ExpiresAt,
		TokenType:    "Bearer",
		User:         sanitize(user),
		MFARequired:  false,
	}, nil
}

// Refresh exchanges a valid refresh token for a new token pair.
func (s *UserService) Refresh(ctx context.Context, refreshToken string) (*model.LoginResponse, error) {
	userID, err := s.jwtSvc.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, apierrors.New(apierrors.KindUnauth, "invalid refresh token")
	}

	tokenHash := hashToken(refreshToken)
	valid, err := s.repo.IsRefreshTokenValid(ctx, tokenHash)
	if err != nil || !valid {
		return nil, apierrors.New(apierrors.KindUnauth, "refresh token revoked or expired")
	}

	uid, _ := uuid.Parse(userID)
	user, err := s.repo.GetByID(ctx, uid)
	if err != nil {
		return nil, apierrors.New(apierrors.KindUnauth, "user not found")
	}

	// Revoke old token
	_ = s.repo.RevokeRefreshToken(ctx, tokenHash)

	roles, _ := s.roleRepo.GetRoleNamesByUser(ctx, uid)
	isSuperAdmin := user.PrivilegeLevel == "super_admin"

	pair, err := s.jwtSvc.GenerateTokenPair(
		user.TenantID.String(),
		user.ID.String(),
		user.Email,
		roles,
		isSuperAdmin,
	)
	if err != nil {
		return nil, apierrors.Internal("generate tokens", err)
	}

	newHash := hashToken(pair.RefreshToken)
	_ = s.repo.SaveRefreshToken(ctx, user.ID, user.TenantID, newHash, pair.ExpiresAt)

	return &model.LoginResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		ExpiresAt:    pair.ExpiresAt,
		TokenType:    "Bearer",
		User:         sanitize(user),
	}, nil
}

// Create creates a new identity within the given tenant.
// TenantID is sourced from the JWT context, never from the request body.
func (s *UserService) Create(ctx context.Context, tenantID uuid.UUID, req *model.CreateUserRequest) (*model.Identity, error) {
	// Check email uniqueness within tenant
	existing, _ := s.repo.GetByEmail(ctx, tenantID, req.Email)
	if existing != nil {
		return nil, apierrors.Conflict(fmt.Sprintf("email '%s' is already registered in this tenant", req.Email))
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, apierrors.Internal("hash password", err)
	}

	user, err := s.repo.Create(ctx, tenantID, req, string(hash))
	if err != nil {
		return nil, apierrors.Internal("create user", err)
	}

	// Assign roles
	if len(req.RoleIDs) > 0 {
		_ = s.roleRepo.AssignRoles(ctx, user.ID, req.RoleIDs)
	}

	s.logger.Info().
		Str("tenant_id", tenantID.String()).
		Str("user_id", user.ID.String()).
		Str("email", user.Email).
		Msg("user_created")

	return sanitize(user), nil
}

// GetByID retrieves a user, enforcing tenant isolation.
func (s *UserService) GetByID(ctx context.Context, tenantID, userID uuid.UUID) (*model.Identity, error) {
	user, err := s.repo.GetByID(ctx, userID)
	if err != nil {
		return nil, apierrors.NotFound("user")
	}
	// Tenant isolation: user must belong to the requester's tenant
	if user.TenantID != tenantID {
		return nil, apierrors.Forbidden("access denied")
	}

	roles, _ := s.roleRepo.GetRoleNamesByUser(ctx, userID)
	user.Roles = roles

	return sanitize(user), nil
}

// List returns paginated users for a tenant.
func (s *UserService) List(ctx context.Context, f *model.ListUsersFilter) (*model.UserList, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Page <= 0 {
		f.Page = 1
	}

	users, total, err := s.repo.List(ctx, f)
	if err != nil {
		return nil, apierrors.Internal("list users", err)
	}

	return &model.UserList{Users: users, Total: total, Page: f.Page, Limit: f.Limit}, nil
}

// Update applies partial updates to a user.
func (s *UserService) Update(ctx context.Context, tenantID, userID uuid.UUID, req *model.UpdateUserRequest) (*model.Identity, error) {
	user, err := s.repo.GetByID(ctx, userID)
	if err != nil || user.TenantID != tenantID {
		return nil, apierrors.NotFound("user")
	}

	updated, err := s.repo.Update(ctx, userID, req)
	if err != nil {
		return nil, apierrors.Internal("update user", err)
	}

	if req.RoleIDs != nil {
		_ = s.roleRepo.SyncRoles(ctx, userID, req.RoleIDs)
	}

	return sanitize(updated), nil
}

// Disable soft-disables a user account.
func (s *UserService) Disable(ctx context.Context, tenantID, userID uuid.UUID) error {
	user, err := s.repo.GetByID(ctx, userID)
	if err != nil || user.TenantID != tenantID {
		return apierrors.NotFound("user")
	}
	return s.repo.SetStatus(ctx, userID, "disabled")
}

// EnrollMFA begins MFA enrolment, returning the TOTP secret and QR URL.
func (s *UserService) EnrollMFA(ctx context.Context, tenantID, userID uuid.UUID) (*model.MFAEnrollResponse, error) {
	user, err := s.repo.GetByID(ctx, userID)
	if err != nil || user.TenantID != tenantID {
		return nil, apierrors.NotFound("user")
	}

	secret, url, err := s.mfaSvc.GenerateSecret(user.Email)
	if err != nil {
		return nil, apierrors.Internal("generate MFA secret", err)
	}

	// Store secret (encrypted in prod — here we store plaintext for MVP dev)
	if err := s.repo.SetMFASecret(ctx, userID, secret); err != nil {
		return nil, apierrors.Internal("save MFA secret", err)
	}

	return &model.MFAEnrollResponse{Secret: secret, QRCodeURL: url}, nil
}

// VerifyMFAEnrolment confirms the MFA code and activates MFA.
func (s *UserService) VerifyMFAEnrolment(ctx context.Context, tenantID, userID uuid.UUID, code string) error {
	user, err := s.repo.GetByID(ctx, userID)
	if err != nil || user.TenantID != tenantID {
		return apierrors.NotFound("user")
	}

	if !s.mfaSvc.ValidateCode(user.MFASecret, code) {
		return apierrors.New(apierrors.KindUnauth, "invalid MFA code")
	}

	return s.repo.EnableMFA(ctx, userID)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// sanitize removes sensitive fields before returning to the API layer.
func sanitize(u *model.Identity) *model.Identity {
	u.PasswordHash = ""
	u.MFASecret = ""
	return u
}

// hashToken returns a SHA-256 hex hash of a token for safe database storage.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// Identity internal type with sensitive fields (not exported in model).
// We extend model.Identity here to add DB-only fields.
type _ = time.Time // ensure time is used
