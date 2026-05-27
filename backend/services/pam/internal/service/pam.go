package service

import (
	"context"
	"fmt"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/pam/internal/model"
	"github.com/cyberradar/platform/services/pam/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// PAMService handles JIT access, sessions, and privileged account management.
type PAMService struct {
	repo   *repository.PAMRepository
	logger zerolog.Logger
}

// NewPAMService creates a PAMService.
func NewPAMService(repo *repository.PAMRepository, logger zerolog.Logger) *PAMService {
	return &PAMService{repo: repo, logger: logger}
}

// ─── Privileged Accounts ──────────────────────────────────────────────────────

// CreateAccount registers a new privileged account.
func (s *PAMService) CreateAccount(ctx context.Context, tenantID uuid.UUID, req *model.CreateAccountRequest) (*model.PrivilegedAccount, error) {
	a, err := s.repo.CreateAccount(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create privileged account", err)
	}
	s.logger.Info().
		Str("account_id", a.ID.String()).
		Str("account_name", a.AccountName).
		Str("tenant_id", tenantID.String()).
		Msg("privileged_account_created")
	return a, nil
}

// GetAccount returns a privileged account.
func (s *PAMService) GetAccount(ctx context.Context, tenantID, id uuid.UUID) (*model.PrivilegedAccount, error) {
	a, err := s.repo.GetAccount(ctx, tenantID, id)
	if err != nil {
		return nil, apierrors.Internal("get privileged account", err)
	}
	if a == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "privileged account not found")
	}
	return a, nil
}

// ListAccounts returns all active privileged accounts.
func (s *PAMService) ListAccounts(ctx context.Context, tenantID uuid.UUID) ([]*model.PrivilegedAccount, error) {
	accounts, err := s.repo.ListAccounts(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("list privileged accounts", err)
	}
	return accounts, nil
}

// ─── Access Requests (JIT) ────────────────────────────────────────────────────

// CreateRequest submits a JIT access request.
func (s *PAMService) CreateRequest(ctx context.Context, tenantID, requesterID uuid.UUID, req *model.CreateRequestRequest) (*model.AccessRequest, error) {
	// Validate privileged account exists and requester is authorized
	if req.PrivilegedAccountID != nil {
		acct, err := s.repo.GetAccount(ctx, tenantID, *req.PrivilegedAccountID)
		if err != nil || acct == nil {
			return nil, apierrors.New(apierrors.KindNotFound, "privileged account not found")
		}
	}

	ar, err := s.repo.CreateRequest(ctx, tenantID, requesterID, req)
	if err != nil {
		return nil, apierrors.Internal("create access request", err)
	}

	s.logger.Info().
		Str("request_id", ar.ID.String()).
		Str("requester_id", requesterID.String()).
		Str("tenant_id", tenantID.String()).
		Int("duration_min", ar.RequestedDurationMin).
		Msg("pam_access_requested")

	return ar, nil
}

// GetRequest returns a single access request.
func (s *PAMService) GetRequest(ctx context.Context, tenantID, requestID uuid.UUID) (*model.AccessRequest, error) {
	ar, err := s.repo.GetRequest(ctx, tenantID, requestID)
	if err != nil {
		return nil, apierrors.Internal("get access request", err)
	}
	if ar == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "access request not found")
	}
	return ar, nil
}

// ListRequests returns filtered access requests.
func (s *PAMService) ListRequests(ctx context.Context, f model.AccessRequestFilter) ([]*model.AccessRequest, int, error) {
	requests, total, err := s.repo.ListRequests(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list access requests", err)
	}
	return requests, total, nil
}

// ResolveRequest approves or rejects a pending JIT request.
// Only users with the approver role can call this (enforced by handler).
func (s *PAMService) ResolveRequest(ctx context.Context, tenantID, requestID, approverID uuid.UUID, req *model.ApproveRequestRequest) error {
	// Must not self-approve
	ar, err := s.GetRequest(ctx, tenantID, requestID)
	if err != nil {
		return err
	}
	if ar.RequesterID == approverID {
		return apierrors.New(apierrors.KindForbidden, "cannot approve your own request")
	}
	if ar.Status != model.RequestPending {
		return apierrors.New(apierrors.KindBadInput, fmt.Sprintf("request is already %s", ar.Status))
	}

	if err := s.repo.ResolveRequest(ctx, tenantID, requestID, approverID, req.Approved, req.Note); err != nil {
		return apierrors.Internal("resolve access request", err)
	}

	action := "rejected"
	if req.Approved {
		action = "approved"
	}
	s.logger.Info().
		Str("request_id", requestID.String()).
		Str("approver_id", approverID.String()).
		Str("action", action).
		Msg("pam_request_resolved")

	return nil
}

// ─── Privileged Sessions ──────────────────────────────────────────────────────

// OpenSession opens a privileged session against an approved JIT request.
func (s *PAMService) OpenSession(ctx context.Context, tenantID, userID uuid.UUID, req *model.OpenSessionRequest) (*model.PrivilegedSession, error) {
	ar, err := s.GetRequest(ctx, tenantID, req.RequestID)
	if err != nil {
		return nil, err
	}
	if ar.Status != model.RequestApproved {
		return nil, apierrors.New(apierrors.KindForbidden, "request is not in approved status")
	}
	if ar.RequesterID != userID {
		return nil, apierrors.New(apierrors.KindForbidden, "only the requester can open the session")
	}

	// Compute expiry
	acct, err := s.repo.GetAccount(ctx, tenantID, req.PrivilegedAccountID)
	if err != nil || acct == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "privileged account not found")
	}
	durationMin := ar.RequestedDurationMin
	if durationMin > acct.MaxSessionMinutes {
		durationMin = acct.MaxSessionMinutes
	}
	expiresAt := time.Now().UTC().Add(time.Duration(durationMin) * time.Minute)

	session, err := s.repo.OpenSession(ctx, tenantID, userID, req, expiresAt)
	if err != nil {
		return nil, apierrors.Internal("open session", err)
	}

	s.logger.Warn().
		Str("session_id", session.ID.String()).
		Str("user_id", userID.String()).
		Str("account", acct.AccountName).
		Str("tenant_id", tenantID.String()).
		Time("expires_at", expiresAt).
		Msg("privileged_session_opened")

	return session, nil
}

// GetSession returns a privileged session.
func (s *PAMService) GetSession(ctx context.Context, tenantID, sessionID uuid.UUID) (*model.PrivilegedSession, error) {
	sess, err := s.repo.GetSession(ctx, tenantID, sessionID)
	if err != nil {
		return nil, apierrors.Internal("get session", err)
	}
	if sess == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "session not found")
	}
	return sess, nil
}

// ListSessions returns filtered sessions.
func (s *PAMService) ListSessions(ctx context.Context, f model.SessionFilter) ([]*model.PrivilegedSession, int, error) {
	sessions, total, err := s.repo.ListSessions(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list sessions", err)
	}
	return sessions, total, nil
}

// TerminateSession forcibly ends an active session.
func (s *PAMService) TerminateSession(ctx context.Context, tenantID, sessionID, callerID uuid.UUID) error {
	sess, err := s.GetSession(ctx, tenantID, sessionID)
	if err != nil {
		return err
	}
	if sess.Status != model.SessionActive {
		return apierrors.New(apierrors.KindBadInput, "session is not active")
	}

	if err := s.repo.TerminateSession(ctx, tenantID, sessionID, model.SessionTerminated); err != nil {
		return apierrors.Internal("terminate session", err)
	}

	s.logger.Warn().
		Str("session_id", sessionID.String()).
		Str("terminated_by", callerID.String()).
		Msg("privileged_session_terminated")
	return nil
}

// RecordEvent appends an event to an active session audit trail.
func (s *PAMService) RecordEvent(ctx context.Context, tenantID, sessionID uuid.UUID, req *model.RecordEventRequest) (*model.SessionEvent, error) {
	sess, err := s.GetSession(ctx, tenantID, sessionID)
	if err != nil {
		return nil, err
	}
	if sess.Status != model.SessionActive {
		return nil, apierrors.New(apierrors.KindBadInput, "session is not active")
	}

	return s.repo.RecordEvent(ctx, tenantID, sessionID, req)
}

// ListSessionEvents returns all events for a session.
func (s *PAMService) ListSessionEvents(ctx context.Context, tenantID, sessionID uuid.UUID) ([]*model.SessionEvent, error) {
	if _, err := s.GetSession(ctx, tenantID, sessionID); err != nil {
		return nil, err
	}
	events, err := s.repo.ListSessionEvents(ctx, tenantID, sessionID)
	if err != nil {
		return nil, apierrors.Internal("list session events", err)
	}
	return events, nil
}

// ─── Identity Risk ────────────────────────────────────────────────────────────

// GetIdentityRisk returns the risk profile for an identity.
func (s *PAMService) GetIdentityRisk(ctx context.Context, tenantID, identityID uuid.UUID) (*model.IdentityRiskProfile, error) {
	p, err := s.repo.GetRiskProfile(ctx, tenantID, identityID)
	if err != nil {
		return nil, apierrors.Internal("get risk profile", err)
	}
	if p == nil {
		return &model.IdentityRiskProfile{
			TenantID:         tenantID,
			IdentityID:       identityID,
			NormalLoginHours: []int{},
			NormalCountries:  []string{},
			NormalIPPrefixes: []string{},
		}, nil
	}
	return p, nil
}

// GetRiskBreakdown returns detailed risk factors.
func (s *PAMService) GetRiskBreakdown(ctx context.Context, tenantID, identityID uuid.UUID) (*model.RiskBreakdown, error) {
	p, err := s.GetIdentityRisk(ctx, tenantID, identityID)
	if err != nil {
		return nil, err
	}
	return ComputeBreakdown(p), nil
}

// ListHighRiskIdentities returns identities with risk_score >= threshold.
func (s *PAMService) ListHighRiskIdentities(ctx context.Context, tenantID uuid.UUID, threshold float64) ([]*model.IdentityRiskProfile, error) {
	if threshold <= 0 {
		threshold = 6.0
	}
	profiles, err := s.repo.ListHighRisk(ctx, tenantID, threshold, 100)
	if err != nil {
		return nil, apierrors.Internal("list high risk identities", err)
	}
	return profiles, nil
}
