package service

import (
	"context"
	"fmt"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/tenant/internal/model"
	"github.com/cyberradar/platform/services/tenant/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// TenantService contains business logic for tenant management.
type TenantService struct {
	repo   *repository.TenantRepository
	logger zerolog.Logger
}

// NewTenantService creates a TenantService.
func NewTenantService(repo *repository.TenantRepository, logger zerolog.Logger) *TenantService {
	return &TenantService{repo: repo, logger: logger}
}

// Create validates and creates a new tenant.
func (s *TenantService) Create(ctx context.Context, req *model.CreateTenantRequest) (*model.Tenant, error) {
	// Check slug uniqueness
	exists, err := s.repo.SlugExists(ctx, req.Slug)
	if err != nil {
		return nil, apierrors.Internal("check slug", err)
	}
	if exists {
		return nil, apierrors.Conflict(fmt.Sprintf("slug '%s' is already taken", req.Slug))
	}

	// Validate parent exists if provided
	if req.ParentID != nil {
		if _, err := s.repo.GetByID(ctx, *req.ParentID); err != nil {
			return nil, apierrors.NotFound("parent tenant")
		}
	}

	tenant, err := s.repo.Create(ctx, req)
	if err != nil {
		return nil, apierrors.Internal("create tenant", err)
	}

	s.logger.Info().
		Str("tenant_id", tenant.ID.String()).
		Str("slug", tenant.Slug).
		Msg("tenant_created")

	return tenant, nil
}

// GetByID retrieves a tenant — callers supply the requester's tenantID
// to enforce that super admins can see all, but tenant admins only their own.
func (s *TenantService) GetByID(ctx context.Context, requesterTenantID, targetID uuid.UUID, isSuperAdmin bool) (*model.Tenant, error) {
	tenant, err := s.repo.GetByID(ctx, targetID)
	if err != nil {
		return nil, apierrors.NotFound("tenant")
	}

	// Non super-admin users can only view their own tenant or children.
	if !isSuperAdmin && tenant.ID != requesterTenantID {
		// Check if target is a child of requester tenant
		if tenant.ParentID == nil || *tenant.ParentID != requesterTenantID {
			return nil, apierrors.Forbidden("access to this tenant is not permitted")
		}
	}

	return tenant, nil
}

// List returns a paginated list of tenants.
// Super admins see all; others see only their subtree.
func (s *TenantService) List(ctx context.Context, requesterTenantID uuid.UUID, isSuperAdmin bool, f *model.ListTenantsFilter) (*model.TenantList, error) {
	if !isSuperAdmin {
		// Restrict to the requester's tenant subtree
		f.ParentID = &requesterTenantID
	}

	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Page <= 0 {
		f.Page = 1
	}

	tenants, total, err := s.repo.List(ctx, f)
	if err != nil {
		return nil, apierrors.Internal("list tenants", err)
	}

	return &model.TenantList{
		Tenants: tenants,
		Total:   total,
		Page:    f.Page,
		Limit:   f.Limit,
	}, nil
}

// Update applies partial updates to a tenant.
func (s *TenantService) Update(ctx context.Context, requesterTenantID, targetID uuid.UUID, isSuperAdmin bool, req *model.UpdateTenantRequest) (*model.Tenant, error) {
	// Authorization: super admin or same tenant
	if !isSuperAdmin && targetID != requesterTenantID {
		return nil, apierrors.Forbidden("cannot update another tenant")
	}

	tenant, err := s.repo.Update(ctx, targetID, req)
	if err != nil {
		return nil, apierrors.Internal("update tenant", err)
	}

	s.logger.Info().
		Str("tenant_id", targetID.String()).
		Str("updated_by_tenant", requesterTenantID.String()).
		Msg("tenant_updated")

	return tenant, nil
}

// Delete soft-deletes a tenant. Only super admins may delete tenants.
func (s *TenantService) Delete(ctx context.Context, requesterTenantID, targetID uuid.UUID, isSuperAdmin bool) error {
	if !isSuperAdmin {
		return apierrors.Forbidden("only super admins can delete tenants")
	}

	// Prevent deletion of the platform tenant
	platformID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	if targetID == platformID {
		return apierrors.Forbidden("the platform tenant cannot be deleted")
	}

	if err := s.repo.SoftDelete(ctx, targetID); err != nil {
		return apierrors.Internal("delete tenant", err)
	}

	s.logger.Warn().
		Str("tenant_id", targetID.String()).
		Str("deleted_by_tenant", requesterTenantID.String()).
		Msg("tenant_deleted")

	return nil
}
