package service

import (
	"context"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/google/uuid"
)

// RevokeToken invalidates a refresh token (logout).
func (s *UserService) RevokeToken(ctx context.Context, refreshToken string) error {
	hash := hashToken(refreshToken)
	return s.repo.RevokeRefreshToken(ctx, hash)
}

// HasPermission checks if a user has the given resource:action permission.
func (s *UserService) HasPermission(ctx context.Context, userID uuid.UUID, resource, action string) (bool, error) {
	return s.roleRepo.HasPermission(ctx, userID, resource, action)
}

// GetAllPermissions returns all available platform permissions.
func (s *UserService) GetAllPermissions(ctx context.Context) ([]interface{}, error) {
	perms, err := s.roleRepo.GetAllPermissions(ctx)
	if err != nil {
		return nil, apierrors.Internal("get permissions", err)
	}
	result := make([]interface{}, len(perms))
	for i, p := range perms {
		result[i] = p
	}
	return result, nil
}

// parseUUID is a thin wrapper around uuid.Parse.
func parseUUID(s string) (uuid.UUID, error) {
	return uuidFromString(s)
}
