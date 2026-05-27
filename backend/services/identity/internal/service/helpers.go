package service

import (
	"fmt"

	"github.com/google/uuid"
)

// uuidFromString parses a UUID string. Wraps uuid.Parse.
func uuidFromString(s string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid UUID %q: %w", s, err)
	}
	return id, nil
}
