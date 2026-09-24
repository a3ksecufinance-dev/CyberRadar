package errors

import (
	"errors"
	"fmt"
)

// Sentinel errors for domain-layer use.
// Services return these; handlers map them to HTTP codes.

type Kind string

const (
	KindNotFound  Kind = "NOT_FOUND"
	KindConflict  Kind = "CONFLICT"
	KindForbidden Kind = "FORBIDDEN"
	KindBadInput  Kind = "BAD_INPUT"
	KindInternal  Kind = "INTERNAL"
	KindUnauth    Kind = "UNAUTHORIZED"
)

// DomainError is a typed error returned by service layer.
type DomainError struct {
	Kind    Kind
	Message string
	Err     error
}

func (e *DomainError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Kind, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Kind, e.Message)
}

func (e *DomainError) Unwrap() error { return e.Err }

// Message returns the error text meant for the caller: the domain message
// alone, without the [KIND] prefix Error() adds for logs and without any
// wrapped cause.
//
// Handlers must use this rather than Error(). Passing Error() to a response
// helper put the internal kind tag into API responses, and response.NotFound
// appends " not found" to what it is given, so a NotFound built by
// apierrors.NotFound came out as "[NOT_FOUND] thing not found not found".
func Message(err error) string {
	var de *DomainError
	if errors.As(err, &de) {
		return de.Message
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

// New creates a DomainError without a wrapped error.
func New(kind Kind, message string) *DomainError {
	return &DomainError{Kind: kind, Message: message}
}

// Wrap creates a DomainError wrapping an underlying error.
func Wrap(kind Kind, message string, err error) *DomainError {
	return &DomainError{Kind: kind, Message: message, Err: err}
}

// NotFound returns a KindNotFound error.
func NotFound(resource string) *DomainError {
	return New(KindNotFound, resource+" not found")
}

// Conflict returns a KindConflict error.
func Conflict(message string) *DomainError {
	return New(KindConflict, message)
}

// Forbidden returns a KindForbidden error.
func Forbidden(message string) *DomainError {
	return New(KindForbidden, message)
}

// BadInput returns a KindBadInput error.
func BadInput(message string) *DomainError {
	return New(KindBadInput, message)
}

// Internal returns a KindInternal error.
func Internal(message string, err error) *DomainError {
	return Wrap(KindInternal, message, err)
}

// IsKind checks whether an error is of the given Kind.
func IsKind(err error, kind Kind) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(*DomainError); ok {
		return e.Kind == kind
	}
	return false
}
