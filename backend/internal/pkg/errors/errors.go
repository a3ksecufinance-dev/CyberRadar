package errors

import "fmt"

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
