// Package httperr turns an error from anywhere below the handler into the HTTP
// answer it deserves.
//
// It exists because every service had grown its own `mapError`, and they did
// not agree. Some passed err.Error() to the client, leaking the internal
// "[KIND] " prefix and sometimes a wrapped driver message. Others sent 500 for
// everything the domain layer had not classified — which included every
// database constraint violation, so a caller who picked a value outside a CHECK
// list was told the server had failed rather than that the value was wrong.
package httperr

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rs/zerolog"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
)

// PostgreSQL SQLSTATEs worth distinguishing. The full list is in the manual
// under "Appendix A: Error Codes"; these are the ones a well-formed request
// can still hit, and each says something specific about the request rather
// than about the server.
const (
	sqlStateNotNullViolation     = "23502"
	sqlStateForeignKeyViolation  = "23503"
	sqlStateUniqueViolation      = "23505"
	sqlStateCheckViolation       = "23514"
	sqlStateExclusionViolation   = "23P01"
	sqlStateInvalidTextRepr      = "22P02"
	sqlStateStringDataTruncation = "22001"
	sqlStateNumericOutOfRange    = "22003"
)

// Write answers err with a status and a body the caller can act on.
//
// Order matters: a domain error carries the service's own judgement and wins
// over whatever the driver said underneath it.
func Write(w http.ResponseWriter, err error) {
	WriteLogged(w, err, zerolog.Nop())
}

// WriteLogged is Write, and logs the errors it turns into a 500 — the only
// class whose detail never reaches the caller, and so the only class that is
// invisible without a log line.
func WriteLogged(w http.ResponseWriter, err error, logger zerolog.Logger) {
	if err == nil {
		response.InternalError(w)
		return
	}

	if writeDomain(w, err) {
		return
	}
	if writeDatabase(w, err) {
		return
	}

	logger.Error().Err(err).Msg("unhandled_error")
	response.InternalError(w)
}

func writeDomain(w http.ResponseWriter, err error) bool {
	var de *apierrors.DomainError
	if !errors.As(err, &de) {
		return false
	}
	// apierrors.Message gives the domain text without the [KIND] prefix and
	// without the wrapped cause, which is what may be shown to a caller.
	msg := apierrors.Message(err)
	switch de.Kind {
	case apierrors.KindNotFound:
		response.NotFound(w, msg)
	case apierrors.KindConflict:
		response.Conflict(w, msg)
	case apierrors.KindForbidden:
		response.Forbidden(w, msg)
	case apierrors.KindUnauth:
		response.Unauthorized(w, msg)
	case apierrors.KindBadInput:
		response.BadRequest(w, "BAD_INPUT", msg)
	default:
		response.InternalError(w)
	}
	return true
}

func writeDatabase(w http.ResponseWriter, err error) bool {
	if errors.Is(err, pgx.ErrNoRows) {
		response.NotFound(w, "resource not found")
		return true
	}

	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return false
	}

	switch pg.Code {
	case sqlStateCheckViolation:
		// A CHECK is how the schema states an enumeration. Rejecting a value
		// outside it is the database validating the request, not failing.
		response.UnprocessableEntity(w, map[string]string{
			"field":      fieldFromConstraint(pg.ConstraintName, pg.TableName),
			"constraint": pg.ConstraintName,
			"reason":     "value is not accepted for this field",
		})
	case sqlStateNotNullViolation:
		response.UnprocessableEntity(w, map[string]string{
			"field":  pg.ColumnName,
			"reason": "field is required",
		})
	case sqlStateForeignKeyViolation:
		response.UnprocessableEntity(w, map[string]string{
			"field":      fieldFromConstraint(pg.ConstraintName, pg.TableName),
			"constraint": pg.ConstraintName,
			"reason":     "referenced record does not exist",
		})
	case sqlStateUniqueViolation, sqlStateExclusionViolation:
		response.Conflict(w, "a record with these values already exists")
	case sqlStateInvalidTextRepr:
		// A malformed UUID or an enum literal the type cannot parse.
		response.BadRequest(w, "INVALID_VALUE", "a value is not in the expected format")
	case sqlStateStringDataTruncation:
		response.UnprocessableEntity(w, map[string]string{
			"field":  pg.ColumnName,
			"reason": "value is too long",
		})
	case sqlStateNumericOutOfRange:
		response.UnprocessableEntity(w, map[string]string{
			"field":  pg.ColumnName,
			"reason": "value is out of range",
		})
	default:
		return false
	}
	return true
}

// fieldFromConstraint recovers the column a constraint is about.
//
// PostgreSQL names an inline constraint "<table>_<column>_check" (or _fkey),
// so trimming the table prefix and the kind suffix gives the column back. A
// constraint the schema named itself will not follow that shape; the caller
// still gets the constraint name in the response, which names the rule that
// rejected the value without revealing anything about the request that made it.
func fieldFromConstraint(constraint, table string) string {
	name := constraint
	if table != "" {
		name = strings.TrimPrefix(name, table+"_")
	}
	for _, suffix := range []string{"_check", "_fkey", "_key", "_excl"} {
		name = strings.TrimSuffix(name, suffix)
	}
	if name == "" || name == constraint {
		return ""
	}
	return name
}
