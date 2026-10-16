package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/tenant/internal/model"
)

// ConnectorRepository reads and writes the connector registry.
type ConnectorRepository struct {
	db *pgxpool.Pool
}

func NewConnectorRepository(db *pgxpool.Pool) *ConnectorRepository {
	return &ConnectorRepository{db: db}
}

// The registry speaks the platform's own error vocabulary rather than its
// own: internal/pkg/httperr turns these into the status a caller can act on,
// and a package that invented its own would be answered 500 for both.
// A duplicate name is not among them: httperr reads the unique constraint's
// SQLSTATE directly and answers 409, so classifying it a second time here
// would be an opinion that can drift from the first.
func errNoSuchConnector() error { return apierrors.NotFound("connector") }

const connectorColumns = `
	id, tenant_id, name, source_type, format, config, enabled,
	silent_after_seconds, created_at, updated_at`

func scanConnector(row scannable) (*model.Connector, error) {
	var c model.Connector
	var silent int
	if err := row.Scan(&c.ID, &c.TenantID, &c.Name, &c.SourceType, &c.Format,
		&c.Config, &c.Enabled, &silent, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	c.SilentAfter = time.Duration(silent) * time.Second
	return &c, nil
}

// Create registers a connector.
func (r *ConnectorRepository) Create(ctx context.Context, tenantID uuid.UUID, req *model.CreateConnectorRequest) (*model.Connector, error) {
	config := req.Config
	if len(config) == 0 {
		config = []byte(`{}`)
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	silent := req.SilentAfter
	if silent == 0 {
		silent = int((time.Hour).Seconds())
	}

	const q = `
		INSERT INTO connectors (tenant_id, name, source_type, format, config, enabled, silent_after_seconds)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING ` + connectorColumns

	c, err := scanConnector(r.db.QueryRow(ctx, q,
		tenantID, req.Name, req.SourceType, req.Format, config, enabled, silent))
	if err != nil {
		// The driver error is returned as it is: httperr reads the SQLSTATE
		// and answers 409 for the unique constraint, so re-classifying it
		// here would be a second opinion that can disagree with the first.
		return nil, fmt.Errorf("register connector: %w", err)
	}
	return c, nil
}

// List returns a tenant's connectors, newest first.
func (r *ConnectorRepository) List(ctx context.Context, tenantID uuid.UUID) ([]*model.Connector, error) {
	const q = `SELECT ` + connectorColumns + `
		FROM connectors WHERE tenant_id = $1 ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list connectors: %w", err)
	}
	defer rows.Close()

	out := []*model.Connector{}
	for rows.Next() {
		c, err := scanConnector(rows)
		if err != nil {
			return nil, fmt.Errorf("scan connector: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Get returns one connector of this tenant.
//
// Scoped by tenant in the query rather than fetched and checked afterwards: a
// check that can be forgotten at one call site is not a boundary.
func (r *ConnectorRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (*model.Connector, error) {
	const q = `SELECT ` + connectorColumns + ` FROM connectors WHERE tenant_id = $1 AND id = $2`
	c, err := scanConnector(r.db.QueryRow(ctx, q, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNoSuchConnector()
	}
	if err != nil {
		return nil, fmt.Errorf("read connector: %w", err)
	}
	return c, nil
}

// Update changes the fields a caller named and leaves the rest alone.
//
// COALESCE rather than a built statement: a caller disabling a connector must
// not have to resend its configuration, which is how configuration gets
// silently reverted to whatever the caller happened to be holding.
func (r *ConnectorRepository) Update(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateConnectorRequest) (*model.Connector, error) {
	const q = `
		UPDATE connectors SET
			name                 = COALESCE($3, name),
			source_type          = COALESCE($4, source_type),
			format               = COALESCE($5, format),
			config               = COALESCE($6, config),
			enabled              = COALESCE($7, enabled),
			silent_after_seconds = COALESCE($8, silent_after_seconds),
			updated_at           = now()
		WHERE tenant_id = $1 AND id = $2
		RETURNING ` + connectorColumns

	var config any
	if req.Config != nil {
		config = []byte(*req.Config)
	}
	c, err := scanConnector(r.db.QueryRow(ctx, q,
		tenantID, id, req.Name, req.SourceType, req.Format, config, req.Enabled, req.SilentAfter))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNoSuchConnector()
	}
	if err != nil {
		return nil, fmt.Errorf("update connector: %w", err)
	}
	return c, nil
}

// Delete removes a connector from the registry.
//
// It does not touch the events it already produced: those are what happened,
// and deleting a registration cannot unmake them.
func (r *ConnectorRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM connectors WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("delete connector: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errNoSuchConnector()
	}
	return nil
}
