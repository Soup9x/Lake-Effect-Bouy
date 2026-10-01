package store

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Tenant struct {
	ID         uuid.UUID
	Name       string
	Slug       string
	ExternalID *string
	Source     *string
	Notes      *string
	ArchivedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type TenantSummary struct {
	Tenant
	AgentsTotal  int
	AgentsOnline int
	// OldestSignature is the oldest signature date across active agents.
	OldestSignature *time.Time
}

const tenantCols = `t.id, t.name, t.slug, t.external_id, t.source, t.notes, t.archived_at, t.created_at, t.updated_at`

func scanTenant(row interface{ Scan(...any) error }, t *Tenant, extra ...any) error {
	return row.Scan(append([]any{&t.ID, &t.Name, &t.Slug, &t.ExternalID, &t.Source, &t.Notes, &t.ArchivedAt, &t.CreatedAt, &t.UpdatedAt}, extra...)...)
}

var slugStrip = regexp.MustCompile(`[^a-z0-9]+`)

// Slugify turns a tenant name into a URL slug.
func Slugify(name string) string {
	s := strings.Trim(slugStrip.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(s) > 50 {
		s = strings.Trim(s[:50], "-")
	}
	if s == "" {
		s = "tenant"
	}
	return s
}

type TenantInput struct {
	Name       string
	ExternalID *string
	Source     *string
	Notes      *string
}

func CreateTenant(ctx context.Context, db DB, in TenantInput) (*Tenant, error) {
	base := Slugify(in.Name)
	slug := base
	// Pick a free slug; archived tenants keep theirs.
	for i := 2; ; i++ {
		var exists bool
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE slug=$1)`, slug).Scan(&exists); err != nil {
			return nil, err
		}
		if !exists {
			break
		}
		slug = base + "-" + strconv.Itoa(i)
	}
	t := &Tenant{}
	err := scanTenant(db.QueryRow(ctx, `INSERT INTO tenants AS t (id, name, slug, external_id, source, notes)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING `+tenantCols,
		NewID(), in.Name, slug, in.ExternalID, in.Source, in.Notes), t)
	if err != nil {
		return nil, mapErr(err)
	}
	return t, nil
}

func UpdateTenant(ctx context.Context, db DB, id uuid.UUID, in TenantInput) (*Tenant, error) {
	t := &Tenant{}
	err := scanTenant(db.QueryRow(ctx, `UPDATE tenants AS t SET name=$2, external_id=$3, source=$4, notes=$5, updated_at=now()
		WHERE id=$1 AND archived_at IS NULL RETURNING `+tenantCols,
		id, in.Name, in.ExternalID, in.Source, in.Notes), t)
	if err != nil {
		return nil, mapErr(err)
	}
	return t, nil
}

func GetTenant(ctx context.Context, db DB, id uuid.UUID) (*Tenant, error) {
	t := &Tenant{}
	err := scanTenant(db.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants t WHERE id=$1`, id), t)
	if err != nil {
		return nil, mapErr(err)
	}
	return t, nil
}

// ArchiveTenant archives the tenant and revokes its open enrollment tokens.
// Agents of an archived tenant are rejected with agent_revoked.
func ArchiveTenant(ctx context.Context, db DB, id uuid.UUID) error {
	tag, err := db.Exec(ctx, `UPDATE tenants SET archived_at=now(), updated_at=now() WHERE id=$1 AND archived_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	_, err = db.Exec(ctx, `UPDATE enrollment_tokens SET revoked_at=now() WHERE tenant_id=$1 AND revoked_at IS NULL`, id)
	return err
}

func ListTenants(ctx context.Context, db DB, offlineAfter time.Duration, includeArchived bool) ([]TenantSummary, error) {
	rows, err := db.Query(ctx, `SELECT `+tenantCols+`,
			count(a.id) FILTER (WHERE a.revoked_at IS NULL),
			count(a.id) FILTER (WHERE a.revoked_at IS NULL AND a.last_heartbeat_at > now() - $1::interval),
			min(a.signature_date) FILTER (WHERE a.revoked_at IS NULL)
		FROM tenants t LEFT JOIN agents a ON a.tenant_id = t.id
		WHERE $2 OR t.archived_at IS NULL
		GROUP BY t.id ORDER BY lower(t.name)`, offlineAfter, includeArchived)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantSummary
	for rows.Next() {
		var s TenantSummary
		if err := scanTenant(rows, &s.Tenant, &s.AgentsTotal, &s.AgentsOnline, &s.OldestSignature); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
