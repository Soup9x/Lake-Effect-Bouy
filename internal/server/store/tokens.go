package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type EnrollmentToken struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	Label        string
	TokenPrefix  string
	ExpiresAt    time.Time
	MaxUses      *int
	UseCount     int
	RevokedAt    *time.Time
	CreatedBy    uuid.UUID
	CreatedAt    time.Time
	CreatorEmail string
}

// Usable reports whether the token can still enroll an agent.
func (t EnrollmentToken) Usable(now time.Time) bool {
	return t.RevokedAt == nil && now.Before(t.ExpiresAt) && (t.MaxUses == nil || t.UseCount < *t.MaxUses)
}

const tokenCols = //nolint:gosec // column list, not a credential
`e.id, e.tenant_id, e.label, e.token_prefix, e.expires_at, e.max_uses, e.use_count, e.revoked_at, e.created_by, e.created_at`

func scanToken(row interface{ Scan(...any) error }, t *EnrollmentToken, extra ...any) error {
	return row.Scan(append([]any{&t.ID, &t.TenantID, &t.Label, &t.TokenPrefix, &t.ExpiresAt, &t.MaxUses, &t.UseCount, &t.RevokedAt, &t.CreatedBy, &t.CreatedAt}, extra...)...)
}

func CreateEnrollmentToken(ctx context.Context, db DB, tenantID uuid.UUID, label, prefix string, hash []byte, expires time.Time, maxUses *int, createdBy uuid.UUID) (*EnrollmentToken, error) {
	t := &EnrollmentToken{}
	err := scanToken(db.QueryRow(ctx, `INSERT INTO enrollment_tokens AS e (id, tenant_id, label, token_prefix, token_hash, expires_at, max_uses, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+tokenCols,
		NewID(), tenantID, label, prefix, hash, expires, maxUses, createdBy), t)
	if err != nil {
		return nil, mapErr(err)
	}
	return t, nil
}

func ListEnrollmentTokens(ctx context.Context, db DB, tenantID uuid.UUID) ([]EnrollmentToken, error) {
	rows, err := db.Query(ctx, `SELECT `+tokenCols+`, u.email FROM enrollment_tokens e JOIN users u ON u.id=e.created_by
		WHERE e.tenant_id=$1 ORDER BY e.created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrollmentToken
	for rows.Next() {
		var t EnrollmentToken
		if err := scanToken(rows, &t, &t.CreatorEmail); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func GetEnrollmentToken(ctx context.Context, db DB, id uuid.UUID) (*EnrollmentToken, error) {
	t := &EnrollmentToken{}
	err := scanToken(db.QueryRow(ctx, `SELECT `+tokenCols+` FROM enrollment_tokens e WHERE id=$1`, id), t)
	if err != nil {
		return nil, mapErr(err)
	}
	return t, nil
}

// LockEnrollmentTokenByHash finds a token by hash and locks its row for the
// rest of the transaction, so concurrent enrollments can't exceed max_uses.
func LockEnrollmentTokenByHash(ctx context.Context, db DB, hash []byte) (*EnrollmentToken, error) {
	t := &EnrollmentToken{}
	err := scanToken(db.QueryRow(ctx, `SELECT `+tokenCols+` FROM enrollment_tokens e WHERE token_hash=$1 FOR UPDATE`, hash), t)
	if err != nil {
		return nil, mapErr(err)
	}
	return t, nil
}

func RehashEnrollmentToken(ctx context.Context, db DB, id uuid.UUID, hash []byte) error {
	_, err := db.Exec(ctx, `UPDATE enrollment_tokens SET token_hash=$2 WHERE id=$1`, id, hash)
	return err
}

func IncrementTokenUse(ctx context.Context, db DB, id uuid.UUID) error {
	_, err := db.Exec(ctx, `UPDATE enrollment_tokens SET use_count = use_count + 1 WHERE id=$1`, id)
	return err
}

func RevokeEnrollmentToken(ctx context.Context, db DB, id uuid.UUID) error {
	tag, err := db.Exec(ctx, `UPDATE enrollment_tokens SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
