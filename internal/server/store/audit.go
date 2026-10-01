package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type AuditRow struct {
	ID         int64
	OccurredAt time.Time
	ActorType  string
	ActorID    *uuid.UUID
	ActorLabel string
	TenantID   *uuid.UUID
	TenantName *string
	Action     string
	TargetType string
	TargetID   string
	Outcome    string
	IP         *string
	Details    map[string]any
}

type AuditFilter struct {
	TenantID *uuid.UUID
	Action   string // prefix match, e.g. "tenant." or "auth.login_failed"
	Actor    string // substring of actor label
	Since    *time.Time
	Until    *time.Time
	BeforeID int64 // pagination cursor; 0 = newest
	Limit    int
}

func ListAudit(ctx context.Context, db DB, f AuditFilter) ([]AuditRow, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	rows, err := db.Query(ctx, `SELECT l.id, l.occurred_at, l.actor_type, l.actor_id, l.actor_label, l.tenant_id, t.name,
			l.action, l.target_type, l.target_id, l.outcome, host(l.ip), l.details
		FROM audit_log l LEFT JOIN tenants t ON t.id = l.tenant_id
		WHERE ($1::uuid IS NULL OR l.tenant_id = $1)
		  AND ($2 = '' OR l.action LIKE $2 || '%')
		  AND ($3 = '' OR l.actor_label ILIKE '%' || $3 || '%')
		  AND ($4::timestamptz IS NULL OR l.occurred_at >= $4)
		  AND ($5::timestamptz IS NULL OR l.occurred_at < $5)
		  AND ($6 = 0 OR l.id < $6)
		ORDER BY l.id DESC LIMIT $7`, f.TenantID, f.Action, f.Actor, f.Since, f.Until, f.BeforeID, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var r AuditRow
		if err := rows.Scan(&r.ID, &r.OccurredAt, &r.ActorType, &r.ActorID, &r.ActorLabel, &r.TenantID, &r.TenantName,
			&r.Action, &r.TargetType, &r.TargetID, &r.Outcome, &r.IP, &r.Details); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
