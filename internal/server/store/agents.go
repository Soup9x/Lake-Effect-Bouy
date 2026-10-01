package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

type Agent struct {
	ID                      uuid.UUID
	TenantID                uuid.UUID
	EnrolledVia             *uuid.UUID
	CredentialHash          []byte
	CredentialPrevHash      []byte
	CredentialPrevExpiresAt *time.Time
	CredentialRotatedAt     *time.Time
	RotateRequestedAt       *time.Time
	MachineID               string
	Hostname                string
	OSFamily                string
	OSName                  string
	OSVersion               string
	Arch                    string
	AgentVersion            string
	EngineVersion           *string
	SignatureVersion        *int
	SignatureDate           *time.Time
	ClamdStatus             string
	ClamdError              *string
	LastHeartbeatAt         *time.Time
	LastIP                  *netip.Addr
	EnrolledAt              time.Time
	RevokedAt               *time.Time

	// Joined from tenants.
	TenantName       string
	TenantArchivedAt *time.Time
}

// Online reports whether the agent has heartbeated within offlineAfter.
func (a Agent) Online(now time.Time, offlineAfter time.Duration) bool {
	return a.RevokedAt == nil && a.LastHeartbeatAt != nil && now.Sub(*a.LastHeartbeatAt) < offlineAfter
}

const agentCols = `a.id, a.tenant_id, a.enrolled_via, a.credential_hash, a.credential_prev_hash, a.credential_prev_expires_at,
	a.credential_rotated_at, a.rotate_requested_at, a.machine_id, a.hostname, a.os_family, a.os_name, a.os_version, a.arch,
	a.agent_version, a.clamav_engine_version, a.signature_version, a.signature_date, a.clamd_status, a.clamd_error,
	a.last_heartbeat_at, a.last_ip, a.enrolled_at, a.revoked_at, t.name, t.archived_at`

func scanAgent(row interface{ Scan(...any) error }, a *Agent) error {
	return row.Scan(&a.ID, &a.TenantID, &a.EnrolledVia, &a.CredentialHash, &a.CredentialPrevHash, &a.CredentialPrevExpiresAt,
		&a.CredentialRotatedAt, &a.RotateRequestedAt, &a.MachineID, &a.Hostname, &a.OSFamily, &a.OSName, &a.OSVersion, &a.Arch,
		&a.AgentVersion, &a.EngineVersion, &a.SignatureVersion, &a.SignatureDate, &a.ClamdStatus, &a.ClamdError,
		&a.LastHeartbeatAt, &a.LastIP, &a.EnrolledAt, &a.RevokedAt, &a.TenantName, &a.TenantArchivedAt)
}

type NewAgent struct {
	TenantID       uuid.UUID
	EnrolledVia    uuid.UUID
	ID             uuid.UUID
	CredentialHash []byte
	MachineID      string
	Hostname       string
	OSFamily       string
	OSName         string
	OSVersion      string
	Arch           string
	AgentVersion   string
	IP             *netip.Addr
}

func CreateAgent(ctx context.Context, db DB, n NewAgent) error {
	_, err := db.Exec(ctx, `INSERT INTO agents (id, tenant_id, enrolled_via, credential_hash, machine_id, hostname, os_family, os_name, os_version, arch, agent_version, last_ip)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		n.ID, n.TenantID, n.EnrolledVia, n.CredentialHash, n.MachineID, n.Hostname, n.OSFamily, n.OSName, n.OSVersion, n.Arch, n.AgentVersion, n.IP)
	return mapErr(err)
}

func GetAgent(ctx context.Context, db DB, id uuid.UUID) (*Agent, error) {
	a := &Agent{}
	err := scanAgent(db.QueryRow(ctx, `SELECT `+agentCols+` FROM agents a JOIN tenants t ON t.id=a.tenant_id WHERE a.id=$1`, id), a)
	if err != nil {
		return nil, mapErr(err)
	}
	return a, nil
}

// ActiveAgentByMachine finds the non-revoked agent for a machine in a tenant.
func ActiveAgentByMachine(ctx context.Context, db DB, tenantID uuid.UUID, machineID string) (*Agent, error) {
	a := &Agent{}
	err := scanAgent(db.QueryRow(ctx, `SELECT `+agentCols+` FROM agents a JOIN tenants t ON t.id=a.tenant_id
		WHERE a.tenant_id=$1 AND a.machine_id=$2 AND a.revoked_at IS NULL`, tenantID, machineID), a)
	if err != nil {
		return nil, mapErr(err)
	}
	return a, nil
}

type AgentFilter struct {
	TenantID uuid.UUID
	Query    string // hostname substring
	Status   string // "", "online", "offline"
	Revoked  bool   // include revoked agents
}

func ListAgents(ctx context.Context, db DB, f AgentFilter, offlineAfter time.Duration) ([]Agent, error) {
	rows, err := db.Query(ctx, `SELECT `+agentCols+` FROM agents a JOIN tenants t ON t.id=a.tenant_id
		WHERE a.tenant_id=$1
		  AND ($2 = '' OR a.hostname ILIKE '%' || $2 || '%')
		  AND ($3 OR a.revoked_at IS NULL)
		  AND ($4 = '' OR ($4 = 'online') = (a.revoked_at IS NULL AND COALESCE(a.last_heartbeat_at > now() - $5::interval, false)))
		ORDER BY lower(a.hostname), a.enrolled_at`, f.TenantID, f.Query, f.Revoked, f.Status, offlineAfter)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		var a Agent
		if err := scanAgent(rows, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

type HeartbeatUpdate struct {
	Hostname         string
	OSName           string
	OSVersion        string
	AgentVersion     string
	ClamdStatus      string
	EngineVersion    *string
	SignatureVersion *int
	SignatureDate    *time.Time
	ClamdError       *string
	IP               *netip.Addr
}

func RecordHeartbeat(ctx context.Context, db DB, id uuid.UUID, h HeartbeatUpdate) error {
	_, err := db.Exec(ctx, `UPDATE agents SET hostname=$2, os_name=$3, os_version=$4, agent_version=$5, clamd_status=$6,
		clamav_engine_version=$7, signature_version=$8, signature_date=$9, clamd_error=$10, last_ip=$11,
		last_heartbeat_at=now(), updated_at=now() WHERE id=$1`,
		id, h.Hostname, h.OSName, h.OSVersion, h.AgentVersion, h.ClamdStatus, h.EngineVersion, h.SignatureVersion, h.SignatureDate, h.ClamdError, h.IP)
	return err
}

func RevokeAgent(ctx context.Context, db DB, id uuid.UUID) error {
	tag, err := db.Exec(ctx, `UPDATE agents SET revoked_at=now(), updated_at=now() WHERE id=$1 AND revoked_at IS NULL`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func RequestRotation(ctx context.Context, db DB, id uuid.UUID) error {
	tag, err := db.Exec(ctx, `UPDATE agents SET rotate_requested_at=now(), updated_at=now() WHERE id=$1 AND revoked_at IS NULL`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// RotateCredential installs a new credential hash. heldHash is the hash of the
// credential the agent authenticated with; it stays valid until prevExpires,
// and the rotation request stays set, until the agent first uses the new
// credential. If the agent never received or saved the new credential, its
// next heartbeat (still on heldHash) asks it to rotate again.
func RotateCredential(ctx context.Context, db DB, id uuid.UUID, newHash, heldHash []byte, prevExpires time.Time) error {
	_, err := db.Exec(ctx, `UPDATE agents SET credential_prev_hash=$3, credential_prev_expires_at=$4,
		credential_hash=$2, credential_rotated_at=now(), rotate_requested_at=COALESCE(rotate_requested_at, now()),
		updated_at=now() WHERE id=$1`, id, newHash, heldHash, prevExpires)
	return err
}

// ClearPreviousCredential drops the grace-period credential once the agent
// has authenticated with the new one, which completes the rotation. A
// rotation requested after the credential was issued stays pending. Returns
// the remaining rotation request, if any.
func ClearPreviousCredential(ctx context.Context, db DB, id uuid.UUID) (*time.Time, error) {
	var requested *time.Time
	err := db.QueryRow(ctx, `UPDATE agents SET credential_prev_hash=NULL, credential_prev_expires_at=NULL,
		rotate_requested_at = CASE WHEN rotate_requested_at <= credential_rotated_at THEN NULL ELSE rotate_requested_at END
		WHERE id=$1 RETURNING rotate_requested_at`, id).Scan(&requested)
	return requested, err
}

func RehashAgentCredential(ctx context.Context, db DB, id uuid.UUID, hash []byte) error {
	_, err := db.Exec(ctx, `UPDATE agents SET credential_hash=$2 WHERE id=$1`, id, hash)
	return err
}

// --- events ---

type AgentEvent struct {
	ID         int64
	Type       string
	Details    map[string]any
	OccurredAt time.Time
}

func AddAgentEvent(ctx context.Context, db DB, agentID, tenantID uuid.UUID, typ string, details map[string]any) error {
	if details == nil {
		details = map[string]any{}
	}
	b, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = db.Exec(ctx, `INSERT INTO agent_events (agent_id, tenant_id, type, details) VALUES ($1,$2,$3,$4)`, agentID, tenantID, typ, b)
	return err
}

func ListAgentEvents(ctx context.Context, db DB, agentID uuid.UUID, limit int) ([]AgentEvent, error) {
	rows, err := db.Query(ctx, `SELECT id, type, details, occurred_at FROM agent_events WHERE agent_id=$1 ORDER BY occurred_at DESC, id DESC LIMIT $2`, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentEvent
	for rows.Next() {
		var e AgentEvent
		if err := rows.Scan(&e.ID, &e.Type, &e.Details, &e.OccurredAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// SweepOnlineState flips recorded_online for agents whose computed state
// changed and records went_online / went_offline events. Returns the count.
func SweepOnlineState(ctx context.Context, db DB, offlineAfter time.Duration) (int, error) {
	var n int
	err := db.QueryRow(ctx, `WITH changed AS (
			UPDATE agents SET recorded_online = NOT recorded_online
			WHERE revoked_at IS NULL
			  AND recorded_online <> COALESCE(last_heartbeat_at > now() - $1::interval, false)
			RETURNING id, tenant_id, recorded_online, last_heartbeat_at
		), ev AS (
			INSERT INTO agent_events (agent_id, tenant_id, type, details)
			SELECT id, tenant_id, CASE WHEN recorded_online THEN 'went_online' ELSE 'went_offline' END,
			       jsonb_build_object('last_heartbeat_at', last_heartbeat_at)
			FROM changed RETURNING 1
		) SELECT count(*) FROM ev`, offlineAfter).Scan(&n)
	return n, err
}
