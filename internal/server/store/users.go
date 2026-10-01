package store

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                uuid.UUID
	Email             string
	DisplayName       string
	PasswordHash      string
	Role              string
	DisabledAt        *time.Time
	FailedLoginCount  int
	LockedUntil       *time.Time
	PasswordChangedAt time.Time
	CreatedAt         time.Time
}

const userCols = `u.id, u.email, u.display_name, u.password_hash, u.role, u.disabled_at, u.failed_login_count, u.locked_until, u.password_changed_at, u.created_at`

func scanUser(row interface{ Scan(...any) error }, u *User, extra ...any) error {
	return row.Scan(append([]any{&u.ID, &u.Email, &u.DisplayName, &u.PasswordHash, &u.Role, &u.DisabledAt, &u.FailedLoginCount, &u.LockedUntil, &u.PasswordChangedAt, &u.CreatedAt}, extra...)...)
}

func CreateUser(ctx context.Context, db DB, email, displayName, passwordHash string) (*User, error) {
	u := &User{}
	err := scanUser(db.QueryRow(ctx, `INSERT INTO users AS u (id, email, display_name, password_hash) VALUES ($1,$2,$3,$4) RETURNING `+userCols,
		NewID(), email, displayName, passwordHash), u)
	if err != nil {
		return nil, mapErr(err)
	}
	return u, nil
}

func GetUserByEmail(ctx context.Context, db DB, email string) (*User, error) {
	u := &User{}
	err := scanUser(db.QueryRow(ctx, `SELECT `+userCols+` FROM users u WHERE lower(email)=lower($1)`, email), u)
	if err != nil {
		return nil, mapErr(err)
	}
	return u, nil
}

func GetUser(ctx context.Context, db DB, id uuid.UUID) (*User, error) {
	u := &User{}
	err := scanUser(db.QueryRow(ctx, `SELECT `+userCols+` FROM users u WHERE id=$1`, id), u)
	if err != nil {
		return nil, mapErr(err)
	}
	return u, nil
}

func ListUsers(ctx context.Context, db DB) ([]User, error) {
	rows, err := db.Query(ctx, `SELECT `+userCols+` FROM users u ORDER BY lower(email)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := scanUser(rows, &u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func CountActiveUsers(ctx context.Context, db DB) (int, error) {
	var n int
	err := db.QueryRow(ctx, `SELECT count(*) FROM users WHERE disabled_at IS NULL`).Scan(&n)
	return n, err
}

func DisableUser(ctx context.Context, db DB, id uuid.UUID) error {
	tag, err := db.Exec(ctx, `UPDATE users SET disabled_at=now(), updated_at=now() WHERE id=$1 AND disabled_at IS NULL`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	_, err = db.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, id)
	return err
}

func SetPassword(ctx context.Context, db DB, id uuid.UUID, hash string) error {
	_, err := db.Exec(ctx, `UPDATE users SET password_hash=$2, password_changed_at=now(), failed_login_count=0, locked_until=NULL, updated_at=now() WHERE id=$1`, id, hash)
	return err
}

// RecordLoginFailure increments the failure count and locks the account for
// lockFor once it reaches maxFailures. Returns true if the account is now locked.
func RecordLoginFailure(ctx context.Context, db DB, id uuid.UUID, maxFailures int, lockFor time.Duration) (bool, error) {
	var locked bool
	err := db.QueryRow(ctx, `UPDATE users SET
			failed_login_count = failed_login_count + 1,
			locked_until = CASE WHEN failed_login_count + 1 >= $2 THEN now() + $3::interval ELSE locked_until END
		WHERE id=$1 RETURNING locked_until IS NOT NULL AND locked_until > now()`, id, maxFailures, lockFor).Scan(&locked)
	return locked, err
}

func RecordLoginSuccess(ctx context.Context, db DB, id uuid.UUID) error {
	_, err := db.Exec(ctx, `UPDATE users SET failed_login_count=0, locked_until=NULL WHERE id=$1`, id)
	return err
}

func HasConfirmedMFA(ctx context.Context, db DB, userID uuid.UUID) (bool, error) {
	var ok bool
	err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_mfa_factors WHERE user_id=$1 AND confirmed_at IS NOT NULL)`, userID).Scan(&ok)
	return ok, err
}

// --- sessions ---

type Session struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	AuthLevel   int
	MFARequired bool
	CSRFToken   string
	CreatedAt   time.Time
	LastSeenAt  time.Time
	ExpiresAt   time.Time
	User        User
}

func CreateSession(ctx context.Context, db DB, tokenHash []byte, userID uuid.UUID, authLevel int, mfaRequired bool, csrf string, expires time.Time, ip *netip.Addr, ua string) (*Session, error) {
	s := &Session{}
	err := db.QueryRow(ctx, `INSERT INTO sessions (id, token_hash, user_id, auth_level, mfa_required, csrf_token, expires_at, ip, user_agent)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id, user_id, auth_level, mfa_required, csrf_token, created_at, last_seen_at, expires_at`,
		NewID(), tokenHash, userID, authLevel, mfaRequired, csrf, expires, ip, ua).
		Scan(&s.ID, &s.UserID, &s.AuthLevel, &s.MFARequired, &s.CSRFToken, &s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return s, nil
}

// GetActiveSession returns a session that is not revoked, not past its
// absolute expiry, and whose user is enabled. Idle timeout is checked by the caller.
func GetActiveSession(ctx context.Context, db DB, tokenHash []byte) (*Session, error) {
	s := &Session{}
	err := db.QueryRow(ctx, `SELECT s.id, s.user_id, s.auth_level, s.mfa_required, s.csrf_token, s.created_at, s.last_seen_at, s.expires_at, `+userCols+`
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at > now() AND u.disabled_at IS NULL`, tokenHash).
		Scan(append([]any{&s.ID, &s.UserID, &s.AuthLevel, &s.MFARequired, &s.CSRFToken, &s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt},
			&s.User.ID, &s.User.Email, &s.User.DisplayName, &s.User.PasswordHash, &s.User.Role, &s.User.DisabledAt, &s.User.FailedLoginCount, &s.User.LockedUntil, &s.User.PasswordChangedAt, &s.User.CreatedAt)...)
	if err != nil {
		return nil, mapErr(err)
	}
	return s, nil
}

func TouchSession(ctx context.Context, db DB, id uuid.UUID) error {
	_, err := db.Exec(ctx, `UPDATE sessions SET last_seen_at=now() WHERE id=$1`, id)
	return err
}

func RehashSession(ctx context.Context, db DB, id uuid.UUID, tokenHash []byte) error {
	_, err := db.Exec(ctx, `UPDATE sessions SET token_hash=$2 WHERE id=$1`, id, tokenHash)
	return err
}

func RevokeSession(ctx context.Context, db DB, id uuid.UUID) error {
	_, err := db.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, id)
	return err
}

// RevokeOtherSessions revokes all of a user's sessions except keep.
func RevokeOtherSessions(ctx context.Context, db DB, userID, keep uuid.UUID) error {
	_, err := db.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND id<>$2 AND revoked_at IS NULL`, userID, keep)
	return err
}

func DeleteStaleSessions(ctx context.Context, db DB, olderThan time.Duration) error {
	_, err := db.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now() - $1::interval OR revoked_at < now() - $1::interval`, olderThan)
	return err
}
