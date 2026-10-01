package server

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/store"
)

// Migrate applies all pending migrations using the given (owner) database URL.
func Migrate(ctx context.Context, url string) error {
	pool, err := store.Open(ctx, url)
	if err != nil {
		return fmt.Errorf("connect for migrations: %w", err)
	}
	defer pool.Close()
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer func() { _ = sqlDB.Close() }()
	return migrate(ctx, sqlDB)
}

func migrate(ctx context.Context, sqlDB *sql.DB) error {
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, mustSub())
	if err != nil {
		return err
	}
	_, err = p.Up(ctx)
	return err
}
