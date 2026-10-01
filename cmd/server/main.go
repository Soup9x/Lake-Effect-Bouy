// Command clamav-console is the console server.
//
//	clamav-console serve                 run the server (applies migrations first if MIGRATE_DATABASE_URL is set)
//	clamav-console migrate               apply migrations and exit
//	clamav-console admin create-user     create an admin user (password from stdin)
//	clamav-console admin reset-password  set a user's password and unlock it (password from stdin)
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/term"

	"github.com/Soup9x/Lake-Effect-Bouy/internal/server"
	"github.com/Soup9x/Lake-Effect-Bouy/internal/server/audit"
	"github.com/Soup9x/Lake-Effect-Bouy/internal/server/auth"
	"github.com/Soup9x/Lake-Effect-Bouy/internal/server/config"
	"github.com/Soup9x/Lake-Effect-Bouy/internal/server/store"
)

var version = "dev"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(ctx, log)
	case "migrate":
		err = migrate(ctx)
	case "admin":
		err = admin(ctx, os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: clamav-console serve | migrate | admin create-user --email E [--name N] | admin reset-password --email E | version")
	os.Exit(2)
}

func serve(ctx context.Context, log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if !cfg.CookieSecure {
		log.Warn("INSECURE_COOKIES_FOR_DEV=true: session cookies are not marked Secure. Never use this in production.")
	}
	if cfg.MigrateDatabaseURL != "" {
		if err := server.Migrate(ctx, cfg.MigrateDatabaseURL); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	pool, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	go server.RunBackground(ctx, pool, cfg, log)
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           server.Handler(cfg, pool, log),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("server started", "addr", cfg.ListenAddr, "version", version, "public_url", cfg.PublicURL.String())
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func migrate(ctx context.Context) error {
	url := os.Getenv("MIGRATE_DATABASE_URL")
	if url == "" {
		return errors.New("MIGRATE_DATABASE_URL (owner role) is required")
	}
	return server.Migrate(ctx, url)
}

// readPassword reads a password without echo from a terminal, or one line
// from stdin when piped. Never from argv.
func readPassword(prompt string) (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func admin(ctx context.Context, args []string) error {
	if len(args) < 1 {
		usage()
	}
	fs := flag.NewFlagSet("admin "+args[0], flag.ExitOnError)
	email := fs.String("email", "", "user email")
	name := fs.String("name", "", "display name")
	_ = fs.Parse(args[1:])
	if *email == "" {
		return errors.New("--email is required")
	}
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return errors.New("DATABASE_URL is required")
	}
	pw, err := readPassword("Password: ")
	if err != nil {
		return err
	}
	if err := auth.ValidatePassword(pw, *email); err != nil {
		return err
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	pool, err := store.Open(ctx, url)
	if err != nil {
		return err
	}
	defer pool.Close()
	cli := audit.Actor{Type: audit.ActorSystem, Label: "cli"}

	switch args[0] {
	case "create-user":
		return store.InTx(ctx, pool, func(tx pgx.Tx) error {
			u, err := store.CreateUser(ctx, tx, *email, *name, hash)
			if errors.Is(err, store.ErrConflict) {
				return errors.New("a user with that email already exists")
			}
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "created user", u.Email)
			return audit.Write(ctx, tx, audit.Entry{Actor: cli, Action: audit.UserCreate, TargetType: "user", TargetID: u.ID.String(),
				Details: map[string]any{"email": u.Email, "via": "cli"}})
		})
	case "reset-password":
		return store.InTx(ctx, pool, func(tx pgx.Tx) error {
			u, err := store.GetUserByEmail(ctx, tx, *email)
			if err != nil {
				return fmt.Errorf("find user: %w", err)
			}
			if err := store.SetPassword(ctx, tx, u.ID, hash); err != nil {
				return err
			}
			if err := store.RevokeOtherSessions(ctx, tx, u.ID, store.NewID()); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "password reset for", u.Email)
			return audit.Write(ctx, tx, audit.Entry{Actor: cli, Action: audit.PasswordChange, TargetType: "user", TargetID: u.ID.String(),
				Details: map[string]any{"email": u.Email, "via": "cli_reset"}})
		})
	}
	usage()
	return nil
}
