package pgstore_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	auth "github.com/AuthPointServices/auth-go"
	"github.com/AuthPointServices/auth-go/pgstore"
	"github.com/AuthPointServices/auth-go/storetest"
)

// Corre contra un Postgres de verdad: TEST_DB_DSN=postgres://…; sin él, se salta.
func pool(t *testing.T) *pgxpool.Pool {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set")
	}
	db, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

func open(t *testing.T, key []byte) *pgstore.Store {
	db := pool(t)
	s, err := pgstore.New(db, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `TRUNCATE auth_sessions, auth_logins`); err != nil {
		t.Fatal(err)
	}
	return s
}

var key = bytes.Repeat([]byte{7}, 32)

func TestStore(t *testing.T) {
	storetest.Run(t, func(t *testing.T) auth.Store { return open(t, key) })
}

// Ni el ID ni los tokens quedan legibles en la base, y con otra clave no se abren.
func TestNothingReadableAtRest(t *testing.T) {
	s := open(t, key)
	now := time.Now()
	x := &auth.Session{ID: "the-cookie", Identity: auth.Identity{Subject: "u1"}, IDToken: "idtok", AccessToken: "secret-access",
		RefreshToken: "secret-refresh", AccessExpiry: now.Add(time.Minute), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := s.Create(t.Context(), x); err != nil {
		t.Fatal(err)
	}
	var dump string
	if err := pool(t).QueryRow(t.Context(), `SELECT string_agg(t::text, '') FROM auth_sessions t`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"the-cookie", "secret-access", "secret-refresh", "idtok"} {
		if bytes.Contains([]byte(dump), []byte(secret)) {
			t.Errorf("%q readable in the table", secret)
		}
	}
	other, _ := pgstore.New(pool(t), bytes.Repeat([]byte{8}, 32))
	if _, err := other.Get(t.Context(), "the-cookie"); err == nil {
		t.Fatal("opened with another key")
	}
}
