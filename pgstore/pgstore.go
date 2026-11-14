// Package pgstore guarda las sesiones en Postgres: por el hash de su ID y con los tokens cifrados (AES-256-GCM).
package pgstore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	auth "github.com/AuthPointServices/auth-go"
)

const Schema = `
CREATE TABLE IF NOT EXISTS auth_sessions (
	id_hash           bytea PRIMARY KEY,
	subject           text NOT NULL,
	sid               text NOT NULL DEFAULT '',
	identity          jsonb NOT NULL,
	tokens            bytea NOT NULL,
	access_expires_at timestamptz NOT NULL,
	created_at        timestamptz NOT NULL,
	expires_at        timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_sessions_sid ON auth_sessions (sid) WHERE sid <> '';
CREATE INDEX IF NOT EXISTS auth_sessions_subject ON auth_sessions (subject);
CREATE INDEX IF NOT EXISTS auth_sessions_expires ON auth_sessions (expires_at);

CREATE TABLE IF NOT EXISTS auth_logins (
	state_hash bytea PRIMARY KEY,
	data       bytea NOT NULL,
	expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_logins_expires ON auth_logins (expires_at);
`

type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

type Store struct {
	db   DB
	aead cipher.AEAD
}

var _ auth.Store = (*Store)(nil)

// key: 32 bytes, la misma en todas las instancias. Cambiarla cierra todas las sesiones.
func New(db DB, key []byte) (*Store, error) {
	if len(key) != 32 {
		return nil, errors.New("pgstore: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, aead: aead}, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.db.Exec(ctx, Schema)
	return err
}

func (s *Store) DeleteExpired(ctx context.Context) (int64, error) {
	a, err := s.db.Exec(ctx, `DELETE FROM auth_sessions WHERE expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	b, err := s.db.Exec(ctx, `DELETE FROM auth_logins WHERE expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return a.RowsAffected() + b.RowsAffected(), nil
}

// El aad es la clave de la fila: un cifrado copiado a otra no se abre.
func (s *Store) seal(v any, aad []byte) ([]byte, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, s.aead.NonceSize(), s.aead.NonceSize()+len(plain)+s.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plain, aad), nil
}

func (s *Store) open(box, aad []byte, v any) error {
	n := s.aead.NonceSize()
	if len(box) < n {
		return errors.New("pgstore: short ciphertext")
	}
	plain, err := s.aead.Open(nil, box[:n], box[n:], aad)
	if err != nil {
		return fmt.Errorf("pgstore: decrypt: %w", err)
	}
	return json.Unmarshal(plain, v)
}

type tokens struct {
	ID      string `json:"id"`
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

func (s *Store) SaveLogin(ctx context.Context, state string, l auth.Login) error {
	h := auth.HashID(state)
	box, err := s.seal(l, h)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `INSERT INTO auth_logins (state_hash, data, expires_at) VALUES ($1, $2, $3)`, h, box, l.ExpiresAt)
	return err
}

func (s *Store) TakeLogin(ctx context.Context, state string) (auth.Login, error) {
	h := auth.HashID(state)
	var box []byte
	err := s.db.QueryRow(ctx, `DELETE FROM auth_logins WHERE state_hash = $1 AND expires_at > now() RETURNING data`, h).Scan(&box)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.Login{}, auth.ErrNotFound
	}
	if err != nil {
		return auth.Login{}, err
	}
	var l auth.Login
	return l, s.open(box, h, &l)
}

func (s *Store) Create(ctx context.Context, x *auth.Session) error {
	h := auth.HashID(x.ID)
	box, err := s.seal(tokens{x.IDToken, x.AccessToken, x.RefreshToken}, h)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `INSERT INTO auth_sessions (id_hash, subject, sid, identity, tokens, access_expires_at, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		h, x.Identity.Subject, x.SID, x.Identity, box, x.AccessExpiry, x.CreatedAt, x.ExpiresAt)
	return err
}

const columns = `sid, identity, tokens, access_expires_at, created_at, expires_at`

func (s *Store) scan(row pgx.Row, id string) (*auth.Session, error) {
	x := &auth.Session{ID: id}
	var box []byte
	err := row.Scan(&x.SID, &x.Identity, &box, &x.AccessExpiry, &x.CreatedAt, &x.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, auth.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var t tokens
	if err := s.open(box, auth.HashID(id), &t); err != nil {
		return nil, err
	}
	x.IDToken, x.AccessToken, x.RefreshToken = t.ID, t.Access, t.Refresh
	return x, nil
}

func (s *Store) Get(ctx context.Context, id string) (*auth.Session, error) {
	return s.scan(s.db.QueryRow(ctx, `SELECT `+columns+` FROM auth_sessions WHERE id_hash = $1 AND expires_at > now()`, auth.HashID(id)), id)
}

func (s *Store) Update(ctx context.Context, id string, fn func(*auth.Session) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	h := auth.HashID(id)
	x, err := s.scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM auth_sessions WHERE id_hash = $1 AND expires_at > now() FOR UPDATE`, h), id)
	if err != nil {
		return err
	}
	if err := fn(x); err != nil {
		return err
	}
	box, err := s.seal(tokens{x.IDToken, x.AccessToken, x.RefreshToken}, h)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE auth_sessions SET tokens = $2, access_expires_at = $3, identity = $4 WHERE id_hash = $1`,
		h, box, x.AccessExpiry, x.Identity); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) Delete(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM auth_sessions WHERE id_hash = $1`, auth.HashID(id))
	return err
}

func (s *Store) DeleteBySID(ctx context.Context, sid string) error {
	if sid == "" {
		return nil
	}
	_, err := s.db.Exec(ctx, `DELETE FROM auth_sessions WHERE sid = $1`, sid)
	return err
}

func (s *Store) DeleteBySubject(ctx context.Context, sub string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM auth_sessions WHERE subject = $1`, sub)
	return err
}
