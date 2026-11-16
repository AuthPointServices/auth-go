package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var ErrNotFound = errors.New("auth: not found")

type Session struct {
	// ID es el valor de la cookie; se guarda su hash.
	ID           string
	Identity     Identity
	SID          string
	IDToken      string
	AccessToken  string
	RefreshToken string
	AccessExpiry time.Time
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// Login es un inicio de sesión a medio hacer.
type Login struct {
	Verifier  string
	Nonce     string
	ReturnTo  string
	ExpiresAt time.Time
	// Retry marca el inicio que abre la vuelta de uno que este navegador ya no esperaba (ver stale).
	Retry bool `json:",omitempty"`
}

// Update debe excluir a otros Update de la misma sesión mientras corre fn, y darle la sesión con su ID.
type Store interface {
	SaveLogin(ctx context.Context, state string, l Login) error
	// TakeLogin lo borra: cada state sirve una vez.
	TakeLogin(ctx context.Context, state string) (Login, error)
	Create(ctx context.Context, s *Session) error
	Get(ctx context.Context, id string) (*Session, error)
	Update(ctx context.Context, id string, fn func(*Session) error) error
	Delete(ctx context.Context, id string) error
	DeleteBySID(ctx context.Context, sid string) error
	DeleteBySubject(ctx context.Context, sub string) error
}

func newID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func HashID(id string) []byte {
	h := sha256.Sum256([]byte(id))
	return h[:]
}

// MemoryStore es para pruebas o un solo proceso: al reiniciar se pierde todo.
type MemoryStore struct {
	mu       sync.Mutex
	sessions map[[32]byte]Session
	logins   map[[32]byte]Login
	now      func() time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{sessions: map[[32]byte]Session{}, logins: map[[32]byte]Login{}, now: time.Now}
}

func key(id string) [32]byte { return sha256.Sum256([]byte(id)) }

func (m *MemoryStore) SaveLogin(_ context.Context, state string, l Login) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logins[key(state)] = l
	return nil
}

func (m *MemoryStore) TakeLogin(_ context.Context, state string) (Login, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key(state)
	l, ok := m.logins[k]
	delete(m.logins, k)
	if !ok || !m.now().Before(l.ExpiresAt) {
		return Login{}, ErrNotFound
	}
	return l, nil
}

func (m *MemoryStore) Create(_ context.Context, s *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[key(s.ID)] = *s
	return nil
}

func (m *MemoryStore) Get(_ context.Context, id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[key(id)]
	if !ok || !m.now().Before(s.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &s, nil
}

// ponytail: un candado para todo el almacén.
func (m *MemoryStore) Update(_ context.Context, id string, fn func(*Session) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key(id)
	s, ok := m.sessions[k]
	if !ok || !m.now().Before(s.ExpiresAt) {
		return ErrNotFound
	}
	s.ID = id
	if err := fn(&s); err != nil {
		return err
	}
	m.sessions[k] = s
	return nil
}

func (m *MemoryStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, key(id))
	return nil
}

func (m *MemoryStore) DeleteBySID(_ context.Context, sid string) error {
	return m.deleteWhere(func(s Session) bool { return s.SID == sid })
}

func (m *MemoryStore) DeleteBySubject(_ context.Context, sub string) error {
	return m.deleteWhere(func(s Session) bool { return s.Identity.Subject == sub })
}

func (m *MemoryStore) deleteWhere(match func(Session) bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.sessions {
		if match(s) {
			delete(m.sessions, k)
		}
	}
	return nil
}
