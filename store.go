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

// ErrNotFound: la sesión o el inicio de sesión no existe o ya venció.
var ErrNotFound = errors.New("auth: not found")

// Session es una sesión del producto: quién es y sus tokens, que nunca salen del servidor.
type Session struct {
	// ID es el valor de la cookie. Los almacenes guardan sólo su hash.
	ID           string
	Identity     Identity
	SID          string // la sesión del emisor, para el cierre por back-channel
	IDToken      string // id_token_hint al cerrar sesión
	AccessToken  string
	RefreshToken string
	AccessExpiry time.Time
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// Login es un inicio de sesión a medio hacer: lo que hace falta al volver del emisor.
type Login struct {
	Verifier  string // PKCE
	Nonce     string
	ReturnTo  string
	ExpiresAt time.Time
}

// Store guarda sesiones e inicios de sesión. Update debe excluir a otros Update de la misma sesión mientras corre
// fn (el refresh token sirve una sola vez y dos refrescos a la vez cerrarían la sesión) y darle a fn la sesión con
// su ID.
type Store interface {
	SaveLogin(ctx context.Context, state string, l Login) error
	// TakeLogin lo devuelve y lo borra: cada state sirve una vez.
	TakeLogin(ctx context.Context, state string) (Login, error)
	Create(ctx context.Context, s *Session) error
	Get(ctx context.Context, id string) (*Session, error)
	Update(ctx context.Context, id string, fn func(*Session) error) error
	Delete(ctx context.Context, id string) error
	DeleteBySID(ctx context.Context, sid string) error
	DeleteBySubject(ctx context.Context, sub string) error
}

// newID son 32 bytes al azar en base64url: el valor de una cookie o de un state.
func newID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashID es la clave con la que se guarda un ID: quien lea el almacén no puede usar las sesiones.
func HashID(id string) []byte {
	h := sha256.Sum256([]byte(id))
	return h[:]
}

// MemoryStore guarda en memoria. Sirve para pruebas y para un solo proceso: al reiniciar se pierden las sesiones.
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

// ponytail: un solo candado para todo el almacén; basta en pruebas y en un proceso pequeño.
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
