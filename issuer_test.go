package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// fakeIssuer es un emisor OIDC de prueba: publica discovery y claves, y firma los tokens que se le pidan.
type fakeIssuer struct {
	*httptest.Server
	key jwk.Key

	mu sync.Mutex
	// token responde al endpoint de tokens; por defecto, un error.
	token func(form map[string]string) (int, any)
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.Import(raw)
	if err != nil {
		t.Fatal(err)
	}
	_ = key.Set(jwk.KeyIDKey, "test")
	_ = key.Set(jwk.AlgorithmKey, jwa.RS256())
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	set := jwk.NewSet()
	_ = set.AddKey(pub)

	f := &fakeIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"issuer":                 f.URL,
			"authorization_endpoint": f.URL + "/auth",
			"token_endpoint":         f.URL + "/token",
			"end_session_endpoint":   f.URL + "/logout",
			"jwks_uri":               f.URL + "/jwks",
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, set) })
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form := map[string]string{}
		for k := range r.PostForm {
			form[k] = r.PostForm.Get(k)
		}
		if id, secret, ok := r.BasicAuth(); ok {
			form["client_id"], form["client_secret"] = id, secret
		}
		f.mu.Lock()
		h := f.token
		f.mu.Unlock()
		if h == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		code, body := h(form)
		writeJSON(w, code, body)
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeIssuer) onToken(h func(form map[string]string) (int, any)) {
	f.mu.Lock()
	f.token = h
	f.mu.Unlock()
}

// sign firma claims con la clave del emisor; iss e iat van por defecto.
func (f *fakeIssuer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok := jwt.New()
	_ = tok.Set(jwt.IssuerKey, f.URL)
	_ = tok.Set(jwt.IssuedAtKey, time.Now())
	for k, v := range claims {
		if err := tok.Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	b, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), f.key))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
