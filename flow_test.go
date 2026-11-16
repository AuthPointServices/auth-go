package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// app es un producto de prueba con auth montado contra el emisor falso.
type app struct {
	*Auth
	f       *fakeIssuer
	handler http.Handler
	store   *MemoryStore
}

func newApp(t *testing.T) *app {
	t.Helper()
	f := newFakeIssuer(t)
	store := NewMemoryStore()
	a, err := New(t.Context(), Config{Issuer: f.URL, ClientID: "accounts", ClientSecret: "s3cret", BaseURL: "http://app.test", Store: store})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/auth/", a.Routes())
	mux.Handle("/api/me", a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := FromContext(r.Context())
		_, _ = w.Write([]byte(s.Identity.Email + " " + s.AccessToken))
	})))
	return &app{Auth: a, f: f, handler: mux, store: store}
}

func (x *app) do(r *http.Request) *http.Response {
	w := httptest.NewRecorder()
	x.handler.ServeHTTP(w, r)
	return w.Result()
}

func cookie(res *http.Response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// login hace el ida y vuelta completo y devuelve la cookie de sesión.
func (x *app) login(t *testing.T, returnTo string) *http.Cookie {
	t.Helper()
	return x.loginWith(t, returnTo, "", returnTo)
}

// loginWith vuelve del emisor con `extra` en la query y espera acabar en `want`.
func (x *app) loginWith(t *testing.T, returnTo, extra, want string) *http.Cookie {
	t.Helper()
	res := x.do(httptest.NewRequest(http.MethodGet, "/auth/login?return_to="+url.QueryEscape(returnTo), nil))
	if res.StatusCode != http.StatusFound {
		t.Fatalf("login: %d", res.StatusCode)
	}
	to, _ := url.Parse(res.Header.Get("Location"))
	q := to.Query()
	if !strings.HasPrefix(to.String(), x.f.URL+"/auth?") || q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "accounts" ||
		q.Get("redirect_uri") != "http://app.test/auth/callback" || q.Get("scope") != "openid profile email" {
		t.Fatalf("authorize url = %s", to)
	}
	state, challenge, nonce := q.Get("state"), q.Get("code_challenge"), q.Get("nonce")

	x.f.onToken(func(form map[string]string) (int, any) {
		sum := sha256.Sum256([]byte(form["code_verifier"]))
		if form["grant_type"] != "authorization_code" || form["code"] != "c1" || form["client_secret"] != "s3cret" ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			return http.StatusBadRequest, map[string]string{"error": "invalid_grant"}
		}
		return http.StatusOK, map[string]any{
			"access_token": "at1", "refresh_token": "rt1", "token_type": "Bearer", "expires_in": 300,
			"id_token": x.f.sign(t, map[string]any{"sub": "u1", "aud": "accounts", "exp": time.Now().Add(time.Minute),
				"nonce": nonce, "sid": "s1", "email": "ana@example.test", "email_verified": true}),
		}
	})
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=c1&state="+state+extra, nil)
	req.AddCookie(cookie(res, "login"))
	back := x.do(req)
	if back.StatusCode != http.StatusSeeOther || back.Header.Get("Location") != want {
		t.Fatalf("callback: %d → %s", back.StatusCode, back.Header.Get("Location"))
	}
	c := cookie(back, "session")
	if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie = %+v", c)
	}
	return c
}

func (x *app) get(path string, c *http.Cookie) *http.Response {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if c != nil {
		req.AddCookie(c)
	}
	return x.do(req)
}

func body(res *http.Response) string {
	b, _ := io.ReadAll(res.Body)
	return string(b)
}

func TestLoginFlow(t *testing.T) {
	x := newApp(t)
	c := x.login(t, "/files?view=list")

	var s struct {
		Authenticated bool     `json:"authenticated"`
		User          Identity `json:"user"`
	}
	if err := json.NewDecoder(x.get("/auth/session", c).Body).Decode(&s); err != nil || !s.Authenticated || s.User.Email != "ana@example.test" {
		t.Fatalf("session = %+v, %v", s, err)
	}
	if got := body(x.get("/api/me", c)); got != "ana@example.test at1" {
		t.Fatalf("api = %q", got)
	}
	if res := x.get("/api/me", nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous api = %d", res.StatusCode)
	}
	if got := body(x.get("/auth/session", nil)); !strings.Contains(got, `"authenticated":false`) {
		t.Fatalf("anonymous session = %s", got)
	}
}

func TestActionStatusReachesTheApp(t *testing.T) {
	x := newApp(t)
	x.loginWith(t, "/security", "&kc_action_status=success", "/security?action_status=success")
	x.loginWith(t, "/security", "&kc_action_status=whatever", "/security")
}

func TestCallbackRejects(t *testing.T) {
	x := newApp(t)
	res := x.do(httptest.NewRequest(http.MethodGet, "/auth/login?return_to=/files", nil))
	state, _ := url.Parse(res.Header.Get("Location"))
	login := cookie(res, "login")

	// Una vuelta que este navegador ya no espera (otra pestaña, o la cookie caducó): su código no se canjea, y un
	// inicio nuevo vuelve a donde iba aquel, o a la portada si ya no se sabe.
	x.f.onToken(func(map[string]string) (int, any) {
		t.Error("a stale callback must not exchange its code")
		return http.StatusBadRequest, nil
	})
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=c1&state=other", nil)
	req.AddCookie(login)
	if res := x.do(req); res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/auth/login?retry=1&return_to=%2F" {
		t.Fatalf("other state: %d → %s", res.StatusCode, res.Header.Get("Location"))
	}
	if res := x.do(httptest.NewRequest(http.MethodGet, "/auth/callback?code=c1&state="+state.Query().Get("state"), nil)); res.Header.Get("Location") != "/auth/login?retry=1&return_to=%2Ffiles" {
		t.Fatalf("no cookie → %s", res.Header.Get("Location"))
	}

	// El reintento sólo va una vez: si su vuelta tampoco cuadra (sin cookies), se dice. Sin código tampoco se reintenta.
	res = x.do(httptest.NewRequest(http.MethodGet, "/auth/login?retry=1&return_to=/files", nil))
	retry, _ := url.Parse(res.Header.Get("Location"))
	if res := x.do(httptest.NewRequest(http.MethodGet, "/auth/callback?code=c1&state="+retry.Query().Get("state"), nil)); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("retry without cookie: %d", res.StatusCode)
	}
	if res := x.do(httptest.NewRequest(http.MethodGet, "/auth/callback?error=access_denied&state=other", nil)); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("error without cookie: %d", res.StatusCode)
	}

	// La persona canceló en el emisor: vuelve a donde estaba con el motivo.
	res = x.do(httptest.NewRequest(http.MethodGet, "/auth/login?return_to=/files", nil))
	to, _ := url.Parse(res.Header.Get("Location"))
	req = httptest.NewRequest(http.MethodGet, "/auth/callback?error=access_denied&state="+to.Query().Get("state"), nil)
	req.AddCookie(cookie(res, "login"))
	if res := x.do(req); res.Header.Get("Location") != "/files?auth_error=access_denied" {
		t.Fatalf("cancel → %s", res.Header.Get("Location"))
	}
}

func TestRefreshOnceForConcurrentRequests(t *testing.T) {
	x := newApp(t)
	c := x.login(t, "/")
	var calls atomic.Int32
	x.f.onToken(func(form map[string]string) (int, any) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		if form["grant_type"] != "refresh_token" || form["refresh_token"] != "rt1" {
			return http.StatusBadRequest, map[string]string{"error": "invalid_grant"}
		}
		return http.StatusOK, map[string]any{"access_token": "at2", "refresh_token": "rt2", "token_type": "Bearer", "expires_in": 3600}
	})
	// Cinco minutos después el token venció: varios pedidos a la vez, un solo refresco.
	x.now = func() time.Time { return time.Now().Add(6 * time.Minute) }
	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() {
			if got := body(x.get("/api/me", c)); got != "ana@example.test at2" {
				t.Errorf("api = %q", got)
			}
		})
	}
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Fatalf("refresh calls = %d", n)
	}
}

func TestSessionEndsWhenIssuerRefuses(t *testing.T) {
	x := newApp(t)
	c := x.login(t, "/")
	x.f.onToken(nil) // invalid_grant: la sesión se cerró en el emisor
	x.now = func() time.Time { return time.Now().Add(6 * time.Minute) }
	res := x.get("/api/me", c)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("api = %d", res.StatusCode)
	}
	if gone := cookie(res, "session"); gone == nil || gone.MaxAge >= 0 {
		t.Fatalf("cookie not cleared: %+v", gone)
	}
	if _, err := x.store.Get(t.Context(), c.Value); err == nil {
		t.Fatal("session still stored")
	}
}

func TestLogout(t *testing.T) {
	x := newApp(t)
	c := x.login(t, "/")

	// Desde otro sitio no se puede cerrar la sesión de nadie.
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.AddCookie(c)
	if res := x.do(req); res.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site logout = %d", res.StatusCode)
	}

	req = httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(c)
	res := x.do(req)
	to, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(to.String(), x.f.URL+"/logout?") ||
		to.Query().Get("post_logout_redirect_uri") != "http://app.test/" || to.Query().Get("id_token_hint") == "" {
		t.Fatalf("logout → %d %s", res.StatusCode, to)
	}
	if res := x.get("/api/me", c); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after logout = %d", res.StatusCode)
	}
}

func TestBackchannelLogout(t *testing.T) {
	x := newApp(t)
	c := x.login(t, "/")
	post := func(token string) *http.Response {
		req := httptest.NewRequest(http.MethodPost, "/auth/backchannel-logout", strings.NewReader("logout_token="+url.QueryEscape(token)))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return x.do(req)
	}
	if res := post("garbage"); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("garbage = %d", res.StatusCode)
	}
	token := x.f.sign(t, map[string]any{"aud": "accounts", "jti": "j1", "sid": "s1", "sub": "u1",
		"events": map[string]any{backchannelEvent: map[string]any{}}})
	if res := post(token); res.StatusCode != http.StatusOK {
		t.Fatalf("logout token = %d", res.StatusCode)
	}
	if res := x.get("/api/me", c); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after backchannel = %d", res.StatusCode)
	}
}

func TestSafeReturn(t *testing.T) {
	for in, want := range map[string]string{
		"/files?view=list":    "/files?view=list",
		"":                    "/",
		"https://evil.test/x": "/",
		"//evil.test/x":       "/",
		"/\\evil.test":        "/",
		"files":               "/",
		"/a\nb":               "/",
	} {
		if got := safeReturn(in); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}
