package auth

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const loginTTL = 10 * time.Minute

var (
	prompts = map[string]bool{"login": true, "create": true}
	// Con su parámetro, si lo lleva: «idp_link:google».
	action = regexp.MustCompile(`^[A-Za-z_-]{1,64}(:[A-Za-z0-9._-]{1,64})?$`)
	locale = regexp.MustCompile(`^[a-z]{2}(-[A-Z]{2})?$`)
)

// El state va también en una cookie: la vuelta sólo vale en este navegador.
func (a *Auth) handleLogin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := newID()
	l := Login{Verifier: oauth2.GenerateVerifier(), Nonce: newID(), ReturnTo: safeReturn(q.Get("return_to")), ExpiresAt: a.now().Add(loginTTL), Retry: q.Get("retry") == "1"}
	if err := a.cfg.Store.SaveLogin(r.Context(), state, l); err != nil {
		a.fail(w, r, "save login", err)
		return
	}
	http.SetCookie(w, a.newCookie(a.login, state, loginTTL))

	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(l.Verifier), oauth2.SetAuthURLParam("nonce", l.Nonce)}
	if p := q.Get("prompt"); prompts[p] {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", p))
	}
	if v := q.Get("action"); action.MatchString(v) {
		opts = append(opts, oauth2.SetAuthURLParam("kc_action", v))
	}
	if v := q.Get("login_hint"); v != "" && len(v) <= 254 {
		opts = append(opts, oauth2.SetAuthURLParam("login_hint", v))
	}
	if v := q.Get("locale"); locale.MatchString(v) {
		opts = append(opts, oauth2.SetAuthURLParam("ui_locales", v))
	}
	// #nosec G710 -- el destino es el emisor configurado.
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, opts...), http.StatusFound)
}

// safeReturn sólo deja rutas de este origen.
func safeReturn(p string) string {
	if p == "" || p[0] != '/' || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return "/"
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	return p
}

func (a *Auth) newCookie(name, value string, ttl time.Duration) *http.Cookie {
	return &http.Cookie{ // #nosec G124 -- Secure sigue a BaseURL
		Name: name, Value: value, Path: "/", MaxAge: int(ttl.Seconds()),
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	}
}

func (a *Auth) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode}) // #nosec G124 -- como newCookie
}

func (a *Auth) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	a.log.ErrorContext(r.Context(), "auth: "+what, "err", err)
	// El producto lo cuenta con su marca; el fallo queda en el registro.
	http.Redirect(w, r, "/?auth_error=failed", http.StatusSeeOther)
}
