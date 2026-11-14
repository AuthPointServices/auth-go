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

// Lo que el producto puede pedirle al emisor al mandar a entrar, y con qué forma.
var (
	prompts = map[string]bool{"login": true, "create": true} // create abre el registro
	action  = regexp.MustCompile(`^[A-Za-z_-]{1,64}$`)       // kc_action: cambiar contraseña, añadir una passkey…
	locale  = regexp.MustCompile(`^[a-z]{2}(-[A-Z]{2})?$`)
)

// handleLogin manda al emisor con un state, PKCE y nonce nuevos; el state queda también en una cookie para que la
// vuelta sólo valga en este navegador. Con ?return_to= vuelve ahí (sólo rutas de este origen).
func (a *Auth) handleLogin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := newID()
	l := Login{Verifier: oauth2.GenerateVerifier(), Nonce: newID(), ReturnTo: safeReturn(q.Get("return_to")), ExpiresAt: a.now().Add(loginTTL)}
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
	// #nosec G710 -- el destino es el endpoint de autorización del emisor configurado; lo del pedido va como parámetro.
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, opts...), http.StatusFound)
}

// safeReturn deja pasar sólo una ruta de este mismo origen: nada de «//otro.sitio» ni «/\otro.sitio».
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

// Secure va siempre que el producto es https; sólo en desarrollo (http://localhost) no se puede.
func (a *Auth) newCookie(name, value string, ttl time.Duration) *http.Cookie {
	return &http.Cookie{ // #nosec G124 -- Secure depende de BaseURL, ver arriba
		Name: name, Value: value, Path: "/", MaxAge: int(ttl.Seconds()),
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	}
}

func (a *Auth) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode}) // #nosec G124 -- como newCookie
}

// fail registra el error y responde sin dar detalles.
func (a *Auth) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	a.log.ErrorContext(r.Context(), "auth: "+what, "err", err)
	http.Error(w, "No se pudo iniciar sesión. Vuelve a intentarlo.", http.StatusInternalServerError)
}
