package auth

import (
	"net/http"
	"net/url"
)

// Routes son las rutas /auth/*, para montar en la raíz del producto.
func (a *Auth) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", a.handleLogin)
	mux.HandleFunc("GET /auth/callback", a.handleCallback)
	mux.HandleFunc("GET /auth/session", a.handleSession)
	mux.HandleFunc("POST /auth/logout", a.handleLogout)
	mux.HandleFunc("POST /auth/backchannel-logout", a.handleBackchannel)
	return http.NewCrossOriginProtection().Handler(mux)
}

// handleLogout cierra aquí y en el emisor. Es un POST de formulario: el navegador sigue la redirección.
func (a *Auth) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var hint string
	if c, err := r.Cookie(a.cookie); err == nil && c.Value != "" {
		if s, err := a.cfg.Store.Get(ctx, c.Value); err == nil {
			hint = s.IDToken
		}
		if err := a.cfg.Store.Delete(ctx, c.Value); err != nil {
			a.log.ErrorContext(ctx, "auth: delete session", "err", err)
		}
	}
	a.clearCookie(w, a.cookie)
	if a.provider.EndSessionURL == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	u, err := url.Parse(a.provider.EndSessionURL)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	q := u.Query()
	q.Set("client_id", a.cfg.ClientID)
	q.Set("post_logout_redirect_uri", a.base.String()+"/")
	if hint != "" {
		q.Set("id_token_hint", hint)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

// ponytail: no guarda los jti; repetir un aviso sólo vuelve a borrar lo ya borrado.
func (a *Auth) handleBackchannel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	sid, sub, err := a.provider.verifyLogoutToken(r.PostForm.Get("logout_token"), a.cfg.ClientID)
	if err != nil {
		a.log.WarnContext(ctx, "auth: rejected logout token", "err", err)
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	if sid != "" {
		err = a.cfg.Store.DeleteBySID(ctx, sid)
	} else {
		err = a.cfg.Store.DeleteBySubject(ctx, sub)
	}
	if err != nil {
		a.log.ErrorContext(ctx, "auth: backchannel logout", "err", err)
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
