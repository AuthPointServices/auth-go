package auth

import (
	"errors"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

func (a *Auth) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	c, err := r.Cookie(a.login)
	a.clearCookie(w, a.login)
	if err != nil || c.Value == "" || c.Value != q.Get("state") {
		a.stale(w, r)
		return
	}
	l, err := a.cfg.Store.TakeLogin(ctx, c.Value)
	if errors.Is(err, ErrNotFound) {
		a.stale(w, r)
		return
	}
	if err != nil {
		a.fail(w, r, "take login", err)
		return
	}
	// Cancelado en el emisor: vuelve con el motivo.
	if e := q.Get("error"); e != "" {
		http.Redirect(w, r, withParam(l.ReturnTo, "auth_error", e), http.StatusSeeOther)
		return
	}

	tok, err := a.oauth.Exchange(a.client(ctx), q.Get("code"), oauth2.VerifierOption(l.Verifier))
	if err != nil {
		a.fail(w, r, "exchange code", err)
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	id, sid, err := a.provider.verifyIDToken(rawID, a.cfg.ClientID, l.Nonce)
	if err != nil {
		a.fail(w, r, "verify id token", err)
		return
	}
	now := a.now()
	s := &Session{
		ID: newID(), Identity: id, SID: sid, IDToken: rawID,
		AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken, AccessExpiry: tok.Expiry,
		CreatedAt: now, ExpiresAt: now.Add(a.cfg.MaxAge),
	}
	if err := a.cfg.Store.Create(ctx, s); err != nil {
		a.fail(w, r, "create session", err)
		return
	}
	// La sesión nueva reemplaza la que hubiera (al volver de una acción de la cuenta).
	if old, err := r.Cookie(a.cookie); err == nil && old.Value != "" {
		if err := a.cfg.Store.Delete(ctx, old.Value); err != nil {
			a.log.WarnContext(ctx, "auth: delete replaced session", "err", err)
		}
	}
	http.SetCookie(w, a.newCookie(a.cookie, s.ID, a.cfg.MaxAge))
	to := l.ReturnTo
	// Tras una acción de la cuenta, Keycloak dice cómo acabó; la app lo confirma.
	if st := q.Get("kc_action_status"); actionStatus[st] {
		to = withParam(to, "action_status", st)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// stale atiende la vuelta de un inicio que este navegador ya no espera: la página de acceso siguió abierta más que el
// inicio que la abrió (en otra pestaña empezó otro, o pasaron más de loginTTL). El emisor ya abrió su sesión, así que
// un inicio nuevo vuelve sin pedir nada. El código de la vuelta no se usa: no es de este navegador. Se reintenta una
// vez; si esa vuelta tampoco cuadra (el navegador no guarda cookies), se dice.
func (a *Auth) stale(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	l, err := a.cfg.Store.TakeLogin(r.Context(), q.Get("state"))
	if q.Get("code") == "" || l.Retry {
		http.Error(w, "El inicio de sesión no es válido o caducó. Vuelve a intentarlo.", http.StatusBadRequest)
		return
	}
	to := "/"
	if err == nil {
		to = l.ReturnTo
	}
	http.Redirect(w, r, "/auth/login?retry=1&return_to="+url.QueryEscape(to), http.StatusSeeOther)
}

var actionStatus = map[string]bool{"success": true, "cancelled": true, "error": true}

func withParam(path, k, v string) string {
	u, err := url.Parse(path)
	if err != nil {
		return "/"
	}
	q := u.Query()
	q.Set(k, v)
	u.RawQuery = q.Encode()
	return u.String()
}
