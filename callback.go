package auth

import (
	"errors"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

// handleCallback es la vuelta del emisor: comprueba que el state es el de este navegador, canjea el código con el
// verificador PKCE, valida el ID token y abre la sesión.
func (a *Auth) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	c, err := r.Cookie(a.login)
	a.clearCookie(w, a.login)
	if err != nil || c.Value == "" || c.Value != q.Get("state") {
		http.Error(w, "El inicio de sesión no es válido o caducó. Vuelve a intentarlo.", http.StatusBadRequest)
		return
	}
	l, err := a.cfg.Store.TakeLogin(ctx, c.Value)
	if errors.Is(err, ErrNotFound) {
		http.Error(w, "El inicio de sesión no es válido o caducó. Vuelve a intentarlo.", http.StatusBadRequest)
		return
	}
	if err != nil {
		a.fail(w, r, "take login", err)
		return
	}
	// La persona canceló o el emisor no pudo: vuelve a donde estaba y el producto decide qué decir.
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
	// Si este navegador ya tenía una sesión (volver de cambiar la contraseña, por ejemplo), la nueva la reemplaza.
	if old, err := r.Cookie(a.cookie); err == nil && old.Value != "" {
		if err := a.cfg.Store.Delete(ctx, old.Value); err != nil {
			a.log.WarnContext(ctx, "auth: delete replaced session", "err", err)
		}
	}
	http.SetCookie(w, a.newCookie(a.cookie, s.ID, a.cfg.MaxAge))
	http.Redirect(w, r, l.ReturnTo, http.StatusSeeOther)
}

// withParam añade un parámetro a una ruta que ya pasó por safeReturn.
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
