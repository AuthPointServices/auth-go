package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// refreshBefore: el token de acceso se renueva si le queda menos que esto.
const refreshBefore = 30 * time.Second

var errEnded = errors.New("auth: session ended at the issuer")

type ctxKey struct{}

// FromContext devuelve la sesión que dejó Load o Require.
func FromContext(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(ctxKey{}).(*Session)
	return s, ok
}

// Load lee la sesión de la cookie, renueva su token si hace falta y la deja en el contexto. Sin sesión, sigue igual.
func (a *Auth) Load(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s := a.current(w, r); s != nil {
			r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, s))
		}
		next.ServeHTTP(w, r)
	})
}

// Require es Load para una API: sin sesión responde 401. Además rechaza los pedidos que cambian algo desde otro
// origen (CSRF), porque la cookie viaja sola.
func (a *Auth) Require(next http.Handler) http.Handler {
	return http.NewCrossOriginProtection().Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := a.current(w, r)
		if s == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthenticated"}`))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, s)))
	}))
}

// current es la sesión de este pedido con su token al día; nil si no hay o el emisor la cerró. Una cookie que ya
// no vale se borra.
func (a *Auth) current(w http.ResponseWriter, r *http.Request) *Session {
	c, err := r.Cookie(a.cookie)
	if err != nil || c.Value == "" {
		return nil
	}
	s, err := a.cfg.Store.Get(r.Context(), c.Value)
	if err == nil {
		s, err = a.fresh(r.Context(), s)
	}
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			a.log.ErrorContext(r.Context(), "auth: load session", "err", err)
			return nil
		}
		a.clearCookie(w, a.cookie)
		return nil
	}
	return s
}

// fresh renueva el token de acceso si está por vencer. Con la sesión bloqueada: si otro pedido la renovó mientras
// tanto, usa la suya. Si el emisor ya no la acepta (la cerró, o venció), la sesión se borra.
func (a *Auth) fresh(ctx context.Context, s *Session) (*Session, error) {
	if a.now().Add(refreshBefore).Before(s.AccessExpiry) {
		return s, nil
	}
	var out Session
	err := a.cfg.Store.Update(ctx, s.ID, func(cur *Session) error {
		if a.now().Add(refreshBefore).Before(cur.AccessExpiry) {
			out = *cur
			return nil
		}
		if cur.RefreshToken == "" {
			return errEnded
		}
		tok, err := a.oauth.TokenSource(a.client(ctx), &oauth2.Token{RefreshToken: cur.RefreshToken}).Token()
		if err != nil {
			if re := (*oauth2.RetrieveError)(nil); errors.As(err, &re) && re.ErrorCode == "invalid_grant" {
				return errEnded
			}
			return err
		}
		cur.AccessToken, cur.AccessExpiry = tok.AccessToken, tok.Expiry
		if tok.RefreshToken != "" {
			cur.RefreshToken = tok.RefreshToken
		}
		if raw, _ := tok.Extra("id_token").(string); raw != "" {
			cur.IDToken = raw
		}
		out = *cur
		return nil
	})
	if errors.Is(err, errEnded) {
		_ = a.cfg.Store.Delete(ctx, s.ID)
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// handleSession le dice al frontend si hay sesión y quién es; nunca le da tokens.
func (a *Auth) handleSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	s := a.current(w, r)
	if s == nil {
		_, _ = w.Write([]byte(`{"authenticated":false}`))
		return
	}
	_ = json.NewEncoder(w).Encode(struct {
		Authenticated bool     `json:"authenticated"`
		User          Identity `json:"user"`
	}{true, s.Identity})
}
