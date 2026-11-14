package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

const refreshBefore = 30 * time.Second

var errEnded = errors.New("auth: session ended at the issuer")

type ctxKey struct{}

// FromContext devuelve la sesión que dejó Load o Require.
func FromContext(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(ctxKey{}).(*Session)
	return s, ok
}

// NewContext sirve para probar handlers.
func NewContext(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, ctxKey{}, s)
}

// Load deja la sesión en el contexto si la hay.
func (a *Auth) Load(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s := a.current(w, r); s != nil {
			r = r.WithContext(NewContext(r.Context(), s))
		}
		next.ServeHTTP(w, r)
	})
}

// Require responde 401 sin sesión y rechaza pedidos de otro origen (CSRF).
func (a *Auth) Require(next http.Handler) http.Handler {
	return http.NewCrossOriginProtection().Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := a.current(w, r)
		if s == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthenticated"}`))
			return
		}
		next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), s)))
	}))
}

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

// fresh renueva el token con la sesión bloqueada: los refresh tokens sirven una vez.
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

// handleSession nunca devuelve tokens.
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
