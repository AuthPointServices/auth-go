// Package storetest comprueba que un auth.Store se porta como espera el resto de la librería.
package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	auth "github.com/AuthPointServices/auth-go"
)

// Run corre la batería contra el almacén que devuelve open, uno limpio por prueba.
func Run(t *testing.T, open func(t *testing.T) auth.Store) {
	ctx := context.Background()
	session := func(id, sid, sub string) *auth.Session {
		now := time.Now().UTC().Truncate(time.Millisecond)
		return &auth.Session{
			ID: id, SID: sid, Identity: auth.Identity{Subject: sub, Email: sub + "@example.test", Name: "Ana Pérez"},
			IDToken: "id-" + id, AccessToken: "at-" + id, RefreshToken: "rt-" + id, AccessExpiry: now.Add(5 * time.Minute),
			CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}
	}

	t.Run("login is taken once", func(t *testing.T) {
		s := open(t)
		l := auth.Login{Verifier: "v", Nonce: "n", ReturnTo: "/files", ExpiresAt: time.Now().Add(time.Minute)}
		if err := s.SaveLogin(ctx, "st", l); err != nil {
			t.Fatal(err)
		}
		got, err := s.TakeLogin(ctx, "st")
		if err != nil || got.Verifier != "v" || got.Nonce != "n" || got.ReturnTo != "/files" {
			t.Fatalf("login = %+v, %v", got, err)
		}
		if _, err := s.TakeLogin(ctx, "st"); !errors.Is(err, auth.ErrNotFound) {
			t.Fatalf("second take: %v", err)
		}
	})

	t.Run("expired login", func(t *testing.T) {
		s := open(t)
		_ = s.SaveLogin(ctx, "old", auth.Login{Verifier: "v", ExpiresAt: time.Now().Add(-time.Second)})
		if _, err := s.TakeLogin(ctx, "old"); !errors.Is(err, auth.ErrNotFound) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("session round trip", func(t *testing.T) {
		s := open(t)
		want := session("a", "s1", "u1")
		if err := s.Create(ctx, want); err != nil {
			t.Fatal(err)
		}
		got, err := s.Get(ctx, "a")
		if err != nil {
			t.Fatal(err)
		}
		if got.Identity != want.Identity || got.RefreshToken != want.RefreshToken || got.SID != "s1" ||
			!got.AccessExpiry.Equal(want.AccessExpiry) || !got.ExpiresAt.Equal(want.ExpiresAt) {
			t.Fatalf("got %+v\nwant %+v", got, want)
		}
		if _, err := s.Get(ctx, "b"); !errors.Is(err, auth.ErrNotFound) {
			t.Fatalf("unknown: %v", err)
		}
	})

	t.Run("expired session", func(t *testing.T) {
		s := open(t)
		old := session("a", "s1", "u1")
		old.ExpiresAt = time.Now().Add(-time.Second)
		_ = s.Create(ctx, old)
		if _, err := s.Get(ctx, "a"); !errors.Is(err, auth.ErrNotFound) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("update saves only on success", func(t *testing.T) {
		s := open(t)
		_ = s.Create(ctx, session("a", "s1", "u1"))
		if err := s.Update(ctx, "a", func(x *auth.Session) error {
			if x.ID != "a" {
				t.Errorf("update sees id %q", x.ID)
			}
			x.AccessToken = "new"
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		boom := errors.New("boom")
		if err := s.Update(ctx, "a", func(x *auth.Session) error { x.AccessToken = "lost"; return boom }); !errors.Is(err, boom) {
			t.Fatalf("err = %v", err)
		}
		if got, _ := s.Get(ctx, "a"); got.AccessToken != "new" {
			t.Fatalf("access token = %q", got.AccessToken)
		}
	})

	// Dos refrescos a la vez: el segundo tiene que ver lo que guardó el primero.
	t.Run("updates are serialized", func(t *testing.T) {
		s := open(t)
		_ = s.Create(ctx, session("a", "s1", "u1"))
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				err := s.Update(ctx, "a", func(x *auth.Session) error {
					n := len(x.AccessToken)
					time.Sleep(5 * time.Millisecond)
					x.AccessToken = x.AccessToken[:n] + "+"
					return nil
				})
				if err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if got, _ := s.Get(ctx, "a"); got.AccessToken != "at-a++++++++" {
			t.Fatalf("access token = %q", got.AccessToken)
		}
	})

	t.Run("delete by id, sid and subject", func(t *testing.T) {
		s := open(t)
		for _, x := range []*auth.Session{session("a", "s1", "u1"), session("b", "s2", "u1"), session("c", "s3", "u2"), session("d", "s4", "u3")} {
			_ = s.Create(ctx, x)
		}
		_ = s.Delete(ctx, "d")
		_ = s.DeleteBySID(ctx, "s3")
		_ = s.DeleteBySubject(ctx, "u1")
		for _, id := range []string{"a", "b", "c", "d"} {
			if _, err := s.Get(ctx, id); !errors.Is(err, auth.ErrNotFound) {
				t.Errorf("%s still there", id)
			}
		}
	})
}
