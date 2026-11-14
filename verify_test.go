package auth

import (
	"testing"
	"time"
)

func provider(t *testing.T, f *fakeIssuer) *Provider {
	t.Helper()
	p, err := Discover(t.Context(), f.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVerifyIDToken(t *testing.T) {
	f := newFakeIssuer(t)
	p := provider(t, f)
	base := func() map[string]any {
		return map[string]any{"sub": "u1", "aud": "accounts", "exp": time.Now().Add(time.Minute), "nonce": "n1",
			"sid": "s1", "email": "ana@example.test", "email_verified": true, "name": "Ana Pérez"}
	}

	id, sid, err := p.verifyIDToken(f.sign(t, base()), "accounts", "n1")
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "u1" || id.Email != "ana@example.test" || !id.EmailVerified || id.Name != "Ana Pérez" || sid != "s1" {
		t.Fatalf("identity = %+v, sid %q", id, sid)
	}

	bad := map[string]func(map[string]any){
		"other audience": func(c map[string]any) { c["aud"] = "orange" },
		"expired":        func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour) },
		"other nonce":    func(c map[string]any) { c["nonce"] = "n2" },
		"no nonce":       func(c map[string]any) { delete(c, "nonce") },
		"other issuer":   func(c map[string]any) { c["iss"] = "https://evil.example" },
		"two audiences":  func(c map[string]any) { c["aud"] = []string{"accounts", "orange"}; c["azp"] = "orange" },
	}
	for name, change := range bad {
		c := base()
		change(c)
		if _, _, err := p.verifyIDToken(f.sign(t, c), "accounts", "n1"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestVerifyIDTokenFromAnotherKey(t *testing.T) {
	f, other := newFakeIssuer(t), newFakeIssuer(t)
	p := provider(t, f)
	raw := other.sign(t, map[string]any{"iss": f.URL, "sub": "u1", "aud": "accounts", "exp": time.Now().Add(time.Minute), "nonce": "n"})
	if _, _, err := p.verifyIDToken(raw, "accounts", "n"); err == nil {
		t.Fatal("accepted a token signed by another key")
	}
}

func TestVerifyLogoutToken(t *testing.T) {
	f := newFakeIssuer(t)
	p := provider(t, f)
	event := map[string]any{backchannelEvent: map[string]any{}}
	base := func() map[string]any {
		return map[string]any{"aud": "accounts", "jti": "j1", "sid": "s1", "sub": "u1", "events": event}
	}

	sid, sub, err := p.verifyLogoutToken(f.sign(t, base()), "accounts")
	if err != nil || sid != "s1" || sub != "u1" {
		t.Fatalf("sid %q sub %q err %v", sid, sub, err)
	}

	bad := map[string]func(map[string]any){
		"no event":     func(c map[string]any) { c["events"] = map[string]any{"other": map[string]any{}} },
		"with nonce":   func(c map[string]any) { c["nonce"] = "n" },
		"no sid, sub":  func(c map[string]any) { delete(c, "sid"); delete(c, "sub") },
		"no jti":       func(c map[string]any) { delete(c, "jti") },
		"too old":      func(c map[string]any) { c["iat"] = time.Now().Add(-time.Hour) },
		"other client": func(c map[string]any) { c["aud"] = "orange" },
	}
	for name, change := range bad {
		c := base()
		change(c)
		if _, _, err := p.verifyLogoutToken(f.sign(t, c), "accounts"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
