package auth

import (
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
)

func TestDiscover(t *testing.T) {
	f := newFakeIssuer(t)
	p, err := Discover(t.Context(), f.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.TokenURL != f.URL+"/token" || p.EndSessionURL != f.URL+"/logout" {
		t.Fatalf("endpoints = %+v", p)
	}
	if n := p.keys.Len(); n != 1 {
		t.Fatalf("keys = %d", n)
	}
}

// La misma discovery servida desde otra dirección: el emisor que declara ya no es el configurado.
func TestDiscoverRejectsAnotherIssuer(t *testing.T) {
	f := newFakeIssuer(t)
	target, _ := url.Parse(f.URL)
	proxy := httptest.NewServer(httputil.NewSingleHostReverseProxy(target))
	defer proxy.Close()
	if _, err := Discover(t.Context(), proxy.URL, nil); err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("err = %v", err)
	}
}
