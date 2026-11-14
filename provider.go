package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Provider es el emisor OIDC: sus endpoints y sus claves, que se refrescan solas.
type Provider struct {
	Issuer        string
	AuthURL       string
	TokenURL      string
	EndSessionURL string
	keys          jwk.Set
}

type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// ctx debe durar lo que la aplicación: refresca las claves.
func Discover(ctx context.Context, issuer string, client *http.Client) (*Provider, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: discovery: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth: discovery: %s", res.Status)
	}
	var d discovery
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&d); err != nil {
		return nil, fmt.Errorf("auth: discovery: %w", err)
	}
	// OIDC Discovery §4.3.
	if d.Issuer != issuer {
		return nil, fmt.Errorf("auth: discovery: issuer %q, want %q", d.Issuer, issuer)
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, errors.New("auth: discovery: missing endpoints")
	}
	if !sameOrigin(d.JWKSURI, issuer) {
		return nil, fmt.Errorf("auth: discovery: jwks_uri %q outside the issuer", d.JWKSURI)
	}

	cache, err := jwk.NewCache(ctx, httprc.NewClient(httprc.WithHTTPClient(client)))
	if err != nil {
		return nil, err
	}
	if err := cache.Register(ctx, d.JWKSURI, jwk.WithMinInterval(5*time.Minute)); err != nil {
		return nil, fmt.Errorf("auth: jwks: %w", err)
	}
	keys, err := cache.CachedSet(d.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("auth: jwks: %w", err)
	}
	return &Provider{
		Issuer:        d.Issuer,
		AuthURL:       d.AuthorizationEndpoint,
		TokenURL:      d.TokenEndpoint,
		EndSessionURL: d.EndSessionEndpoint,
		keys:          keys,
	}, nil
}

func sameOrigin(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && ua.Scheme == ub.Scheme && ua.Host == ub.Host
}
