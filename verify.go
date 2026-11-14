package auth

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

const skew = 30 * time.Second

const backchannelEvent = "http://schemas.openid.net/event/backchannel-logout"

type Identity struct {
	Subject       string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	Locale        string `json:"locale,omitempty"`
}

// OIDC Core §3.1.3.7.
func (p *Provider) verifyIDToken(raw, clientID, nonce string) (Identity, string, error) {
	tok, err := jwt.ParseString(raw, jwt.WithKeySet(p.keys), jwt.WithIssuer(p.Issuer), jwt.WithAudience(clientID),
		jwt.WithAcceptableSkew(skew), jwt.WithRequiredClaim(jwt.ExpirationKey), jwt.WithRequiredClaim(jwt.SubjectKey))
	if err != nil {
		return Identity{}, "", fmt.Errorf("auth: id token: %w", err)
	}
	var got string
	if err := tok.Get("nonce", &got); err != nil || got != nonce {
		return Identity{}, "", errors.New("auth: id token: nonce mismatch")
	}
	if aud, _ := tok.Audience(); len(aud) > 1 {
		var azp string
		if err := tok.Get("azp", &azp); err != nil || azp != clientID {
			return Identity{}, "", errors.New("auth: id token: azp mismatch")
		}
	}
	var id Identity
	id.Subject, _ = tok.Subject()
	_ = tok.Get("email", &id.Email)
	_ = tok.Get("email_verified", &id.EmailVerified)
	_ = tok.Get("name", &id.Name)
	_ = tok.Get("given_name", &id.GivenName)
	_ = tok.Get("family_name", &id.FamilyName)
	_ = tok.Get("locale", &id.Locale)
	var sid string
	_ = tok.Get("sid", &sid)
	return id, sid, nil
}

// OIDC Back-Channel Logout §2.6.
func (p *Provider) verifyLogoutToken(raw, clientID string) (sid, sub string, err error) {
	tok, err := jwt.ParseString(raw, jwt.WithKeySet(p.keys), jwt.WithIssuer(p.Issuer), jwt.WithAudience(clientID),
		jwt.WithAcceptableSkew(skew), jwt.WithRequiredClaim(jwt.IssuedAtKey), jwt.WithRequiredClaim(jwt.JwtIDKey))
	if err != nil {
		return "", "", fmt.Errorf("auth: logout token: %w", err)
	}
	if iat, _ := tok.IssuedAt(); time.Since(iat) > 5*time.Minute {
		return "", "", errors.New("auth: logout token: too old")
	}
	var events map[string]any
	if err := tok.Get("events", &events); err != nil {
		return "", "", errors.New("auth: logout token: no events")
	}
	if _, ok := events[backchannelEvent]; !ok {
		return "", "", errors.New("auth: logout token: not a logout event")
	}
	if slices.Contains(tok.Keys(), "nonce") {
		return "", "", errors.New("auth: logout token: has a nonce")
	}
	_ = tok.Get("sid", &sid)
	sub, _ = tok.Subject()
	if sid == "" && sub == "" {
		return "", "", errors.New("auth: logout token: no sid nor sub")
	}
	return sid, sub, nil
}
