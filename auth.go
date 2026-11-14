// Package auth es el inicio de sesión de un producto del lado del servidor (BFF): el backend es el cliente OIDC,
// guarda los tokens y al navegador le da sólo una cookie HttpOnly de su propio dominio.
package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// Config es lo que el producto sabe del emisor y de sí mismo.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// BaseURL es donde el navegador ve el producto; la vuelta va a BaseURL + "/auth/callback".
	BaseURL string
	// Scopes además de openid; por defecto profile y email.
	Scopes []string
	Store  Store
	// MaxAge es el tope de una sesión; por defecto 90 días.
	MaxAge     time.Duration
	HTTPClient *http.Client
	Logger     *slog.Logger
}

// Auth monta las rutas /auth/* y protege las del producto.
type Auth struct {
	cfg      Config
	provider *Provider
	oauth    *oauth2.Config
	base     *url.URL
	cookie   string // nombre de la cookie de sesión
	login    string // nombre de la cookie del inicio a medio hacer
	secure   bool
	log      *slog.Logger
	now      func() time.Time
}

// New descubre el emisor. ctx debe durar lo que la aplicación: refresca las claves.
func New(ctx context.Context, cfg Config) (*Auth, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.BaseURL == "" || cfg.Store == nil {
		return nil, errors.New("auth: Issuer, ClientID, ClientSecret, BaseURL and Store are required")
	}
	base, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") {
		return nil, errors.New("auth: BaseURL must be an absolute http(s) URL")
	}
	if cfg.Scopes == nil {
		cfg.Scopes = []string{"profile", "email"}
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 90 * 24 * time.Hour
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	p, err := Discover(ctx, cfg.Issuer, cfg.HTTPClient)
	if err != nil {
		return nil, err
	}
	a := &Auth{
		cfg:      cfg,
		provider: p,
		base:     base,
		secure:   base.Scheme == "https",
		log:      cfg.Logger,
		now:      time.Now,
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     oauth2.Endpoint{AuthURL: p.AuthURL, TokenURL: p.TokenURL, AuthStyle: oauth2.AuthStyleInHeader},
			RedirectURL:  base.String() + "/auth/callback",
			Scopes:       append([]string{"openid"}, cfg.Scopes...),
		},
	}
	// __Host- exige https; en desarrollo (http) va sin prefijo.
	a.cookie, a.login = "session", "login"
	if a.secure {
		a.cookie, a.login = "__Host-session", "__Host-login"
	}
	return a, nil
}

func (a *Auth) client(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, a.cfg.HTTPClient)
}
