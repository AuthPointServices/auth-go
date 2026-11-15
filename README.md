# auth-go

El inicio de sesión de los productos, del lado del servidor (patrón BFF). El backend de cada producto es el cliente
OIDC de `identity-server`: hace el flujo con código y PKCE, guarda los tokens en su base y al navegador sólo le da
una cookie de sesión `HttpOnly` de su propio dominio. Así funciona igual en `orange.fretchcop.space` que en
`orange.com`, sin cookies de terceros ni tokens en JavaScript.

## Uso

```go
db, _ := pgxpool.New(ctx, os.Getenv("DB_DSN"))
store, _ := pgstore.New(db, sessionKey) // 32 bytes, la misma en todas las instancias
_ = store.Migrate(ctx)                  // o copiar pgstore.Schema a las migraciones del producto

a, err := auth.New(ctx, auth.Config{
	Issuer:       "https://auth.fretchcop.space/realms/fretchcop",
	ClientID:     "orange",
	ClientSecret: os.Getenv("AUTH_CLIENT_SECRET"),
	BaseURL:      "https://orange.com", // o https://orange.fretchcop.space
	Store:        store,
})

mux := http.NewServeMux()
mux.Handle("/auth/", a.Routes())            // login, callback, session, logout, backchannel-logout
mux.Handle("/api/", a.Require(api))         // 401 sin sesión; rechaza pedidos de otro origen
```

Dentro de un handler, `auth.FromContext(r.Context())` da la sesión: quién es (`Identity`) y su `AccessToken`, ya
renovado si hacía falta.

| Ruta | Para qué |
|---|---|
| `GET /auth/login?return_to=/ruta` | Manda a entrar. `prompt=create` abre el registro; `action=UPDATE_PASSWORD` y similares lanzan una acción de la cuenta |
| `GET /auth/callback` | La vuelta del emisor; abre la sesión y vuelve a `return_to`, con `auth_error=…` si el emisor no terminó, o `action_status=success\|cancelled\|error` tras una acción |
| `GET /auth/session` | `{"authenticated": true, "user": {...}}` para el frontend; nunca da tokens |
| `POST /auth/logout` | Cierra aquí y en el emisor (formulario, no `fetch`: el navegador sigue la redirección) |
| `POST /auth/backchannel-logout` | El emisor avisa que una sesión se cerró en otro lado |

En el emisor, el cliente es confidencial, con PKCE S256, la vuelta en `/auth/callback`, el cierre en `/*` y el aviso
por back-channel en `/auth/backchannel-logout`. Ver `identity-server/config/clients.yaml`.

## Pruebas

```sh
go test ./...                                                     # contra un emisor falso
TEST_DB_DSN=postgres://…/authgo_test?sslmode=disable go test ./... # además, el almacén en Postgres
```
