# auth-go

El inicio de sesión de los productos, del lado del servidor (patrón BFF). El backend de cada producto es el cliente
OIDC de `identity-server`: hace el flujo con código y PKCE, guarda los tokens en su base y al navegador sólo le da
una cookie de sesión `HttpOnly` de su propio dominio. Así funciona igual en `orange.fretchcop.space` que en
`orange.com`, sin cookies de terceros ni tokens en JavaScript.
