# @pismile/authjs

Fournisseur **« Se connecter avec pismile »** pour [Auth.js](https://authjs.dev) (Next.js, SvelteKit, Express…).

pismile connecte vos utilisateurs avec leur **alias PI-SPI** (BCEAO) : pas de mot de passe, identité confirmée par leur banque.
Vous recevez le nom vérifié du titulaire, son pays et sa catégorie (P, C, B, G).

## Installation

```bash
npm install next-auth@beta @pismile/authjs
```

## Configuration

Créez une application dans votre [console pismile](https://pismile.com/console) avec l'adresse de redirection
`http://localhost:3000/api/auth/callback/pismile`, puis :

```bash
# .env.local
AUTH_SECRET=...                 # npx auth secret
AUTH_PISMILE_ID=votre_client_id
AUTH_PISMILE_SECRET=votre_secret
```

```ts
// auth.ts
import NextAuth from "next-auth"
import Pismile, { pismileCallbacks } from "@pismile/authjs"

export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [Pismile()],
  callbacks: pismileCallbacks,
})
```

```ts
// app/api/auth/[...nextauth]/route.ts
import { handlers } from "@/auth"
export const { GET, POST } = handlers
```

## Utilisation

```tsx
const session = await auth()
session?.user?.id                  // sub pismile : identifiant stable, propre à votre application
session?.user?.name                // nom vérifié du titulaire
session?.user?.pismile?.country    // « TG »
session?.user?.pismile?.category   // « P » | « C » | « B » | « G »
session?.user?.pismile?.authTime   // dernière vérification de l'alias (secondes Unix)
```

Bouton de connexion : `await signIn("pismile")`.

## Options

```ts
Pismile({
  scope: "openid profile address",  // défaut : "openid profile"
  maxAge: 300,                      // nouvelle vérification si la dernière date de plus de 5 min
  prompt: "login",                  // nouvelle vérification à chaque connexion
})
```

Avant une action sensible, vérifiez côté serveur :

```ts
import { isRecentlyVerified } from "@pismile/authjs"

if (!isRecentlyVerified(session?.user, 300)) {
  await signIn("pismile", undefined, { prompt: "login" })
}
```

### Vos propres callbacks

```ts
callbacks: {
  async jwt(params) {
    const token = await pismileCallbacks.jwt(params)
    // … votre logique
    return token
  },
  session: pismileCallbacks.session,
}
```

## Ce que le paquet configure pour vous

- OpenID Connect avec découverte (`AUTH_PISMILE_ISSUER`, défaut `https://pismile.com`)
- PKCE (`S256`), `state` et `nonce`
- Secret envoyé en `client_secret_basic`
- Claims pismile dans la session, typées en TypeScript
- Utilisateur identifié par `sub` (pismile ne transmet pas d'e-mail)

## Documentation

https://pismile.com/docs/sdk/authjs

## Licence

MIT
