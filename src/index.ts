/**
 * @pismile/authjs — fournisseur « Se connecter avec pismile » pour Auth.js (Next.js, SvelteKit, Express…).
 *
 * pismile est un fournisseur OpenID Connect : connexion par alias PI-SPI (BCEAO), identité confirmée par la banque.
 * Ce paquet préconfigure PKCE, state et nonce, l'authentification client_secret_basic et les claims pismile.
 */
import type { AuthConfig } from "@auth/core"
import type { OIDCConfig, OIDCUserConfig } from "@auth/core/providers"

/** Catégorie du titulaire dans PI-SPI : Particulier, Commerçant, Business (personne morale), Gouvernement. */
export type PismileCategory = "P" | "C" | "B" | "G"

/** Claims renvoyées par pismile (scopes openid, profile, address). */
export interface PismileProfile extends Record<string, any> {
  /** Identifiant stable de l'utilisateur, propre à votre application. */
  sub: string
  /** Nom du titulaire du compte, tel que le connaît son établissement. */
  name?: string
  /** Pays du compte (ISO 3166-1 alpha-2), ex. « TG ». */
  pismile_country?: string
  /** Catégorie du titulaire dans PI-SPI. */
  pismile_category?: PismileCategory
  /** Date de la dernière vérification de l'alias (secondes depuis l'époque Unix). */
  auth_time?: number
  /** Avec le scope address. */
  address?: { country?: string }
}

/** Informations pismile ajoutées à `session.user.pismile` par `pismileCallbacks`. */
export interface PismileClaims {
  country: string | null
  category: PismileCategory | null
  /** Dernière vérification de l'alias (secondes depuis l'époque Unix). */
  authTime: number | null
}

export interface PismileOptions extends OIDCUserConfig<PismileProfile> {
  /** Scopes demandés. Défaut : « openid profile ». */
  scope?: string
  /** Âge maximal de la dernière vérification de l'alias, en secondes (nouvelle vérification au-delà). */
  maxAge?: number
  /** « login » : nouvelle vérification à chaque connexion ; « consent » : redemander l'accord ; « none » : aucune interaction. */
  prompt?: "login" | "consent" | "none"
}

const DEFAULT_ISSUER = "https://pismile.com"
const DEFAULT_SCOPE = "openid profile"

function env(name: string): string | undefined {
  return typeof process !== "undefined" && process.env ? process.env[name] : undefined
}

/**
 * Fournisseur pismile.
 *
 * Variables d'environnement lues par défaut : AUTH_PISMILE_ID, AUTH_PISMILE_SECRET et AUTH_PISMILE_ISSUER
 * (https://pismile.com si absente).
 *
 * @example
 * ```ts
 * import NextAuth from "next-auth"
 * import Pismile, { pismileCallbacks } from "@pismile/authjs"
 *
 * export const { handlers, auth, signIn, signOut } = NextAuth({
 *   providers: [Pismile()],
 *   callbacks: pismileCallbacks,
 * })
 * ```
 */
export default function Pismile(options: PismileOptions = {}): OIDCConfig<PismileProfile> {
  const { scope, maxAge, prompt, authorization, ...rest } = options

  const params: Record<string, string> = { scope: scope ?? DEFAULT_SCOPE }
  if (maxAge !== undefined) {
    if (!Number.isInteger(maxAge) || maxAge < 0) {
      throw new TypeError("[@pismile/authjs] maxAge doit être un entier positif (secondes)")
    }
    params.max_age = String(maxAge)
  }
  if (prompt) {
    params.prompt = prompt
  }
  const extraParams =
    authorization && typeof authorization === "object" && "params" in authorization && authorization.params
      ? (authorization.params as Record<string, string>)
      : {}

  return {
    id: "pismile",
    name: "pismile",
    type: "oidc",
    style: { brandColor: "#12A150" },
    checks: ["pkce", "state", "nonce"],
    client: { token_endpoint_auth_method: "client_secret_basic" },
    ...rest,
    issuer: (rest.issuer ?? env("AUTH_PISMILE_ISSUER") ?? DEFAULT_ISSUER).replace(/\/+$/, ""),
    clientId: rest.clientId ?? env("AUTH_PISMILE_ID"),
    clientSecret: rest.clientSecret ?? env("AUTH_PISMILE_SECRET"),
    authorization: { params: { ...params, ...extraParams } },
    profile:
      rest.profile ??
      ((profile: PismileProfile) => ({
        id: profile.sub,
        name: profile.name ?? null,
        email: null,
        image: null,
      })),
  }
}

type Callbacks = NonNullable<AuthConfig["callbacks"]>
type JwtParams = Parameters<NonNullable<Callbacks["jwt"]>>[0]
type SessionParams = Parameters<NonNullable<Callbacks["session"]>>[0]

/** Extrait les informations pismile d'un profil OIDC. */
export function pismileClaims(profile: Partial<PismileProfile> | undefined | null): PismileClaims {
  return {
    country: profile?.pismile_country ?? profile?.address?.country ?? null,
    category: (profile?.pismile_category as PismileCategory | undefined) ?? null,
    authTime: typeof profile?.auth_time === "number" ? profile.auth_time : null,
  }
}

/**
 * Callbacks à passer à Auth.js (stratégie de session JWT, celle par défaut) :
 * `session.user.id` = sub pismile, `session.user.pismile` = { country, category, authTime }.
 *
 * Si vous avez vos propres callbacks, appelez ceux-ci à l'intérieur :
 * `jwt: async (params) => { const token = await pismileCallbacks.jwt(params); …; return token }`
 */
export const pismileCallbacks = {
  jwt(params: JwtParams) {
    const { token, account, profile } = params
    if (account?.provider === "pismile" && profile) {
      if (profile.sub) {
        token.sub = profile.sub
      }
      token.pismile = pismileClaims(profile as Partial<PismileProfile>)
    }
    return token
  },
  session(params: SessionParams) {
    const { session } = params
    const token = (params as { token?: Record<string, unknown> }).token
    if (session.user && token) {
      if (typeof token.sub === "string") {
        session.user.id = token.sub
      }
      if (token.pismile) {
        session.user.pismile = token.pismile as PismileClaims
      }
    }
    return session
  },
} satisfies Pick<Callbacks, "jwt" | "session">

/**
 * true si la dernière vérification de l'alias date de moins de `seconds` secondes.
 * À appeler côté serveur avant une action sensible (avec `Pismile({ maxAge })` ou `prompt: "login"`).
 */
export function isRecentlyVerified(
  user: { pismile?: PismileClaims | null } | null | undefined,
  seconds: number,
  now: number = Date.now(),
): boolean {
  const authTime = user?.pismile?.authTime
  return typeof authTime === "number" && now / 1000 - authTime <= seconds
}

declare module "@auth/core/types" {
  interface User {
    /** Ajouté par pismileCallbacks. */
    pismile?: PismileClaims
  }
}
