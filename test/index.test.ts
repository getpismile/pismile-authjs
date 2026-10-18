import { Auth, skipCSRFCheck } from "@auth/core"
import { afterEach, describe, expect, it, vi } from "vitest"
import Pismile, { isRecentlyVerified, pismileCallbacks, pismileClaims } from "../src/index.js"

const ISSUER = "https://pismile.example"

afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
})

describe("Pismile()", () => {
  it("préconfigure OIDC, PKCE, state, nonce et client_secret_basic", () => {
    const provider = Pismile({ clientId: "id", clientSecret: "secret", issuer: ISSUER + "/" })
    expect(provider.id).toBe("pismile")
    expect(provider.type).toBe("oidc")
    expect(provider.issuer).toBe(ISSUER)
    expect(provider.checks).toEqual(["pkce", "state", "nonce"])
    expect(provider.client).toEqual({ token_endpoint_auth_method: "client_secret_basic" })
    expect(provider.authorization).toEqual({ params: { scope: "openid profile" } })
  })

  it("lit AUTH_PISMILE_ID, AUTH_PISMILE_SECRET et AUTH_PISMILE_ISSUER", () => {
    vi.stubEnv("AUTH_PISMILE_ID", "env-id")
    vi.stubEnv("AUTH_PISMILE_SECRET", "env-secret")
    vi.stubEnv("AUTH_PISMILE_ISSUER", "http://localhost:8080")
    const provider = Pismile()
    expect(provider.clientId).toBe("env-id")
    expect(provider.clientSecret).toBe("env-secret")
    expect(provider.issuer).toBe("http://localhost:8080")
  })

  it("utilise https://pismile.com par défaut", () => {
    expect(Pismile().issuer).toBe("https://pismile.com")
  })

  it("ajoute scope, max_age et prompt", () => {
    const provider = Pismile({ scope: "openid profile address", maxAge: 300, prompt: "login" })
    expect(provider.authorization).toEqual({
      params: { scope: "openid profile address", max_age: "300", prompt: "login" },
    })
  })

  it("refuse un maxAge invalide", () => {
    expect(() => Pismile({ maxAge: -1 })).toThrow(TypeError)
    expect(() => Pismile({ maxAge: 1.5 })).toThrow(TypeError)
  })

  it("mappe le profil sur l'utilisateur Auth.js (id = sub, pas d'e-mail)", async () => {
    const user = await Pismile().profile!({ sub: "abc", name: "AWA MENSAH" } as any, {} as any)
    expect(user).toEqual({ id: "abc", name: "AWA MENSAH", email: null, image: null })
  })
})

describe("pismileCallbacks", () => {
  const profile = { sub: "abc", name: "AWA MENSAH", pismile_country: "TG", pismile_category: "P", auth_time: 1760781600 }

  it("jwt recopie sub et les claims pismile à la connexion", () => {
    const token = pismileCallbacks.jwt({
      token: {},
      user: { id: "abc" },
      account: { provider: "pismile", type: "oidc", providerAccountId: "abc" },
      profile,
    } as any)
    expect(token).toEqual({ sub: "abc", pismile: { country: "TG", category: "P", authTime: 1760781600 } })
  })

  it("jwt ignore les autres fournisseurs", () => {
    const token = pismileCallbacks.jwt({
      token: { sub: "google-1" },
      user: { id: "g" },
      account: { provider: "google", type: "oidc", providerAccountId: "g" },
      profile: { sub: "g" },
    } as any)
    expect(token).toEqual({ sub: "google-1" })
  })

  it("session expose id et pismile", () => {
    const session = pismileCallbacks.session({
      session: { user: { name: "AWA MENSAH" }, expires: "2099-01-01" },
      token: { sub: "abc", pismile: { country: "TG", category: "P", authTime: 1 } },
    } as any)
    expect(session.user).toEqual({ name: "AWA MENSAH", id: "abc", pismile: { country: "TG", category: "P", authTime: 1 } })
  })

  it("pismileClaims se replie sur address.country", () => {
    expect(pismileClaims({ sub: "x", address: { country: "SN" } })).toEqual({ country: "SN", category: null, authTime: null })
  })
})

describe("isRecentlyVerified", () => {
  it("compare auth_time à la durée demandée", () => {
    const now = 1_000_000_000_000
    const user = { pismile: { country: "TG", category: "P" as const, authTime: now / 1000 - 120 } }
    expect(isRecentlyVerified(user, 300, now)).toBe(true)
    expect(isRecentlyVerified(user, 60, now)).toBe(false)
    expect(isRecentlyVerified(null, 300, now)).toBe(false)
  })
})

describe("intégration avec @auth/core", () => {
  it("redirige vers l'endpoint d'autorisation pismile avec PKCE, state, nonce et max_age", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input instanceof Request ? input.url : input)
      if (url === ISSUER + "/.well-known/openid-configuration") {
        return Response.json({
          issuer: ISSUER,
          authorization_endpoint: ISSUER + "/oauth2/authorize",
          token_endpoint: ISSUER + "/oauth2/token",
          jwks_uri: ISSUER + "/oauth2/jwks",
          userinfo_endpoint: ISSUER + "/userinfo",
          response_types_supported: ["code"],
          subject_types_supported: ["pairwise"],
          id_token_signing_alg_values_supported: ["RS256"],
        })
      }
      return new Response("not found", { status: 404 })
    }))

    const response = await Auth(
      new Request("http://localhost:3000/api/auth/signin/pismile", { method: "POST" }),
      {
        providers: [Pismile({ clientId: "client-123", clientSecret: "secret", issuer: ISSUER, maxAge: 300 })],
        secret: "a-very-long-test-secret-for-auth-js-0123456789",
        trustHost: true,
        basePath: "/api/auth",
        skipCSRFCheck,
      },
    )

    expect(response.status).toBe(302)
    const location = new URL(response.headers.get("location")!)
    expect(location.origin + location.pathname).toBe(ISSUER + "/oauth2/authorize")
    expect(location.searchParams.get("client_id")).toBe("client-123")
    expect(location.searchParams.get("response_type")).toBe("code")
    expect(location.searchParams.get("scope")).toBe("openid profile")
    expect(location.searchParams.get("max_age")).toBe("300")
    expect(location.searchParams.get("code_challenge_method")).toBe("S256")
    expect(location.searchParams.get("code_challenge")).toBeTruthy()
    expect(location.searchParams.get("state")).toBeTruthy()
    expect(location.searchParams.get("nonce")).toBeTruthy()
    expect(location.searchParams.get("redirect_uri")).toBe("http://localhost:3000/api/auth/callback/pismile")
  })
})
