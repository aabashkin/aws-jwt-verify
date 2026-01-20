import {
  SecureJwtVerifier,
  SecureJwtVerificationError,
} from "../../src/secure-jwt-verifier";
import {
  generateKeyPair,
  mockHttpsUri,
  signJwt,
  allowAllRealNetworkTraffic,
  disallowAllRealNetworkTraffic,
} from "./test-util";
import { readFileSync } from "fs";
import { join } from "path";
import { Metrics, Logger } from "../../src/secure-verifier-types";

describe("unit tests secure JWT verifier", () => {
  let keypair: ReturnType<typeof generateKeyPair>;
  let es256keypair: ReturnType<typeof generateKeyPair>;
  let edDsaKeypair: ReturnType<typeof generateKeyPair>;

  beforeAll(() => {
    keypair = generateKeyPair({ kty: "RSA", alg: "RS256" });
    es256keypair = generateKeyPair({ kty: "EC", alg: "ES256" });
    edDsaKeypair = generateKeyPair({ kty: "OKP", alg: "EdDSA", crv: "Ed25519" });
    disallowAllRealNetworkTraffic();
  });

  afterAll(() => {
    allowAllRealNetworkTraffic();
  });

  const fixturesDir = join(__dirname, "../../fixtures/registries");

  function loadFixture(filename: string): unknown {
    const content = readFileSync(join(fixturesDir, filename), "utf-8");
    return JSON.parse(content);
  }

  describe("construction and initialization", () => {
    test("accepts valid golden registry", () => {
      const registry = loadFixture("golden-registry.json");
      expect(() => new SecureJwtVerifier(registry)).not.toThrow();
    });

    test("rejects invalid registry", () => {
      const badRegistry = loadFixture("bad-empty-audiences.json");
      expect(() => new SecureJwtVerifier(badRegistry)).toThrow();
    });

    test("increments success metric on valid registry", () => {
      const metrics: Metrics = {
        incrementCounter: jest.fn(),
        recordHistogram: jest.fn(),
      };

      const registry = loadFixture("golden-registry.json");
      new SecureJwtVerifier(registry, { metrics });

      expect(metrics.incrementCounter).toHaveBeenCalledWith(
        "jwt_policy_registry_lint_total",
        { result: "success" }
      );
    });

    test("increments failure metric on invalid registry", () => {
      const metrics: Metrics = {
        incrementCounter: jest.fn(),
        recordHistogram: jest.fn(),
      };

      const badRegistry = loadFixture("bad-empty-audiences.json");
      expect(() => new SecureJwtVerifier(badRegistry, { metrics })).toThrow();

      expect(metrics.incrementCounter).toHaveBeenCalledWith(
        "jwt_policy_registry_lint_total",
        { result: "failure" }
      );
    });

    test("logs validation results", () => {
      const logger: Logger = {
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
      };

      const registry = loadFixture("golden-registry.json");
      new SecureJwtVerifier(registry, { logger });

      expect(logger.info).toHaveBeenCalledWith(
        "Registry validated successfully",
        expect.objectContaining({ issuerCount: 3 })
      );
    });
  });

  describe("verify - happy path", () => {
    test("verifies valid RS256 JWT", async () => {
      const issuer = "https://auth.prod.example.com/";
      const audience = "ptp-api";
      const now = Math.floor(Date.now() / 1000);

      const jwt = signJwt(
        { kid: keypair.jwk.kid, alg: "RS256" },
        {
          iss: issuer,
          aud: audience,
          sub: "user123",
          exp: now + 3600,
          iat: now,
          hello: "world",
        },
        keypair.privateKey
      );

      mockHttpsUri(
        "https://auth.prod.example.com/.well-known/jwks.json",
        { responsePayload: JSON.stringify({ keys: [keypair.jwk] }) }
      );

      const registry = loadFixture("golden-registry.json");
      const verifier = new SecureJwtVerifier(registry);

      const result = await verifier.verify(jwt);

      expect(result.issuerName).toBe("ptp-prod");
      expect(result.payload).toMatchObject({
        iss: issuer,
        aud: audience,
        sub: "user123",
        hello: "world",
      });
    });

    test("verifies valid ES256 JWT for staging issuer", async () => {
      const issuer = "https://auth.staging.example.com/";
      const audience = "ptp-api";
      const now = Math.floor(Date.now() / 1000);

      const jwt = signJwt(
        { kid: es256keypair.jwk.kid, alg: "ES256" },
        {
          iss: issuer,
          aud: audience,
          sub: "user456",
          exp: now + 3600,
          iat: now,
        },
        es256keypair.privateKey
      );

      mockHttpsUri(
        "https://auth.staging.example.com/.well-known/jwks.json",
        { responsePayload: JSON.stringify({ keys: [es256keypair.jwk] }) }
      );

      const registry = loadFixture("golden-registry.json");
      const verifier = new SecureJwtVerifier(registry);

      const result = await verifier.verify(jwt);

      expect(result.issuerName).toBe("ptp-staging");
      expect(result.payload.sub).toBe("user456");
    });

    test("verifies JWT with multiple audiences (array)", async () => {
      const issuer = "https://auth.staging.example.com/";
      const audiences = ["ptp-api", "ptp-web"];
      const now = Math.floor(Date.now() / 1000);

      const jwt = signJwt(
        { kid: es256keypair.jwk.kid, alg: "ES256" },
        {
          iss: issuer,
          aud: audiences,
          sub: "user789",
          exp: now + 3600,
          iat: now,
        },
        es256keypair.privateKey
      );

      mockHttpsUri(
        "https://auth.staging.example.com/.well-known/jwks.json",
        { responsePayload: JSON.stringify({ keys: [es256keypair.jwk] }) }
      );

      const registry = loadFixture("golden-registry.json");
      const verifier = new SecureJwtVerifier(registry);

      const result = await verifier.verify(jwt);
      expect(result.issuerName).toBe("ptp-staging");
    });

    test("increments success metrics", async () => {
      const metrics: Metrics = {
        incrementCounter: jest.fn(),
        recordHistogram: jest.fn(),
      };

      const issuer = "https://auth.prod.example.com/";
      const audience = "ptp-api";
      const now = Math.floor(Date.now() / 1000);

      const jwt = signJwt(
        { kid: keypair.jwk.kid, alg: "RS256" },
        { iss: issuer, aud: audience, sub: "user", exp: now + 3600, iat: now },
        keypair.privateKey
      );

      mockHttpsUri(
        "https://auth.prod.example.com/.well-known/jwks.json",
        { responsePayload: JSON.stringify({ keys: [keypair.jwk] }) }
      );

      const registry = loadFixture("golden-registry.json");
      const verifier = new SecureJwtVerifier(registry, { metrics });

      await verifier.verify(jwt);

      expect(metrics.incrementCounter).toHaveBeenCalledWith(
        "jwt_verify_success_total",
        { issuer_name: "ptp-prod" }
      );
      expect(metrics.recordHistogram).toHaveBeenCalledWith(
        "jwt_verify_duration_seconds",
        expect.any(Number),
        expect.objectContaining({ issuer_name: "ptp-prod" })
      );
    });
  });

  describe("verify - error cases", () => {
    test("rejects JWT with invalid structure", async () => {
      const registry = loadFixture("golden-registry.json");
      const verifier = new SecureJwtVerifier(registry);

      await expect(verifier.verify("invalid.jwt")).rejects.toThrow(
        SecureJwtVerificationError
      );

      await expect(verifier.verify("invalid.jwt")).rejects.toMatchObject({
        reason: "invalid_structure",
      });
    });

    test("rejects JWT with unknown issuer", async () => {
      const issuer = "https://unknown.example.com/";
      const now = Math.floor(Date.now() / 1000);

      const jwt = signJwt(
        { kid: keypair.jwk.kid, alg: "RS256" },
        {
          iss: issuer,
          aud: "test",
          sub: "user",
          exp: now + 3600,
          iat: now,
        },
        keypair.privateKey
      );

      const registry = loadFixture("golden-registry.json");
      const verifier = new SecureJwtVerifier(registry);

      await expect(verifier.verify(jwt)).rejects.toMatchObject({
        reason: "issuer_mismatch",
      });
    });

    test("rejects JWT with wrong algorithm", async () => {
      const issuer = "https://auth.prod.example.com/";
      const audience = "ptp-api";
      const now = Math.floor(Date.now() / 1000);

      // Try to use ES256 for an issuer that expects RS256
      const jwt = signJwt(
        { kid: es256keypair.jwk.kid, alg: "ES256" },
        {
          iss: issuer,
          aud: audience,
          sub: "user",
          exp: now + 3600,
          iat: now,
        },
        es256keypair.privateKey
      );

      const registry = loadFixture("golden-registry.json");
      const verifier = new SecureJwtVerifier(registry);

      await expect(verifier.verify(jwt)).rejects.toMatchObject({
        reason: "alg_not_allowed",
        issuerName: "ptp-prod",
      });
    });

    test("rejects JWT with wrong audience", async () => {
      const issuer = "https://auth.prod.example.com/";
      const wrongAudience = "wrong-api";
      const now = Math.floor(Date.now() / 1000);

      const jwt = signJwt(
        { kid: keypair.jwk.kid, alg: "RS256" },
        {
          iss: issuer,
          aud: wrongAudience,
          sub: "user",
          exp: now + 3600,
          iat: now,
        },
        keypair.privateKey
      );

      mockHttpsUri(
        "https://auth.prod.example.com/.well-known/jwks.json",
        { responsePayload: JSON.stringify({ keys: [keypair.jwk] }) }
      );

      const registry = loadFixture("golden-registry.json");
      const verifier = new SecureJwtVerifier(registry);

      await expect(verifier.verify(jwt)).rejects.toMatchObject({
        reason: "audience_mismatch",
        issuerName: "ptp-prod",
      });
    });

    test("rejects expired JWT", async () => {
      const issuer = "https://auth.prod.example.com/";
      const audience = "ptp-api";
      const now = Math.floor(Date.now() / 1000);

      const jwt = signJwt(
        { kid: keypair.jwk.kid, alg: "RS256" },
        {
          iss: issuer,
          aud: audience,
          sub: "user",
          exp: now - 3600, // Expired 1 hour ago
          iat: now - 7200,
        },
        keypair.privateKey
      );

      mockHttpsUri(
        "https://auth.prod.example.com/.well-known/jwks.json",
        { responsePayload: JSON.stringify({ keys: [keypair.jwk] }) }
      );

      const registry = loadFixture("golden-registry.json");
      const verifier = new SecureJwtVerifier(registry);

      await expect(verifier.verify(jwt)).rejects.toMatchObject({
        reason: "expired",
        issuerName: "ptp-prod",
      });
    });

    test("rejects JWT that is not yet valid (nbf)", async () => {
      const issuer = "https://auth.prod.example.com/";
      const audience = "ptp-api";
      const now = Math.floor(Date.now() / 1000);

      const jwt = signJwt(
        { kid: keypair.jwk.kid, alg: "RS256" },
        {
          iss: issuer,
          aud: audience,
          sub: "user",
          exp: now + 7200,
          iat: now,
          nbf: now + 3600, // Not valid for another hour
        },
        keypair.privateKey
      );

      mockHttpsUri(
        "https://auth.prod.example.com/.well-known/jwks.json",
        { responsePayload: JSON.stringify({ keys: [keypair.jwk] }) }
      );

      const registry = loadFixture("golden-registry.json");
      const verifier = new SecureJwtVerifier(registry);

      await expect(verifier.verify(jwt)).rejects.toMatchObject({
        reason: "not_yet_valid",
        issuerName: "ptp-prod",
      });
    });

    test("rejects JWT missing required claims", async () => {
      const issuer = "https://auth.prod.example.com/";
      const audience = "ptp-api";
      const now = Math.floor(Date.now() / 1000);

      const jwt = signJwt(
        { kid: keypair.jwk.kid, alg: "RS256" },
        {
          iss: issuer,
          aud: audience,
          // Missing sub claim
          exp: now + 3600,
          iat: now,
        },
        keypair.privateKey
      );

      mockHttpsUri(
        "https://auth.prod.example.com/.well-known/jwks.json",
        { responsePayload: JSON.stringify({ keys: [keypair.jwk] }) }
      );

      const registry = loadFixture("golden-registry.json");
      const verifier = new SecureJwtVerifier(registry);

      await expect(verifier.verify(jwt)).rejects.toMatchObject({
        reason: "missing_required_claim",
        issuerName: "ptp-prod",
      });
    });

    test("rejects JWT missing iat claim", async () => {
      const issuer = "https://auth.prod.example.com/";
      const audience = "ptp-api";
      const now = Math.floor(Date.now() / 1000);

      const jwt = signJwt(
        { kid: keypair.jwk.kid, alg: "RS256" },
        {
          iss: issuer,
          aud: audience,
          sub: "user",
          exp: now + 3600,
          // Missing iat
        },
        keypair.privateKey
      );

      mockHttpsUri(
        "https://auth.prod.example.com/.well-known/jwks.json",
        { responsePayload: JSON.stringify({ keys: [keypair.jwk] }) }
      );

      const registry = loadFixture("golden-registry.json");
      const verifier = new SecureJwtVerifier(registry);

      await expect(verifier.verify(jwt)).rejects.toMatchObject({
        reason: "missing_required_claim",
        issuerName: "ptp-prod",
      });
    });

    test("rejects JWT that exceeds maxTokenAgeSeconds", async () => {
      const issuer = "https://auth.prod.example.com/";
      const audience = "ptp-api";
      const now = Math.floor(Date.now() / 1000);

      const jwt = signJwt(
        { kid: keypair.jwk.kid, alg: "RS256" },
        {
          iss: issuer,
          aud: audience,
          sub: "user",
          exp: now + 3600,
          iat: now - 1000, // Issued 1000 seconds ago (> 900s max)
        },
        keypair.privateKey
      );

      mockHttpsUri(
        "https://auth.prod.example.com/.well-known/jwks.json",
        { responsePayload: JSON.stringify({ keys: [keypair.jwk] }) }
      );

      const registry = loadFixture("golden-registry.json");
      const verifier = new SecureJwtVerifier(registry);

      await expect(verifier.verify(jwt)).rejects.toMatchObject({
        reason: "token_too_old",
        issuerName: "ptp-prod",
      });
    });

    test("increments failure metrics", async () => {
      const metrics: Metrics = {
        incrementCounter: jest.fn(),
        recordHistogram: jest.fn(),
      };

      const registry = loadFixture("golden-registry.json");
      const verifier = new SecureJwtVerifier(registry, { metrics });

      await expect(verifier.verify("invalid.jwt")).rejects.toThrow();

      expect(metrics.incrementCounter).toHaveBeenCalledWith(
        "jwt_verify_failure_total",
        expect.objectContaining({ reason: "invalid_structure" })
      );
    });

    test("logs verification failures", async () => {
      const logger: Logger = {
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
      };

      const registry = loadFixture("golden-registry.json");
      const verifier = new SecureJwtVerifier(registry, { logger });

      await expect(verifier.verify("invalid.jwt")).rejects.toThrow();

      expect(logger.error).toHaveBeenCalledWith(
        "JWT verification failed",
        expect.objectContaining({ reason: "invalid_structure" })
      );
    });
  });

  describe("warm", () => {
    test("hydrates JWKS for all issuers", async () => {
      mockHttpsUri(
        "https://auth.prod.example.com/.well-known/jwks.json",
        { responsePayload: JSON.stringify({ keys: [keypair.jwk] }) }
      );
      mockHttpsUri(
        "https://auth.staging.example.com/.well-known/jwks.json",
        { responsePayload: JSON.stringify({ keys: [es256keypair.jwk] }) }
      );
      mockHttpsUri(
        "https://sso.partner.example.org/oauth2/jwks",
        { responsePayload: JSON.stringify({ keys: [edDsaKeypair.jwk] }) }
      );

      const registry = loadFixture("golden-registry.json");
      const verifier = new SecureJwtVerifier(registry);

      await expect(verifier.warm()).resolves.not.toThrow();
    });

    test("increments hydrate success metrics", async () => {
      const metrics: Metrics = {
        incrementCounter: jest.fn(),
        recordHistogram: jest.fn(),
      };

      mockHttpsUri(
        "https://auth.prod.example.com/.well-known/jwks.json",
        { responsePayload: JSON.stringify({ keys: [keypair.jwk] }) }
      );
      mockHttpsUri(
        "https://auth.staging.example.com/.well-known/jwks.json",
        { responsePayload: JSON.stringify({ keys: [es256keypair.jwk] }) }
      );
      mockHttpsUri(
        "https://sso.partner.example.org/oauth2/jwks",
        { responsePayload: JSON.stringify({ keys: [edDsaKeypair.jwk] }) }
      );

      const registry = loadFixture("golden-registry.json");
      const verifier = new SecureJwtVerifier(registry, { metrics });

      await verifier.warm();

      expect(metrics.incrementCounter).toHaveBeenCalledWith(
        "jwks_hydrate_total",
        expect.objectContaining({ result: "success" })
      );
    });

    test("logs hydration progress", async () => {
      const logger: Logger = {
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
      };

      mockHttpsUri(
        "https://auth.prod.example.com/.well-known/jwks.json",
        { responsePayload: JSON.stringify({ keys: [keypair.jwk] }) }
      );
      mockHttpsUri(
        "https://auth.staging.example.com/.well-known/jwks.json",
        { responsePayload: JSON.stringify({ keys: [es256keypair.jwk] }) }
      );
      mockHttpsUri(
        "https://sso.partner.example.org/oauth2/jwks",
        { responsePayload: JSON.stringify({ keys: [edDsaKeypair.jwk] }) }
      );

      const registry = loadFixture("golden-registry.json");
      const verifier = new SecureJwtVerifier(registry, { logger });

      await verifier.warm();

      expect(logger.info).toHaveBeenCalledWith(
        "Starting JWKS warmup",
        expect.objectContaining({ issuerCount: 3 })
      );
      expect(logger.info).toHaveBeenCalledWith(
        "JWKS warmup completed",
        expect.any(Object)
      );
    });
  });

  describe("error taxonomy contract", () => {
    test("all error reasons are stable strings", async () => {
      const registry = loadFixture("golden-registry.json");
      const verifier = new SecureJwtVerifier(registry);

      const validReasons = [
        "invalid_structure",
        "invalid_signature",
        "issuer_mismatch",
        "audience_mismatch",
        "expired",
        "not_yet_valid",
        "alg_not_allowed",
        "kid_not_found",
        "jwks_fetch_rate_limited",
        "jwks_fetch_failed",
        "policy_violation",
        "missing_required_claim",
        "token_too_old",
      ];

      try {
        await verifier.verify("invalid");
      } catch (error) {
        if (error instanceof SecureJwtVerificationError) {
          expect(validReasons).toContain(error.reason);
        }
      }
    });
  });
});
