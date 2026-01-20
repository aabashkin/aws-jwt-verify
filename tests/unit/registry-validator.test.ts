import {
  validateRegistry,
  RegistryValidationError,
} from "../../src/registry-validator";
import { readFileSync } from "fs";
import { join } from "path";

describe("unit tests registry validator", () => {
  const fixturesDir = join(__dirname, "../../fixtures/registries");

  function loadFixture(filename: string): unknown {
    const content = readFileSync(join(fixturesDir, filename), "utf-8");
    return JSON.parse(content);
  }

  describe("golden registry", () => {
    test("validates successfully", () => {
      const registry = loadFixture("golden-registry.json");
      expect(() => validateRegistry(registry)).not.toThrow();
    });

    test("has expected structure", () => {
      const registry = loadFixture("golden-registry.json");
      const validated = validateRegistry(registry);
      expect(validated.version).toBe(1);
      expect(validated.issuers.length).toBe(3);
      expect(validated.defaults.clockSkewSeconds).toBe(30);
      expect(validated.defaults.maxTokenAgeSeconds).toBe(900);
    });
  });

  describe("registry-level validation", () => {
    test("rejects non-object registry", () => {
      expect(() => validateRegistry(null)).toThrow(RegistryValidationError);
      expect(() => validateRegistry("not an object")).toThrow(
        RegistryValidationError
      );
      expect(() => validateRegistry(123)).toThrow(RegistryValidationError);
    });

    test("rejects unsupported version", () => {
      expect(() =>
        validateRegistry({
          version: 2,
          defaults: {
            clockSkewSeconds: 30,
            maxTokenAgeSeconds: 900,
            requiredClaims: ["iss", "aud", "sub", "exp", "iat"],
          },
          issuers: [],
        })
      ).toThrow(/version must be 1/);
    });

    test("rejects missing defaults", () => {
      expect(() =>
        validateRegistry({
          version: 1,
          issuers: [],
        })
      ).toThrow(/must have defaults/);
    });

    test("rejects missing issuers", () => {
      expect(() =>
        validateRegistry({
          version: 1,
          defaults: {
            clockSkewSeconds: 30,
            maxTokenAgeSeconds: 900,
            requiredClaims: ["iss", "aud", "sub", "exp", "iat"],
          },
        })
      ).toThrow(/must have issuers array/);
    });

    test("rejects empty issuers array (non-dev)", () => {
      expect(() =>
        validateRegistry({
          version: 1,
          defaults: {
            clockSkewSeconds: 30,
            maxTokenAgeSeconds: 900,
            requiredClaims: ["iss", "aud", "sub", "exp", "iat"],
          },
          issuers: [],
        })
      ).toThrow(/at least one issuer/);
    });

    test("rejects duplicate issuer URLs", () => {
      expect(() =>
        validateRegistry({
          version: 1,
          defaults: {
            clockSkewSeconds: 30,
            maxTokenAgeSeconds: 900,
            requiredClaims: ["iss", "aud", "sub", "exp", "iat"],
          },
          issuers: [
            {
              name: "issuer1",
              issuer: "https://auth.example.com/",
              jwksUri: "https://auth.example.com/.well-known/jwks.json",
              audiences: ["api"],
              allowedAlgs: ["RS256"],
            },
            {
              name: "issuer2",
              issuer: "https://auth.example.com/",
              jwksUri: "https://auth.example.com/.well-known/jwks.json",
              audiences: ["api"],
              allowedAlgs: ["RS256"],
            },
          ],
        })
      ).toThrow(/Duplicate issuer URL/);
    });

    test("rejects duplicate issuer names", () => {
      expect(() =>
        validateRegistry({
          version: 1,
          defaults: {
            clockSkewSeconds: 30,
            maxTokenAgeSeconds: 900,
            requiredClaims: ["iss", "aud", "sub", "exp", "iat"],
          },
          issuers: [
            {
              name: "duplicate",
              issuer: "https://auth1.example.com/",
              jwksUri: "https://auth1.example.com/.well-known/jwks.json",
              audiences: ["api"],
              allowedAlgs: ["RS256"],
            },
            {
              name: "duplicate",
              issuer: "https://auth2.example.com/",
              jwksUri: "https://auth2.example.com/.well-known/jwks.json",
              audiences: ["api"],
              allowedAlgs: ["RS256"],
            },
          ],
        })
      ).toThrow(/Duplicate issuer name/);
    });
  });

  describe("defaults validation", () => {
    test("rejects invalid clockSkewSeconds", () => {
      expect(() =>
        validateRegistry({
          version: 1,
          defaults: {
            clockSkewSeconds: -1,
            maxTokenAgeSeconds: 900,
            requiredClaims: ["iss", "aud", "sub", "exp", "iat"],
          },
          issuers: [
            {
              name: "test",
              issuer: "https://auth.example.com/",
              jwksUri: "https://auth.example.com/.well-known/jwks.json",
              audiences: ["api"],
              allowedAlgs: ["RS256"],
            },
          ],
        })
      ).toThrow(/clockSkewSeconds must be between 0 and 60/);

      const badSkew = loadFixture("bad-skew-too-large.json");
      expect(() => validateRegistry(badSkew)).toThrow(
        /clockSkewSeconds must be between 0 and 60/
      );
    });

    test("rejects invalid maxTokenAgeSeconds", () => {
      expect(() =>
        validateRegistry({
          version: 1,
          defaults: {
            clockSkewSeconds: 30,
            maxTokenAgeSeconds: 30,
            requiredClaims: ["iss", "aud", "sub", "exp", "iat"],
          },
          issuers: [
            {
              name: "test",
              issuer: "https://auth.example.com/",
              jwksUri: "https://auth.example.com/.well-known/jwks.json",
              audiences: ["api"],
              allowedAlgs: ["RS256"],
            },
          ],
        })
      ).toThrow(/maxTokenAgeSeconds must be between 60 and 3600/);
    });

    test("rejects missing exp in requiredClaims", () => {
      const badExp = loadFixture("bad-missing-exp.json");
      expect(() => validateRegistry(badExp)).toThrow(
        /requiredClaims must include 'exp'/
      );
    });

    test("rejects missing iat in requiredClaims", () => {
      const badIat = loadFixture("bad-missing-iat.json");
      expect(() => validateRegistry(badIat)).toThrow(
        /requiredClaims must include 'iat'/
      );
    });
  });

  describe("issuer validation", () => {
    test("rejects non-https issuer URL", () => {
      expect(() =>
        validateRegistry({
          version: 1,
          defaults: {
            clockSkewSeconds: 30,
            maxTokenAgeSeconds: 900,
            requiredClaims: ["iss", "aud", "sub", "exp", "iat"],
          },
          issuers: [
            {
              name: "test",
              issuer: "http://auth.example.com/",
              jwksUri: "https://auth.example.com/.well-known/jwks.json",
              audiences: ["api"],
              allowedAlgs: ["RS256"],
            },
          ],
        })
      ).toThrow(/must use https protocol/);
    });

    test("rejects null issuer (skip checks not allowed)", () => {
      expect(() =>
        validateRegistry({
          version: 1,
          defaults: {
            clockSkewSeconds: 30,
            maxTokenAgeSeconds: 900,
            requiredClaims: ["iss", "aud", "sub", "exp", "iat"],
          },
          issuers: [
            {
              name: "test",
              issuer: null,
              jwksUri: "https://auth.example.com/.well-known/jwks.json",
              audiences: ["api"],
              allowedAlgs: ["RS256"],
            },
          ],
        })
      ).toThrow(/cannot be null.*skip checks not allowed/);
    });

    test("rejects non-https jwksUri", () => {
      const badJwksUri = loadFixture("bad-non-https-jwksUri.json");
      expect(() => validateRegistry(badJwksUri)).toThrow(
        /jwksUri must use https protocol/
      );
    });

    test("rejects missing jwksUri (no discovery)", () => {
      expect(() =>
        validateRegistry({
          version: 1,
          defaults: {
            clockSkewSeconds: 30,
            maxTokenAgeSeconds: 900,
            requiredClaims: ["iss", "aud", "sub", "exp", "iat"],
          },
          issuers: [
            {
              name: "test",
              issuer: "https://auth.example.com/",
              audiences: ["api"],
              allowedAlgs: ["RS256"],
            },
          ],
        })
      ).toThrow(/jwksUri must be explicitly provided/);
    });

    test("rejects empty audiences", () => {
      const badAudiences = loadFixture("bad-empty-audiences.json");
      expect(() => validateRegistry(badAudiences)).toThrow(
        /audiences must be a non-empty array/
      );
    });

    test("rejects null in audiences (skip checks not allowed)", () => {
      expect(() =>
        validateRegistry({
          version: 1,
          defaults: {
            clockSkewSeconds: 30,
            maxTokenAgeSeconds: 900,
            requiredClaims: ["iss", "aud", "sub", "exp", "iat"],
          },
          issuers: [
            {
              name: "test",
              issuer: "https://auth.example.com/",
              jwksUri: "https://auth.example.com/.well-known/jwks.json",
              audiences: [null],
              allowedAlgs: ["RS256"],
            },
          ],
        })
      ).toThrow(/audiences cannot include null/);
    });

    test("rejects multiple algorithms", () => {
      const badMultiAlg = loadFixture("bad-multi-alg.json");
      expect(() => validateRegistry(badMultiAlg)).toThrow(
        /must have exactly one allowedAlg/
      );
    });

    test("rejects symmetric algorithm (HS256)", () => {
      expect(() =>
        validateRegistry({
          version: 1,
          defaults: {
            clockSkewSeconds: 30,
            maxTokenAgeSeconds: 900,
            requiredClaims: ["iss", "aud", "sub", "exp", "iat"],
          },
          issuers: [
            {
              name: "test",
              issuer: "https://auth.example.com/",
              jwksUri: "https://auth.example.com/.well-known/jwks.json",
              audiences: ["api"],
              allowedAlgs: ["HS256"],
            },
          ],
        })
      ).toThrow(/symmetric algorithm.*not allowed/);
    });

    test("rejects unsupported algorithm", () => {
      expect(() =>
        validateRegistry({
          version: 1,
          defaults: {
            clockSkewSeconds: 30,
            maxTokenAgeSeconds: 900,
            requiredClaims: ["iss", "aud", "sub", "exp", "iat"],
          },
          issuers: [
            {
              name: "test",
              issuer: "https://auth.example.com/",
              jwksUri: "https://auth.example.com/.well-known/jwks.json",
              audiences: ["api"],
              allowedAlgs: ["PS256"],
            },
          ],
        })
      ).toThrow(/not in supported list/);
    });

    test("validates all supported asymmetric algorithms", () => {
      const algorithms = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"];
      
      for (const alg of algorithms) {
        expect(() =>
          validateRegistry({
            version: 1,
            defaults: {
              clockSkewSeconds: 30,
              maxTokenAgeSeconds: 900,
              requiredClaims: ["iss", "aud", "sub", "exp", "iat"],
            },
            issuers: [
              {
                name: "test",
                issuer: "https://auth.example.com/",
                jwksUri: "https://auth.example.com/.well-known/jwks.json",
                audiences: ["api"],
                allowedAlgs: [alg],
              },
            ],
          })
        ).not.toThrow();
      }
    });

    test("rejects oversized audiences array", () => {
      const largeAudiences = Array.from({ length: 101 }, (_, i) => `aud${i}`);
      expect(() =>
        validateRegistry({
          version: 1,
          defaults: {
            clockSkewSeconds: 30,
            maxTokenAgeSeconds: 900,
            requiredClaims: ["iss", "aud", "sub", "exp", "iat"],
          },
          issuers: [
            {
              name: "test",
              issuer: "https://auth.example.com/",
              jwksUri: "https://auth.example.com/.well-known/jwks.json",
              audiences: largeAudiences,
              allowedAlgs: ["RS256"],
            },
          ],
        })
      ).toThrow(/audiences array too large/);
    });
  });
});
