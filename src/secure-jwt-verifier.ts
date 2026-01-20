// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  PolicyRegistry,
  IssuerPolicy,
  VerifiedToken,
  VerificationErrorReason,
  Metrics,
  Logger,
} from "./secure-verifier-types.js";
import { validateRegistry } from "./registry-validator.js";
import {
  JwtVerifier,
  JwtVerifierSingleIssuer,
  JwtVerifierProperties,
  VerifyProperties,
} from "./jwt-verifier.js";
import {
  JwtBaseError,
  JwtExpiredError,
  JwtInvalidAudienceError,
  JwtInvalidIssuerError,
  JwtInvalidSignatureAlgorithmError,
  JwtInvalidSignatureError,
  JwtNotBeforeError,
  JwtParseError,
  KidNotFoundInJwksError,
  WaitPeriodNotYetEndedJwkError,
} from "./error.js";
import { JwtPayload } from "./jwt-model.js";

/**
 * Secure JWT verification error with stable error taxonomy
 */
export class SecureJwtVerificationError extends Error {
  constructor(
    message: string,
    public readonly reason: VerificationErrorReason,
    public readonly issuerName?: string
  ) {
    super(message);
    this.name = "SecureJwtVerificationError";
  }
}

/**
 * No-op implementations for optional metrics/logger
 */
const noopMetrics: Metrics = {
  incrementCounter: () => {},
  recordHistogram: () => {},
};

const noopLogger: Logger = {
  info: () => {},
  warn: () => {},
  error: () => {},
};

/**
 * Secure JWT Verifier Wrapper
 * 
 * Provides secure-by-default JWT verification with:
 * - Policy-driven configuration (no runtime overrides)
 * - Fail-closed behavior
 * - Bounded JWKS refresh
 * - Algorithm pinning per issuer
 * - Max token age enforcement
 */
export class SecureJwtVerifier {
  private registry: PolicyRegistry;
  private verifiers: Map<
    string,
    JwtVerifierSingleIssuer<JwtVerifierProperties<VerifyProperties>>
  > = new Map();
  private issuersByUrl: Map<string, IssuerPolicy> = new Map();
  private metrics: Metrics;
  private logger: Logger;

  /**
   * Create a new SecureJwtVerifier
   * @param registry - Policy registry (will be validated on construction)
   * @param options - Optional metrics and logger
   */
  constructor(
    registry: unknown,
    options?: {
      metrics?: Metrics;
      logger?: Logger;
    }
  ) {
    this.metrics = options?.metrics || noopMetrics;
    this.logger = options?.logger || noopLogger;

    // Validate and store registry
    try {
      this.registry = validateRegistry(registry);
      this.metrics.incrementCounter("jwt_policy_registry_lint_total", {
        result: "success",
      });
      this.logger.info("Registry validated successfully", {
        issuerCount: this.registry.issuers.length,
      });
    } catch (error) {
      this.metrics.incrementCounter("jwt_policy_registry_lint_total", {
        result: "failure",
      });
      this.logger.error("Registry validation failed", {
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }

    // Create verifiers for each issuer
    for (const issuerPolicy of this.registry.issuers) {
      const verifier = JwtVerifier.create({
        issuer: issuerPolicy.issuer,
        jwksUri: issuerPolicy.jwksUri,
        audience: null, // We'll validate audience ourselves
      });

      this.verifiers.set(issuerPolicy.name, verifier);
      this.issuersByUrl.set(issuerPolicy.issuer, issuerPolicy);
    }
  }

  /**
   * Warm JWKS cache by hydrating all issuers
   * Call this during startup/readiness phase
   */
  async warm(): Promise<void> {
    const startTime = Date.now();
    this.logger.info("Starting JWKS warmup", {
      issuerCount: this.registry.issuers.length,
    });

    const results = await Promise.allSettled(
      Array.from(this.verifiers.entries()).map(
        async ([issuerName, verifier]) => {
          const issuerStart = Date.now();
          try {
            await verifier.hydrate();
            const duration = (Date.now() - issuerStart) / 1000;
            this.metrics.incrementCounter("jwks_hydrate_total", {
              issuer_name: issuerName,
              result: "success",
            });
            this.logger.info("JWKS hydration succeeded", {
              issuer_name: issuerName,
              duration_seconds: duration,
            });
            return { issuerName, success: true };
          } catch (error) {
            const duration = (Date.now() - issuerStart) / 1000;
            this.metrics.incrementCounter("jwks_hydrate_total", {
              issuer_name: issuerName,
              result: "failure",
            });
            this.logger.error("JWKS hydration failed", {
              issuer_name: issuerName,
              duration_seconds: duration,
              error: error instanceof Error ? error.message : String(error),
            });
            throw error;
          }
        }
      )
    );

    const failures = results.filter((r) => r.status === "rejected");
    if (failures.length > 0) {
      throw new Error(
        `JWKS warmup failed for ${failures.length} issuer(s): ${failures
          .map((f) => (f as PromiseRejectedResult).reason)
          .join(", ")}`
      );
    }

    const totalDuration = (Date.now() - startTime) / 1000;
    this.logger.info("JWKS warmup completed", {
      issuerCount: this.registry.issuers.length,
      duration_seconds: totalDuration,
    });
  }

  /**
   * Verify a JWT token according to the configured policy
   * @param jwt - JWT token string
   * @returns Verified token with header, payload, and issuer name
   * @throws SecureJwtVerificationError with stable error reason
   */
  async verify(jwt: string): Promise<VerifiedToken> {
    const startTime = Date.now();
    let issuerName: string | undefined;

    try {
      // Decode JWT header to determine issuer (unverified)
      const parts = jwt.split(".");
      if (parts.length !== 3) {
        throw new SecureJwtVerificationError(
          "JWT must have 3 parts",
          "invalid_structure"
        );
      }

      let header: any;
      let unverifiedPayload: any;
      try {
        header = JSON.parse(
          Buffer.from(parts[0], "base64url").toString("utf-8")
        );
        unverifiedPayload = JSON.parse(
          Buffer.from(parts[1], "base64url").toString("utf-8")
        );
      } catch (e) {
        throw new SecureJwtVerificationError(
          "Failed to parse JWT structure",
          "invalid_structure"
        );
      }

      const issuerUrl = unverifiedPayload.iss;
      if (!issuerUrl || typeof issuerUrl !== "string") {
        throw new SecureJwtVerificationError(
          "JWT missing or invalid issuer claim",
          "issuer_mismatch"
        );
      }

      // Find issuer policy
      const issuerPolicy = this.issuersByUrl.get(issuerUrl);
      if (!issuerPolicy) {
        throw new SecureJwtVerificationError(
          `Unknown issuer: ${issuerUrl}`,
          "issuer_mismatch"
        );
      }

      issuerName = issuerPolicy.name;

      // Verify algorithm matches policy
      const alg = header.alg;
      if (alg !== issuerPolicy.allowedAlgs[0]) {
        throw new SecureJwtVerificationError(
          `Algorithm ${alg} not allowed for issuer ${issuerName} (expected ${issuerPolicy.allowedAlgs[0]})`,
          "alg_not_allowed",
          issuerName
        );
      }

      // Get the verifier for this issuer
      const verifier = this.verifiers.get(issuerName);
      if (!verifier) {
        throw new Error(`No verifier found for issuer ${issuerName}`);
      }

      // Perform signature verification
      let payload: JwtPayload;
      try {
        payload = await verifier.verify(jwt, {
          audience: null, // We validate audience separately
          graceSeconds:
            issuerPolicy.clockSkewSeconds ??
            this.registry.defaults.clockSkewSeconds,
        });
      } catch (error) {
        throw this.mapError(error, issuerName);
      }

      // Validate audience
      const audiences = issuerPolicy.audiences;
      const tokenAudience = payload.aud;

      let audienceMatches = false;
      if (typeof tokenAudience === "string") {
        audienceMatches = audiences.includes(tokenAudience);
      } else if (Array.isArray(tokenAudience)) {
        audienceMatches = tokenAudience.some((aud) => audiences.includes(aud));
      }

      if (!audienceMatches) {
        throw new SecureJwtVerificationError(
          `Audience mismatch for issuer ${issuerName}`,
          "audience_mismatch",
          issuerName
        );
      }

      // Validate required claims
      const requiredClaims =
        issuerPolicy.requiredClaims || this.registry.defaults.requiredClaims;
      for (const claim of requiredClaims) {
        if (!(claim in payload)) {
          throw new SecureJwtVerificationError(
            `Missing required claim: ${claim}`,
            "missing_required_claim",
            issuerName
          );
        }
      }

      // Validate max token age
      const maxTokenAge =
        issuerPolicy.maxTokenAgeSeconds ??
        this.registry.defaults.maxTokenAgeSeconds;
      const iat = payload.iat;
      if (typeof iat !== "number") {
        throw new SecureJwtVerificationError(
          "Missing or invalid iat claim",
          "policy_violation",
          issuerName
        );
      }

      const tokenAge = Date.now() / 1000 - iat;
      if (tokenAge > maxTokenAge) {
        throw new SecureJwtVerificationError(
          `Token too old: ${tokenAge}s > ${maxTokenAge}s`,
          "token_too_old",
          issuerName
        );
      }

      // Validate typ header if allowlist is specified
      if (issuerPolicy.deny?.headerTypAllowlist) {
        const typ = header.typ;
        if (
          typ &&
          !issuerPolicy.deny.headerTypAllowlist.includes(typ as string)
        ) {
          throw new SecureJwtVerificationError(
            `Header typ ${typ} not in allowlist`,
            "policy_violation",
            issuerName
          );
        }
      }

      const duration = (Date.now() - startTime) / 1000;
      this.metrics.incrementCounter("jwt_verify_success_total", {
        issuer_name: issuerName,
      });
      this.metrics.recordHistogram("jwt_verify_duration_seconds", duration, {
        issuer_name: issuerName,
        cache: "hit",
      });

      return {
        header,
        payload,
        issuerName,
      };
    } catch (error) {
      const duration = (Date.now() - startTime) / 1000;

      if (error instanceof SecureJwtVerificationError) {
        this.metrics.incrementCounter("jwt_verify_failure_total", {
          issuer_name: error.issuerName || "unknown",
          reason: error.reason,
        });
        this.logger.error("JWT verification failed", {
          issuer_name: error.issuerName,
          reason: error.reason,
          duration_seconds: duration,
        });
        throw error;
      }

      // Unexpected error
      this.logger.error("JWT verification failed with unexpected error", {
        issuer_name: issuerName || "unknown",
        error: error instanceof Error ? error.message : String(error),
        duration_seconds: duration,
      });

      throw new SecureJwtVerificationError(
        "Verification failed",
        "policy_violation",
        issuerName
      );
    }
  }

  /**
   * Map underlying library errors to stable error taxonomy
   */
  private mapError(
    error: unknown,
    issuerName: string
  ): SecureJwtVerificationError {
    if (error instanceof JwtParseError) {
      return new SecureJwtVerificationError(
        error.message,
        "invalid_structure",
        issuerName
      );
    }

    if (error instanceof JwtInvalidSignatureError) {
      return new SecureJwtVerificationError(
        "Invalid signature",
        "invalid_signature",
        issuerName
      );
    }

    if (error instanceof JwtInvalidSignatureAlgorithmError) {
      return new SecureJwtVerificationError(
        error.message,
        "alg_not_allowed",
        issuerName
      );
    }

    if (error instanceof JwtInvalidIssuerError) {
      return new SecureJwtVerificationError(
        error.message,
        "issuer_mismatch",
        issuerName
      );
    }

    if (error instanceof JwtInvalidAudienceError) {
      return new SecureJwtVerificationError(
        error.message,
        "audience_mismatch",
        issuerName
      );
    }

    if (error instanceof JwtExpiredError) {
      return new SecureJwtVerificationError(
        "Token expired",
        "expired",
        issuerName
      );
    }

    if (error instanceof JwtNotBeforeError) {
      return new SecureJwtVerificationError(
        "Token not yet valid",
        "not_yet_valid",
        issuerName
      );
    }

    if (error instanceof KidNotFoundInJwksError) {
      this.metrics.incrementCounter("jwks_cache_miss_total", {
        issuer_name: issuerName,
      });
      return new SecureJwtVerificationError(
        "Key ID not found in JWKS",
        "kid_not_found",
        issuerName
      );
    }

    if (error instanceof WaitPeriodNotYetEndedJwkError) {
      // Penalty-box / rate limiting
      this.logger.warn("JWKS fetch rate limited", {
        issuer_name: issuerName,
      });
      return new SecureJwtVerificationError(
        "JWKS fetch rate limited (penalty-box)",
        "jwks_fetch_rate_limited",
        issuerName
      );
    }

    if (error instanceof JwtBaseError) {
      return new SecureJwtVerificationError(
        error.message,
        "policy_violation",
        issuerName
      );
    }

    return new SecureJwtVerificationError(
      error instanceof Error ? error.message : String(error),
      "policy_violation",
      issuerName
    );
  }
}
