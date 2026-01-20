// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  PolicyRegistry,
  IssuerPolicy,
  PolicyDefaults,
} from "./secure-verifier-types.js";
import { supportedSignatureAlgorithms } from "./jwt-verifier.js";

/**
 * Registry validation error
 */
export class RegistryValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RegistryValidationError";
  }
}

/**
 * Validate the entire policy registry
 */
export function validateRegistry(registry: unknown): PolicyRegistry {
  if (!registry || typeof registry !== "object") {
    throw new RegistryValidationError("Registry must be an object");
  }

  const reg = registry as Partial<PolicyRegistry>;

  // Validate version
  if (reg.version !== 1) {
    throw new RegistryValidationError(
      "Registry version must be 1 (unsupported version)"
    );
  }

  // Validate defaults
  if (!reg.defaults) {
    throw new RegistryValidationError("Registry must have defaults");
  }
  validateDefaults(reg.defaults);

  // Validate issuers
  if (!reg.issuers || !Array.isArray(reg.issuers)) {
    throw new RegistryValidationError("Registry must have issuers array");
  }

  if (reg.issuers.length === 0) {
    throw new RegistryValidationError(
      "Registry must have at least one issuer (non-dev)"
    );
  }

  // Check for duplicate issuer URLs or names
  const issuerUrls = new Set<string>();
  const issuerNames = new Set<string>();
  for (const issuer of reg.issuers) {
    if (issuerUrls.has(issuer.issuer)) {
      throw new RegistryValidationError(
        `Duplicate issuer URL: ${issuer.issuer}`
      );
    }
    if (issuerNames.has(issuer.name)) {
      throw new RegistryValidationError(
        `Duplicate issuer name: ${issuer.name}`
      );
    }
    issuerUrls.add(issuer.issuer);
    issuerNames.add(issuer.name);

    validateIssuer(issuer, reg.defaults);
  }

  return reg as PolicyRegistry;
}

/**
 * Validate defaults section
 */
function validateDefaults(defaults: unknown): asserts defaults is PolicyDefaults {
  if (!defaults || typeof defaults !== "object") {
    throw new RegistryValidationError("Defaults must be an object");
  }

  const def = defaults as Partial<PolicyDefaults>;

  // Validate clockSkewSeconds
  if (
    typeof def.clockSkewSeconds !== "number" ||
    def.clockSkewSeconds < 0 ||
    def.clockSkewSeconds > 60
  ) {
    throw new RegistryValidationError(
      "Defaults clockSkewSeconds must be between 0 and 60"
    );
  }

  // Validate maxTokenAgeSeconds
  if (
    typeof def.maxTokenAgeSeconds !== "number" ||
    def.maxTokenAgeSeconds < 60 ||
    def.maxTokenAgeSeconds > 3600
  ) {
    throw new RegistryValidationError(
      "Defaults maxTokenAgeSeconds must be between 60 and 3600"
    );
  }

  // Validate requiredClaims
  if (!Array.isArray(def.requiredClaims) || def.requiredClaims.length === 0) {
    throw new RegistryValidationError(
      "Defaults requiredClaims must be a non-empty array"
    );
  }

  if (!def.requiredClaims.includes("exp")) {
    throw new RegistryValidationError(
      "Defaults requiredClaims must include 'exp'"
    );
  }

  if (!def.requiredClaims.includes("iat")) {
    throw new RegistryValidationError(
      "Defaults requiredClaims must include 'iat'"
    );
  }
}

/**
 * Validate a single issuer policy
 */
function validateIssuer(
  issuer: unknown,
  defaults: PolicyDefaults
): asserts issuer is IssuerPolicy {
  if (!issuer || typeof issuer !== "object") {
    throw new RegistryValidationError("Issuer must be an object");
  }

  const iss = issuer as Partial<IssuerPolicy>;

  // Validate name
  if (!iss.name || typeof iss.name !== "string" || iss.name.trim() === "") {
    throw new RegistryValidationError("Issuer name must be a non-empty string");
  }

  // Validate issuer URL - must be absolute https URL  
  if (iss.issuer === null || iss.issuer === "") {
    throw new RegistryValidationError(
      "Issuer URL cannot be null (skip checks not allowed)"
    );
  }
  
  if (typeof iss.issuer !== "string") {
    throw new RegistryValidationError("Issuer URL must be a string");
  }

  try {
    const url = new URL(iss.issuer);
    if (url.protocol !== "https:") {
      throw new RegistryValidationError(
        `Issuer URL must use https protocol: ${iss.issuer}`
      );
    }
  } catch (e) {
    throw new RegistryValidationError(
      `Invalid issuer URL: ${iss.issuer} - ${e}`
    );
  }

  // Validate jwksUri - must be absolute https URL and explicit
  if (!iss.jwksUri || typeof iss.jwksUri !== "string") {
    throw new RegistryValidationError(
      "jwksUri must be explicitly provided (no discovery in v1)"
    );
  }

  if (iss.jwksUri === null) {
    throw new RegistryValidationError(
      "jwksUri cannot be null (skip checks not allowed)"
    );
  }

  try {
    const url = new URL(iss.jwksUri);
    if (url.protocol !== "https:") {
      throw new RegistryValidationError(
        `jwksUri must use https protocol: ${iss.jwksUri}`
      );
    }
  } catch (e) {
    throw new RegistryValidationError(
      `Invalid jwksUri: ${iss.jwksUri} - ${e}`
    );
  }

  // Validate audiences - must be non-empty, bounded
  if (!Array.isArray(iss.audiences) || iss.audiences.length === 0) {
    throw new RegistryValidationError(
      `Issuer ${iss.name} audiences must be a non-empty array`
    );
  }

  if (iss.audiences.includes(null as any)) {
    throw new RegistryValidationError(
      `Issuer ${iss.name} audiences cannot include null (skip checks not allowed)`
    );
  }

  if (iss.audiences.length > 100) {
    throw new RegistryValidationError(
      `Issuer ${iss.name} audiences array too large (max 100)`
    );
  }

  for (const aud of iss.audiences) {
    if (typeof aud !== "string" || aud.trim() === "") {
      throw new RegistryValidationError(
        `Issuer ${iss.name} audiences must contain non-empty strings`
      );
    }
  }

  // Validate allowedAlgs - must be non-empty AND exactly one AND in supported list AND no HS*
  if (!Array.isArray(iss.allowedAlgs)) {
    throw new RegistryValidationError(
      `Issuer ${iss.name} allowedAlgs must be an array`
    );
  }
  
  if (iss.allowedAlgs.length === 0) {
    throw new RegistryValidationError(
      `Issuer ${iss.name} allowedAlgs must be a non-empty array`
    );
  }

  if (iss.allowedAlgs.length !== 1) {
    throw new RegistryValidationError(
      `Issuer ${iss.name} must have exactly one allowedAlg (got ${iss.allowedAlgs.length})`
    );
  }

  const alg = iss.allowedAlgs[0];
  
  // Check for symmetric algorithms first (not allowed)
  if (alg.startsWith("HS")) {
    throw new RegistryValidationError(
      `Issuer ${iss.name} symmetric algorithm ${alg} not allowed (asymmetric only)`
    );
  }
  
  if (!supportedSignatureAlgorithms.includes(alg as any)) {
    throw new RegistryValidationError(
      `Issuer ${iss.name} algorithm ${alg} not in supported list: ${supportedSignatureAlgorithms.join(", ")}`
    );
  }

  // Validate optional clockSkewSeconds
  if (iss.clockSkewSeconds !== undefined) {
    if (
      typeof iss.clockSkewSeconds !== "number" ||
      iss.clockSkewSeconds < 0 ||
      iss.clockSkewSeconds > 60
    ) {
      throw new RegistryValidationError(
        `Issuer ${iss.name} clockSkewSeconds must be between 0 and 60`
      );
    }
  }

  // Validate optional maxTokenAgeSeconds
  if (iss.maxTokenAgeSeconds !== undefined) {
    if (
      typeof iss.maxTokenAgeSeconds !== "number" ||
      iss.maxTokenAgeSeconds < 60 ||
      iss.maxTokenAgeSeconds > 3600
    ) {
      throw new RegistryValidationError(
        `Issuer ${iss.name} maxTokenAgeSeconds must be between 60 and 3600`
      );
    }
  }

  // Validate optional requiredClaims
  const requiredClaims = iss.requiredClaims || defaults.requiredClaims;
  if (!requiredClaims.includes("exp")) {
    throw new RegistryValidationError(
      `Issuer ${iss.name} requiredClaims must include 'exp'`
    );
  }

  if (!requiredClaims.includes("iat")) {
    throw new RegistryValidationError(
      `Issuer ${iss.name} requiredClaims must include 'iat'`
    );
  }
}
