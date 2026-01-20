// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SupportedSignatureAlgorithm } from "./jwt-verifier.js";

/**
 * Policy registry schema for secure JWT verification
 */
export interface PolicyRegistry {
  version: 1;
  defaults: PolicyDefaults;
  issuers: IssuerPolicy[];
}

/**
 * Default policy settings
 */
export interface PolicyDefaults {
  clockSkewSeconds: number;
  maxTokenAgeSeconds: number;
  requiredClaims: string[];
}

/**
 * Per-issuer policy configuration
 */
export interface IssuerPolicy {
  name: string;
  issuer: string;
  jwksUri: string;
  audiences: string[];
  allowedAlgs: SupportedSignatureAlgorithm[]; // Must be exactly one algorithm (validated at runtime)
  clockSkewSeconds?: number;
  maxTokenAgeSeconds?: number;
  requiredClaims?: string[];
  deny?: {
    headerTypAllowlist?: string[];
  };
}

/**
 * Verified token result
 */
export interface VerifiedToken {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  issuerName: string;
}

/**
 * Error reasons for stable error taxonomy
 */
export type VerificationErrorReason =
  | "invalid_structure"
  | "invalid_signature"
  | "issuer_mismatch"
  | "audience_mismatch"
  | "expired"
  | "not_yet_valid"
  | "alg_not_allowed"
  | "kid_not_found"
  | "jwks_fetch_rate_limited"
  | "jwks_fetch_failed"
  | "policy_violation"
  | "missing_required_claim"
  | "token_too_old";

/**
 * Metrics interface for observability
 */
export interface Metrics {
  incrementCounter(
    name: string,
    labels: Record<string, string>,
    value?: number
  ): void;
  recordHistogram(
    name: string,
    value: number,
    labels: Record<string, string>
  ): void;
}

/**
 * Logger interface for structured logging
 */
export interface Logger {
  info(message: string, context: Record<string, unknown>): void;
  warn(message: string, context: Record<string, unknown>): void;
  error(message: string, context: Record<string, unknown>): void;
}
