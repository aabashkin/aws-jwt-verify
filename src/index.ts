// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export { JwtVerifier } from "./jwt-verifier.js";
export { CognitoJwtVerifier } from "./cognito-verifier.js";
export { AlbJwtVerifier } from "./alb-verifier.js";
export {
  SecureJwtVerifier,
  SecureJwtVerificationError,
} from "./secure-jwt-verifier.js";
export type {
  PolicyRegistry,
  IssuerPolicy,
  PolicyDefaults,
  VerifiedToken,
  VerificationErrorReason,
  Metrics,
  Logger,
} from "./secure-verifier-types.js";
export { validateRegistry, RegistryValidationError } from "./registry-validator.js";

// Backward compatibility
import { JwtVerifier } from "./jwt-verifier.js";
/**
 * @deprecated since version 5.0.0, use JwtVerifier instead.
 *   The JwtRsaVerifier has been aliased to JwtVerifier, that supports Elliptic Curve algorithms as well.
 */
export const JwtRsaVerifier = JwtVerifier;
