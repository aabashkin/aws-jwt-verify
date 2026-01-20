# AWS JWT Security Wrapper

A secure-by-default JWT verification module for general OIDC issuers in Node.js, using asymmetric signatures and JWKS, built on `awslabs/aws-jwt-verify`.

## Architecture

This module **wraps** the existing `aws-jwt-verify` library to provide additional security enforcement:

**What's delegated to aws-jwt-verify:**
- Core JWT signature verification (RSA, ECDSA, EdDSA)
- JWKS fetching and caching (with built-in rate limiting)
- exp/nbf claim validation
- Issuer validation

**What this wrapper adds:**
- Policy-driven configuration with strict startup validation
- Algorithm pinning (exactly one algorithm per issuer)
- Max token age enforcement (via `iat`, independent of `exp`)
- Audience allowlist enforcement
- Required claims validation
- Stable error taxonomy for all failure modes
- Metrics and structured logging hooks

## Features

- **Fail-closed by default**: No runtime "helpful" bypasses
- **Policy-driven**: Issuer/audience/JWKS URI/algorithms are static allowlist config
- **Offline hot path**: Verification does not depend on online calls, except bounded JWKS refresh
- **Security-first**: Enforces algorithm pinning, max token age, and required claims
- **Observable**: Built-in metrics and structured logging hooks

## Quick Start

### 1. Create a Policy Registry

Create a JSON file defining your trusted issuers:

```json
{
  "version": 1,
  "defaults": {
    "clockSkewSeconds": 30,
    "maxTokenAgeSeconds": 900,
    "requiredClaims": ["iss", "aud", "sub", "exp", "iat"]
  },
  "issuers": [
    {
      "name": "my-auth-prod",
      "issuer": "https://auth.prod.example.com/",
      "jwksUri": "https://auth.prod.example.com/.well-known/jwks.json",
      "audiences": ["my-api"],
      "allowedAlgs": ["RS256"]
    }
  ]
}
```

### 2. Initialize the Verifier

```typescript
import { SecureJwtVerifier } from 'aws-jwt-verify';
import registryConfig from './registry.json';

const verifier = new SecureJwtVerifier(registryConfig);

// Warm the JWKS cache at startup (recommended)
await verifier.warm();
```

### 3. Verify JWTs

```typescript
try {
  const token = await verifier.verify(jwtString);
  console.log('Token verified:', token.issuerName, token.payload.sub);
} catch (error) {
  if (error instanceof SecureJwtVerificationError) {
    console.error('Verification failed:', error.reason);
    // error.reason is one of the stable error taxonomy values
  }
}
```

## Policy Registry Format

### Registry Structure

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | number | Yes | Must be `1` |
| `defaults` | object | Yes | Default policy settings |
| `issuers` | array | Yes | Array of issuer policies (non-empty) |

### Defaults Object

| Field | Type | Default | Range | Description |
|-------|------|---------|-------|-------------|
| `clockSkewSeconds` | number | 30 | 0-60 | Clock skew tolerance for exp/nbf |
| `maxTokenAgeSeconds` | number | 900 | 60-3600 | Maximum token age (enforced via iat) |
| `requiredClaims` | string[] | - | - | Must include 'exp' and 'iat' |

### Issuer Policy

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique issuer name |
| `issuer` | string | Yes | HTTPS URL of the issuer |
| `jwksUri` | string | Yes | HTTPS URL where JWKS can be fetched |
| `audiences` | string[] | Yes | Non-empty list of allowed audiences |
| `allowedAlgs` | string[] | Yes | Must contain exactly one algorithm |
| `clockSkewSeconds` | number | No | Override default |
| `maxTokenAgeSeconds` | number | No | Override default |
| `requiredClaims` | string[] | No | Override default |
| `deny.headerTypAllowlist` | string[] | No | Optional typ header allowlist |

### Supported Algorithms

- `RS256`, `RS384`, `RS512` (RSA)
- `ES256`, `ES384`, `ES512` (Elliptic Curve)
- `EdDSA` (Edwards Curve)

Symmetric algorithms (HS*) are **not allowed**.

## Security Constraints

### What's Enforced

1. **Algorithm pinning**: Exactly one algorithm per issuer
2. **No skip checks**: Null issuer/audience not allowed
3. **Explicit JWKS URI**: No automatic discovery
4. **Max token age**: Independent of exp, enforced via iat
5. **Required claims**: At minimum: iss, aud, sub, exp, iat
6. **HTTPS only**: All issuer and JWKS URIs must use HTTPS

### What's Prevented

- Algorithm confusion/downgrade attacks
- Issuer/JWKS injection (SSRF)
- Request-driven issuer selection
- Runtime policy overrides
- Token reuse beyond maxTokenAge

## Error Taxonomy

All verification failures throw `SecureJwtVerificationError` with a stable `reason` field:

| Reason | Description |
|--------|-------------|
| `invalid_structure` | JWT parsing failed |
| `invalid_signature` | Signature verification failed |
| `issuer_mismatch` | Unknown or mismatched issuer |
| `audience_mismatch` | Audience not in allowlist |
| `expired` | Token expired (exp) |
| `not_yet_valid` | Token not yet valid (nbf) |
| `alg_not_allowed` | Algorithm not allowed for issuer |
| `kid_not_found` | Key ID not found in JWKS |
| `jwks_fetch_rate_limited` | JWKS fetch in penalty-box |
| `jwks_fetch_failed` | JWKS fetch error |
| `policy_violation` | Other policy violation |
| `missing_required_claim` | Required claim missing |
| `token_too_old` | Token age exceeds maxTokenAgeSeconds |

**Important**: Always return a generic auth failure to clients. Log the specific `reason` for internal observability only.

## Observability

### Metrics Interface

Provide a metrics implementation to track verification behavior:

```typescript
const verifier = new SecureJwtVerifier(registry, {
  metrics: {
    incrementCounter: (name, labels, value = 1) => {
      // e.g., myMetrics.increment(name, labels, value)
    },
    recordHistogram: (name, value, labels) => {
      // e.g., myMetrics.histogram(name, value, labels)
    }
  }
});
```

**Counter Metrics:**
- `jwt_policy_registry_lint_total{result}` - Registry validation results
- `jwt_verify_success_total{issuer_name}` - Successful verifications
- `jwt_verify_failure_total{issuer_name, reason}` - Failed verifications
- `jwks_cache_miss_total{issuer_name}` - JWKS cache misses
- `jwks_hydrate_total{issuer_name, result}` - JWKS hydration results

**Histogram Metrics:**
- `jwt_verify_duration_seconds{issuer_name, cache}` - Verification latency
- `jwks_fetch_duration_seconds{issuer_name}` - JWKS fetch latency

### Logger Interface

Provide a logger implementation for structured logging:

```typescript
const verifier = new SecureJwtVerifier(registry, {
  logger: {
    info: (message, context) => {
      // e.g., logger.info(message, context)
    },
    warn: (message, context) => {
      // e.g., logger.warn(message, context)
    },
    error: (message, context) => {
      // e.g., logger.error(message, context)
    }
  }
});
```

**Never log**: Raw JWT, sub, kid, or full payload (PII/sensitive data).

## Operational Guidance

### JWKS Warmup

**Always** call `warm()` during application startup or in a readiness gate:

```typescript
// Good: Warmup during startup
await verifier.warm();
app.listen(3000);

// Bad: Warmup in a request handler (bypasses cache, hurts performance)
```

### JWKS Caching & Rotation

- **Rate limiting**: The underlying library enforces 1 JWKS download per URI per 10 seconds (penalty-box)
- **Rotation**: Expect transient `kid_not_found` during key rotation
- **Mitigation**: Pre-warm JWKS and consider periodic refresh for high-traffic services

### Registry Validation

Registry validation happens at **construction time**. Invalid registries fail immediately:

```typescript
try {
  const verifier = new SecureJwtVerifier(badRegistry);
} catch (error) {
  if (error instanceof RegistryValidationError) {
    console.error('Invalid registry:', error.message);
    // Fix registry and restart
  }
}
```

## Examples

### Production Setup with Observability

```typescript
import { SecureJwtVerifier } from 'aws-jwt-verify';
import { PrometheusMetrics } from './metrics';
import { WinstonLogger } from './logger';
import registryConfig from './config/jwt-registry.json';

const verifier = new SecureJwtVerifier(registryConfig, {
  metrics: new PrometheusMetrics(),
  logger: new WinstonLogger()
});

// Warmup in startup phase
await verifier.warm();

// In request handler
async function handleRequest(req, res) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.substring(7);
  
  try {
    const verified = await verifier.verify(token);
    req.user = {
      sub: verified.payload.sub,
      issuer: verified.issuerName
    };
    next();
  } catch (error) {
    if (error instanceof SecureJwtVerificationError) {
      // Log specific reason for internal observability
      logger.warn('JWT verification failed', { reason: error.reason });
    }
    // Always return generic error to client
    return res.status(401).json({ error: 'Unauthorized' });
  }
}
```

### Lambda Function with Warmup

```typescript
import { SecureJwtVerifier } from 'aws-jwt-verify';
import registryConfig from './registry.json';

let verifier: SecureJwtVerifier;
let isWarmed = false;

export async function handler(event) {
  // Lazy init + warmup
  if (!verifier) {
    verifier = new SecureJwtVerifier(registryConfig);
    await verifier.warm();
    isWarmed = true;
  }

  const token = event.headers.Authorization?.replace('Bearer ', '');
  if (!token) {
    return { statusCode: 401, body: 'Unauthorized' };
  }

  try {
    const verified = await verifier.verify(token);
    return {
      statusCode: 200,
      body: JSON.stringify({ sub: verified.payload.sub })
    };
  } catch (error) {
    return { statusCode: 401, body: 'Unauthorized' };
  }
}
```

### Multiple Issuers

```json
{
  "version": 1,
  "defaults": {
    "clockSkewSeconds": 30,
    "maxTokenAgeSeconds": 900,
    "requiredClaims": ["iss", "aud", "sub", "exp", "iat"]
  },
  "issuers": [
    {
      "name": "internal-prod",
      "issuer": "https://auth.company.com/",
      "jwksUri": "https://auth.company.com/.well-known/jwks.json",
      "audiences": ["api-prod"],
      "allowedAlgs": ["RS256"]
    },
    {
      "name": "partner-corp",
      "issuer": "https://sso.partner.example.org/",
      "jwksUri": "https://sso.partner.example.org/oauth2/jwks",
      "audiences": ["partner-integration"],
      "allowedAlgs": ["ES256"],
      "clockSkewSeconds": 60
    }
  ]
}
```

## Troubleshooting

### Common Issues

**"Registry validation failed: must have exactly one allowedAlg"**
- Each issuer must specify exactly one algorithm for security
- Change `"allowedAlgs": ["RS256", "ES256"]` to `"allowedAlgs": ["RS256"]`

**"JWKS fetch rate limited (penalty-box)"**
- Too many unknown kids or rapid JWKS fetches
- Check for key rotation, ensure warmup is called, verify kid in token headers

**"Token too old"**
- Token `iat` exceeds `maxTokenAgeSeconds`
- Increase `maxTokenAgeSeconds` (max 3600) or ensure tokens are fresh

**"Audience mismatch"**
- Token `aud` claim not in issuer's `audiences` array
- Add the audience to the registry or fix token issuance

## API Reference

### `SecureJwtVerifier`

**Constructor**

```typescript
new SecureJwtVerifier(
  registry: unknown,
  options?: {
    metrics?: Metrics;
    logger?: Logger;
  }
)
```

**Methods**

- `verify(jwt: string): Promise<VerifiedToken>` - Verify a JWT token
- `warm(): Promise<void>` - Pre-fetch JWKS for all issuers

**Throws**
- `RegistryValidationError` - On invalid registry (at construction)
- `SecureJwtVerificationError` - On verification failure

### `validateRegistry(registry: unknown): PolicyRegistry`

Standalone function to validate a registry without creating a verifier.

## License

This wrapper is built on `aws-jwt-verify` which is Apache 2.0 licensed.
