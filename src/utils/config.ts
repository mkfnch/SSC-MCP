import { z } from 'zod';

const ConfigSchema = z.object({
  transportMode: z.enum(['stdio', 'http']).default('stdio'),
  port: z.coerce.number().int().min(1).max(65535).default(3000),
  /**
   * Comma-separated list of allowed CORS origins for HTTP mode.
   * Example: "https://app.example.com,https://other.example.com"
   * If unset the server defaults to denying all cross-origin requests in
   * production and allowing all in development.
   */
  allowedOrigins: z.string().optional(),
  /**
   * Express "trust proxy" setting for HTTP mode. When unset, the server
   * never trusts client-supplied X-Forwarded-For headers and treats the
   * raw socket address as the client identity (correct for direct
   * exposure). When set, the value is forwarded to Express verbatim:
   *  - "true"  → trust every hop (only safe behind a known proxy chain)
   *  - "1", "2", … → trust N hops
   *  - "loopback", "linklocal", "uniquelocal" → preset address ranges
   *  - "10.0.0.0/8,192.168.0.0/16" → explicit CIDR list
   * Without this, an attacker rotating X-Forwarded-For can defeat the
   * per-IP rate limiter.
   */
  trustedProxy: z.string().optional(),
  ssc: z.object({
    apiBaseUrl: z.string().url().default('https://api.securityscorecard.io'),
    /**
     * SecurityScorecard API key. Must be at least 10 characters to match the
     * minimum realistic key length and catch obvious misconfiguration early.
     */
    apiKey: z.string().min(10).optional(),
  }),
  oauth: z.object({
    issuer: z.string().url().optional(),
    audience: z.string().url().optional(),
    jwksUri: z.string().url().optional(),
    /**
     * Optional expected `azp` (authorized party) claim. When set, the JWT
     * must carry exactly this value or verification fails. Useful when the
     * IdP issues a single audience to multiple clients and only one of
     * them should be able to call this server.
     */
    azp: z.string().min(1).optional(),
  }),
  logLevel: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  nodeEnv: z.enum(['development', 'production', 'test']).default('production'),
});

export type Config = z.infer<typeof ConfigSchema>;

export function loadConfig(): Config {
  return ConfigSchema.parse({
    transportMode: process.env.TRANSPORT_MODE || 'stdio',
    port: process.env.PORT || 3000,
    allowedOrigins: process.env.ALLOWED_ORIGINS,
    trustedProxy: process.env.TRUSTED_PROXY,
    ssc: {
      apiBaseUrl: process.env.SSC_API_BASE_URL || 'https://api.securityscorecard.io',
      apiKey: process.env.SSC_API_KEY || process.env.SSC_API_TOKEN,
    },
    oauth: {
      issuer: process.env.OAUTH_ISSUER,
      audience: process.env.OAUTH_AUDIENCE,
      jwksUri: process.env.JWKS_URI,
      azp: process.env.OAUTH_AZP,
    },
    logLevel: process.env.LOG_LEVEL || 'info',
    nodeEnv: process.env.NODE_ENV || 'production',
  });
}
