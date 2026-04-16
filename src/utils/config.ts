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
    ssc: {
      apiBaseUrl: process.env.SSC_API_BASE_URL || 'https://api.securityscorecard.io',
      apiKey: process.env.SSC_API_KEY || process.env.SSC_API_TOKEN,
    },
    oauth: {
      issuer: process.env.OAUTH_ISSUER,
      audience: process.env.OAUTH_AUDIENCE,
      jwksUri: process.env.JWKS_URI,
    },
    logLevel: process.env.LOG_LEVEL || 'info',
    nodeEnv: process.env.NODE_ENV || 'production',
  });
}
