import { z } from 'zod';

const ConfigSchema = z.object({
  transportMode: z.enum(['stdio', 'http']).default('stdio'),
  port: z.coerce.number().int().min(1).max(65535).default(3000),
  ssc: z.object({
    apiBaseUrl: z.string().url().default('https://api.securityscorecard.io'),
    apiKey: z.string().min(1).optional(),
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
    ssc: {
      apiBaseUrl: process.env.SSC_API_BASE_URL || 'https://api.securityscorecard.io',
      apiKey: process.env.SSC_API_KEY,
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
