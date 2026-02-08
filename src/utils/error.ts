import { logger } from './logger.js';

export class SecurityScorecardError extends Error {
  public readonly statusCode: number;
  public readonly endpoint: string;
  public readonly retryable: boolean;

  constructor(message: string, statusCode: number, endpoint: string) {
    super(message);
    this.name = 'SecurityScorecardError';
    this.statusCode = statusCode;
    this.endpoint = endpoint;
    this.retryable = statusCode === 429 || statusCode >= 500;
  }
}

export class AuthenticationError extends Error {
  constructor(message = 'Authentication failed. Please check your API key.') {
    super(message);
    this.name = 'AuthenticationError';
  }
}

export class RateLimitError extends SecurityScorecardError {
  public readonly retryAfter: number;

  constructor(endpoint: string, retryAfter: number) {
    super(`Rate limit exceeded for ${endpoint}`, 429, endpoint);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

export function formatMcpError(error: unknown): { type: 'text'; text: string }[] {
  if (error instanceof SecurityScorecardError) {
    logger.error({ err: error, endpoint: error.endpoint, statusCode: error.statusCode }, 'SecurityScorecard API error');
    return [{
      type: 'text',
      text: JSON.stringify({
        error: error.message,
        statusCode: error.statusCode,
        endpoint: error.endpoint,
        retryable: error.retryable,
      }),
    }];
  }

  if (error instanceof Error) {
    logger.error({ err: error }, 'Unexpected error');
    return [{ type: 'text', text: JSON.stringify({ error: error.message }) }];
  }

  logger.error({ err: error }, 'Unknown error');
  return [{ type: 'text', text: JSON.stringify({ error: 'An unexpected error occurred' }) }];
}
