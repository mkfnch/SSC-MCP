import { logger } from './logger.js';

/**
 * When running in production, error responses sent to MCP clients are stripped
 * of internal details (endpoint paths, status codes) to avoid leaking API
 * structure. Full details are still emitted to the server-side log.
 */
const isProduction = (process.env.NODE_ENV ?? 'production') === 'production';

/**
 * JSON.stringify can throw on circular references and BigInt values. Tool
 * payloads come from upstream APIs we don't fully control, so we fall back
 * to a generic shape rather than letting the tool handler reject and
 * surface an opaque transport-level error to the MCP client.
 */
function safeStringify(value: unknown, indent?: number): string {
  try {
    return JSON.stringify(value, null, indent);
  } catch (err) {
    logger.warn({ err }, 'safeStringify fallback engaged');
    return JSON.stringify({ error: 'Response could not be serialized to JSON.' });
  }
}

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

function formatMcpError(error: unknown): { type: 'text'; text: string } {
  if (error instanceof RateLimitError) {
    logger.error(
      { err: error, endpoint: error.endpoint, statusCode: error.statusCode },
      'SecurityScorecard rate limit hit'
    );
    return {
      type: 'text',
      text: JSON.stringify({
        error: 'Rate limit exceeded. Please wait before retrying.',
        retryable: true,
        ...(isProduction ? {} : { endpoint: error.endpoint, retryAfter: error.retryAfter }),
      }),
    };
  }

  if (error instanceof SecurityScorecardError) {
    logger.error(
      { err: error, endpoint: error.endpoint, statusCode: error.statusCode },
      'SecurityScorecard API error'
    );
    return {
      type: 'text',
      text: JSON.stringify({
        error: isProduction
          ? 'An API error occurred. Please check your request and try again.'
          : error.message,
        retryable: error.retryable,
        ...(isProduction ? {} : { statusCode: error.statusCode, endpoint: error.endpoint }),
      }),
    };
  }

  if (error instanceof Error) {
    logger.error({ err: error }, 'Unexpected error');
    return {
      type: 'text',
      text: JSON.stringify({
        error: isProduction ? 'An unexpected error occurred.' : error.message,
      }),
    };
  }

  logger.error({ err: error }, 'Unknown error');
  return { type: 'text', text: JSON.stringify({ error: 'An unexpected error occurred.' }) };
}

type ToolResult = { content: { type: 'text'; text: string }[]; isError?: boolean };

export async function handleToolCall<T>(fn: () => Promise<T>): Promise<ToolResult> {
  try {
    const data = await fn();
    return { content: [{ type: 'text', text: safeStringify(data, 2) }] };
  } catch (error) {
    return { content: [formatMcpError(error)], isError: true };
  }
}

export async function handleVoidToolCall(fn: () => Promise<void>, successMessage: string): Promise<ToolResult> {
  try {
    await fn();
    return { content: [{ type: 'text', text: JSON.stringify({ success: true, message: successMessage }) }] };
  } catch (error) {
    return { content: [formatMcpError(error)], isError: true };
  }
}

export function formatResourceError(error: unknown): string {
  return formatMcpError(error).text;
}
