#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { StreamableHTTPServerTransport as StreamableHTTPServerTransportType } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createRemoteJWKSet, jwtVerify } from 'jose';

import { loadConfig } from './utils/config.js';
import { logger } from './utils/logger.js';
import { SecurityScorecardService } from './services/securityscorecard.service.js';
import { registerAllTools } from './tools/index.js';
import { registerResources } from './resources/scorecard.resources.js';

// Global error handlers — prevent silent crashes in Claude Desktop.
// uncaughtException is fatal (process state is unreliable), but
// unhandledRejection is logged-and-continued so a transient API hiccup
// does not tear down the whole MCP session.
process.on('uncaughtException', (error) => {
  logger.fatal({ err: error }, 'Uncaught exception');
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  logger.error({ err: reason }, 'Unhandled promise rejection (non-fatal)');
});

const config = loadConfig();

// ── JWT / OAuth verification ──────────────────────────────────────────────────

/**
 * Lazily-initialised JWKS set. jose maintains its own key-material cache and
 * re-fetches only when keys are rotated, so we create one instance per process.
 */
let _jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

function getJwks(): ReturnType<typeof createRemoteJWKSet> | null {
  if (!config.oauth.jwksUri) return null;
  if (!_jwks) _jwks = createRemoteJWKSet(new URL(config.oauth.jwksUri));
  return _jwks;
}

/**
 * Verifies a Bearer JWT against the configured JWKS endpoint.
 * Returns true only if the token signature, issuer, and audience are all valid.
 */
async function verifyBearerToken(token: string): Promise<boolean> {
  const jwks = getJwks();
  if (!jwks) return false;
  try {
    await jwtVerify(token, jwks, {
      issuer: config.oauth.issuer ?? undefined,
      audience: config.oauth.audience ?? undefined,
    });
    return true;
  } catch {
    // Intentionally catch-all: log nothing here to avoid timing oracle; the
    // caller emits a generic 401.
    return false;
  }
}

// ── In-memory rate limiter ────────────────────────────────────────────────────

const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute sliding window
const RATE_LIMIT_MAX       = 100;    // requests per window per client IP

type RateBucket = { count: number; resetAt: number };
const rateLimitBuckets = new Map<string, RateBucket>();

// Prune stale buckets periodically so the map doesn't grow without bound.
const _rateLimitPruner = setInterval(() => {
  const now = Date.now();
  for (const [ip, bucket] of rateLimitBuckets) {
    if (now >= bucket.resetAt) rateLimitBuckets.delete(ip);
  }
}, RATE_LIMIT_WINDOW_MS);
_rateLimitPruner.unref(); // Don't keep the process alive solely for cleanup.

/**
 * Returns true when the request is within the rate limit, false when it should
 * be rejected. Mutates the bucket state as a side effect.
 */
function allowRequest(clientIp: string): boolean {
  const now = Date.now();
  const bucket = rateLimitBuckets.get(clientIp);
  if (!bucket || now >= bucket.resetAt) {
    rateLimitBuckets.set(clientIp, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return true;
  }
  if (bucket.count >= RATE_LIMIT_MAX) return false;
  bucket.count++;
  return true;
}

// ── MCP server factory ────────────────────────────────────────────────────────

function createServer(): McpServer {
  return new McpServer(
    { name: 'securityscorecard-mcp', version: '1.0.0' },
    {
      instructions:
        'SecurityScorecard MCP Connector for cyber risk intelligence. ' +
        'Provides access to security ratings, portfolio analytics, vendor risk intelligence, ' +
        'attack surface data, and compliance questionnaires. ' +
        'Use get-company-score to retrieve security scores, list-portfolios to view monitored companies, ' +
        'and search-attack-surface for threat intelligence.',
    }
  );
}

function setupTools(server: McpServer, apiKey: string): void {
  const ssc = new SecurityScorecardService(config.ssc.apiBaseUrl, apiKey);
  registerAllTools(server, ssc);
  registerResources(server, ssc);
}

// ── STDIO transport ───────────────────────────────────────────────────────────

async function startStdioTransport(): Promise<void> {
  const server = createServer();
  const apiKey = config.ssc.apiKey;
  if (!apiKey) {
    throw new Error(
      'SSC_API_KEY (or SSC_API_TOKEN) environment variable is required. ' +
      'Set it in your Claude Desktop MCP config under "env": { "SSC_API_KEY": "your-key" }'
    );
  }

  setupTools(server, apiKey);

  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info('SecurityScorecard MCP server running on stdio');

  // Graceful shutdown — close the transport cleanly so Claude Desktop
  // sees a proper disconnect instead of "transport closed unexpectedly".
  const shutdown = async () => {
    logger.info('Shutting down stdio transport');
    try {
      await server.close();
    } catch {
      // best-effort
    }
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

// ── HTTP transport ────────────────────────────────────────────────────────────

/** Maximum age of an idle MCP session before it is evicted. */
const SESSION_TTL_MS = 30 * 60_000; // 30 minutes

async function startHttpTransport(): Promise<void> {
  // Dynamic imports — these modules are only needed for HTTP mode and
  // loading them eagerly in stdio mode risks stdout side-effects during
  // module init that corrupt the JSON-RPC stream.
  const [
    { StreamableHTTPServerTransport },
    { isInitializeRequest },
    { default: express },
    { default: cors },
    { default: helmet },
    { randomUUID },
  ] = await Promise.all([
    import('@modelcontextprotocol/sdk/server/streamableHttp.js'),
    import('@modelcontextprotocol/sdk/types.js'),
    import('express'),
    import('cors'),
    import('helmet'),
    import('node:crypto'),
  ]);

  const app = express();
  app.disable('x-powered-by');

  // ── Security response headers ─────────────────────────────────────────────
  // helmet sets a hardened default set of headers (X-Content-Type-Options,
  // X-Frame-Options, Referrer-Policy, Cross-Origin-*, Permissions-Policy, …).
  // We override CSP to deny everything (this is a JSON-RPC API, not a web
  // app) and disable HSTS outside production so local HTTP development still
  // works.
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: { 'default-src': ["'none'"], 'frame-ancestors': ["'none'"] },
      },
      strictTransportSecurity:
        config.nodeEnv === 'production'
          ? { maxAge: 63072000, includeSubDomains: true }
          : false,
      crossOriginResourcePolicy: { policy: 'same-origin' },
      frameguard: { action: 'deny' },
    })
  );

  // Prevent caching of sensitive API responses. helmet does not set
  // Cache-Control by default.
  app.use((_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  // ── CORS ──────────────────────────────────────────────────────────────────
  // Default: deny all cross-origin requests in production unless ALLOWED_ORIGINS
  // is explicitly configured.  In development the wildcard is kept for ergonomics.
  const allowedOrigins = config.allowedOrigins
    ? config.allowedOrigins.split(',').map((o) => o.trim()).filter(Boolean)
    : [];

  app.use(
    cors({
      origin:
        allowedOrigins.length > 0
          ? allowedOrigins
          : config.nodeEnv === 'development'
            ? true     // allow all in dev
            : false,   // deny all in production when unconfigured
      exposedHeaders: ['Mcp-Session-Id'],
      allowedHeaders: ['Content-Type', 'mcp-session-id', 'Authorization'],
    })
  );

  // ── Body parser with explicit size cap ────────────────────────────────────
  // Prevents memory exhaustion via oversized JSON payloads.
  app.use(express.json({ limit: '100kb' }));

  // ── Session store with TTL enforcement ────────────────────────────────────
  const sessions = new Map<
    string,
    { transport: StreamableHTTPServerTransportType; server: McpServer; lastActivity: number }
  >();

  // Background sweep: evict sessions that have been idle beyond their TTL.
  const _sessionSweeper = setInterval(() => {
    const now = Date.now();
    for (const [id, session] of sessions) {
      if (now - session.lastActivity > SESSION_TTL_MS) {
        session.transport.close().catch(() => {});
        sessions.delete(id);
        logger.info({ sessionId: id }, 'MCP session expired and evicted');
      }
    }
  }, 5 * 60_000); // every 5 minutes
  _sessionSweeper.unref();

  // ── Health check ──────────────────────────────────────────────────────────
  // Version is intentionally omitted to reduce fingerprinting surface.
  app.get('/health', (_req, res) => {
    res.json({
      status: 'healthy',
      server: 'securityscorecard-mcp',
      timestamp: new Date().toISOString(),
    });
  });

  // ── OAuth Protected Resource Metadata (RFC 9728) ──────────────────────────
  app.get('/.well-known/oauth-protected-resource', (_req, res) => {
    res.json({
      resource: config.oauth.audience || 'https://mcp.securityscorecard.io',
      authorization_servers: [config.oauth.issuer || 'https://auth.securityscorecard.io'],
      scopes_supported: [
        'read:portfolios',
        'read:scorecards',
        'read:findings',
        'read:vendors',
        'read:asi',
        'write:portfolios',
        'write:questionnaires',
        'write:plans',
      ],
    });
  });

  // ── MCP Streamable HTTP endpoint (POST) ───────────────────────────────────
  app.post('/mcp', async (req, res) => {
    // Derive a stable client identifier for rate-limiting purposes.
    // X-Forwarded-For is used when the server is deployed behind a trusted proxy
    // (e.g. Kubernetes ingress, AWS ALB).  Fall back to the socket address.
    const clientIp =
      (req.headers['x-forwarded-for'] as string | undefined)
        ?.split(',')[0]
        ?.trim() ??
      req.socket.remoteAddress ??
      'unknown';

    if (!allowRequest(clientIp)) {
      res.status(429).json({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'Too many requests. Please retry later.' },
        id: null,
      });
      return;
    }

    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    let transport: StreamableHTTPServerTransportType;
    let server: McpServer;

    if (sessionId && sessions.has(sessionId)) {
      // Existing session – resume it and refresh TTL.
      const session = sessions.get(sessionId)!;
      session.lastActivity = Date.now();
      transport = session.transport;
      server = session.server;
    } else if (!sessionId && isInitializeRequest(req.body)) {
      // ── New session initialisation ──────────────────────────────────────
      server = createServer();

      // Resolve the SSC API key, handling both OAuth and direct-key modes.
      const authHeader = req.headers['authorization'] as string | undefined;
      let apiKey = config.ssc.apiKey ?? '';

      if (authHeader) {
        const spaceIdx = authHeader.indexOf(' ');

        // Reject malformed Authorization headers (missing or trailing scheme).
        if (spaceIdx <= 0 || spaceIdx === authHeader.length - 1) {
          res.status(401).json({
            jsonrpc: '2.0',
            error: { code: -32000, message: 'Invalid Authorization header format.' },
            id: null,
          });
          return;
        }

        const scheme     = authHeader.slice(0, spaceIdx).toLowerCase();
        const credential = authHeader.slice(spaceIdx + 1).trim();

        if (config.oauth.jwksUri) {
          // ── OAuth mode ────────────────────────────────────────────────
          // The Authorization header must carry a JWT Bearer token.
          // After successful verification the server uses its own SSC API key.
          if (scheme !== 'bearer') {
            res.status(401).json({
              jsonrpc: '2.0',
              error: { code: -32000, message: 'Bearer token required when OAuth is configured.' },
              id: null,
            });
            return;
          }

          const isValid = await verifyBearerToken(credential);
          if (!isValid) {
            res.status(401).json({
              jsonrpc: '2.0',
              error: { code: -32000, message: 'Invalid or expired authorization token.' },
              id: null,
            });
            return;
          }

          // JWT verified – the server-configured SSC API key MUST be present.
          if (!apiKey) {
            logger.error('SSC_API_KEY must be set when OAuth mode is active');
            res.status(500).json({
              jsonrpc: '2.0',
              error: { code: -32000, message: 'Server configuration error.' },
              id: null,
            });
            return;
          }
        } else {
          // ── Direct API-key mode ───────────────────────────────────────
          // Accept only the "Bearer" and "Token" schemes; reject anything else
          // (e.g. "Basic") to prevent credential confusion.
          if (scheme !== 'bearer' && scheme !== 'token') {
            res.status(401).json({
              jsonrpc: '2.0',
              error: { code: -32000, message: 'Authorization scheme must be Bearer or Token.' },
              id: null,
            });
            return;
          }
          apiKey = credential;
        }
      }

      if (!apiKey) {
        res.status(401).json({
          jsonrpc: '2.0',
          error: {
            code: -32000,
            message:
              'SecurityScorecard API key required. ' +
              'Provide via Authorization header or SSC_API_KEY/SSC_API_TOKEN environment variable.',
          },
          id: null,
        });
        return;
      }

      setupTools(server, apiKey);

      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => {
          sessions.set(id, { transport, server, lastActivity: Date.now() });
          logger.info({ sessionId: id }, 'MCP session initialized');
        },
      });

      transport.onclose = () => {
        if (transport.sessionId) {
          sessions.delete(transport.sessionId);
          logger.info({ sessionId: transport.sessionId }, 'MCP session closed');
        }
      };

      await server.connect(transport);
    } else {
      res.status(400).json({
        jsonrpc: '2.0',
        error: {
          code: -32000,
          message:
            'Invalid session. Send an initialize request without a session ID to start a new session.',
        },
        id: null,
      });
      return;
    }

    await transport.handleRequest(req, res, req.body);
  });

  // ── GET /mcp – SSE stream for server-initiated notifications ─────────────
  app.get('/mcp', async (req, res) => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    if (!sessionId || !sessions.has(sessionId)) {
      res.status(400).json({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'Invalid or missing session ID.' },
        id: null,
      });
      return;
    }
    const session = sessions.get(sessionId)!;
    await session.transport.handleRequest(req, res);
  });

  // ── DELETE /mcp – explicit session termination ────────────────────────────
  app.delete('/mcp', async (req, res) => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    if (!sessionId || !sessions.has(sessionId)) {
      res.status(400).json({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'Invalid or missing session ID.' },
        id: null,
      });
      return;
    }
    const session = sessions.get(sessionId)!;
    await session.transport.handleRequest(req, res);
  });

  const port = config.port;
  const httpServer = app.listen(port, () => {
    logger.info({ port, transport: 'streamable-http' }, 'SecurityScorecard MCP server running');
    logger.info(`MCP endpoint: http://localhost:${port}/mcp`);
    logger.info(`Health check: http://localhost:${port}/health`);
  });

  // ── Graceful shutdown ──────────────────────────────────────────────────────
  // Allow in-flight requests to complete before exiting (Docker/K8s sends
  // SIGTERM during rolling deployments).
  const shutdown = () => {
    logger.info('Shutdown signal received, closing HTTP server…');
    httpServer.close(() => {
      for (const [id, session] of sessions) {
        session.transport.close().catch(() => {});
        sessions.delete(id);
      }
      logger.info('All sessions closed, exiting');
      process.exit(0);
    });
    // Force exit after 10 seconds if connections don't drain.
    setTimeout(() => {
      logger.warn('Graceful shutdown timed out, forcing exit');
      process.exit(1);
    }, 10_000).unref();
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

// ── Main entry point ──────────────────────────────────────────────────────────

async function main(): Promise<void> {
  logger.info(
    { transport: config.transportMode, nodeEnv: config.nodeEnv },
    'Starting SecurityScorecard MCP server'
  );

  if (config.transportMode === 'http') {
    await startHttpTransport();
  } else {
    await startStdioTransport();
  }
}

main().catch((error) => {
  logger.fatal({ err: error }, 'Failed to start server');
  // Also write to stderr directly in case logger transport hasn't initialized
  process.stderr.write(`FATAL: Failed to start server: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
