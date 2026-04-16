#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import express from 'express';
import cors from 'cors';
import { randomUUID } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';

import { loadConfig } from './utils/config.js';
import { logger } from './utils/logger.js';
import { SecurityScorecardService } from './services/securityscorecard.service.js';
import { registerAllTools } from './tools/index.js';
import { registerResources } from './resources/scorecard.resources.js';

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
    logger.error('SSC_API_KEY (or SSC_API_TOKEN) environment variable is required for stdio mode');
    process.exit(1);
  }

  setupTools(server, apiKey);

  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info('SecurityScorecard MCP server running on stdio');
}

// ── HTTP transport ────────────────────────────────────────────────────────────

/** Maximum age of an idle MCP session before it is evicted. */
const SESSION_TTL_MS = 30 * 60_000; // 30 minutes

async function startHttpTransport(): Promise<void> {
  const app = express();

  // ── Security response headers ─────────────────────────────────────────────
  // Applied before every response, including errors, to prevent common
  // browser-side attack vectors.
  app.use((_req, res, next) => {
    res.removeHeader('X-Powered-By');                          // fingerprint reduction
    res.setHeader('X-Content-Type-Options', 'nosniff');        // MIME sniffing
    res.setHeader('X-Frame-Options', 'DENY');                  // clickjacking
    res.setHeader('Content-Security-Policy', "default-src 'none'"); // XSS
    res.setHeader('Cache-Control', 'no-store');                // sensitive data caching
    res.setHeader('Referrer-Policy', 'no-referrer');           // referrer leakage
    if (config.nodeEnv === 'production') {
      res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains'); // HSTS
    }
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
    { transport: StreamableHTTPServerTransport; server: McpServer; lastActivity: number }
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
    let transport: StreamableHTTPServerTransport;
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
