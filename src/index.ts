#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import express from 'express';
import cors from 'cors';
import { randomUUID } from 'node:crypto';

import { loadConfig } from './utils/config.js';
import { logger } from './utils/logger.js';
import { SecurityScorecardService } from './services/securityscorecard.service.js';
import { registerAllTools } from './tools/index.js';
import { registerResources } from './resources/scorecard.resources.js';

// Global error handlers — prevent silent crashes in Claude Desktop
process.on('uncaughtException', (error) => {
  logger.fatal({ err: error }, 'Uncaught exception');
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  logger.fatal({ err: reason }, 'Unhandled promise rejection');
  process.exit(1);
});

const config = loadConfig();

function createServer(): McpServer {
  return new McpServer(
    {
      name: 'securityscorecard-mcp',
      version: '1.0.0',
    },
    {
      instructions: 'SecurityScorecard MCP Connector for cyber risk intelligence. ' +
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

async function startStdioTransport(): Promise<void> {
  const server = createServer();
  const apiKey = config.ssc.apiKey;
  if (!apiKey) {
    throw new Error(
      'SSC_API_KEY environment variable is required. ' +
      'Set it in your Claude Desktop MCP config under "env": { "SSC_API_KEY": "your-key" }'
    );
  }

  setupTools(server, apiKey);

  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info('SecurityScorecard MCP server running on stdio');
}

async function startHttpTransport(): Promise<void> {
  const app = express();
  app.use(express.json());
  app.use(cors({
    origin: '*',
    exposedHeaders: ['Mcp-Session-Id'],
    allowedHeaders: ['Content-Type', 'mcp-session-id', 'Authorization'],
  }));

  const sessions = new Map<string, { transport: StreamableHTTPServerTransport; server: McpServer }>();

  // Health check endpoint
  app.get('/health', (_req, res) => {
    res.json({
      status: 'healthy',
      server: 'securityscorecard-mcp',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
    });
  });

  // OAuth Protected Resource Metadata (RFC 9728)
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

  // MCP Streamable HTTP endpoint (POST)
  app.post('/mcp', async (req, res) => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    let transport: StreamableHTTPServerTransport;
    let server: McpServer;

    if (sessionId && sessions.has(sessionId)) {
      const session = sessions.get(sessionId)!;
      transport = session.transport;
      server = session.server;
    } else if (!sessionId && isInitializeRequest(req.body)) {
      // New session initialization
      server = createServer();

      // Extract API key from Authorization header or use env var
      const authHeader = req.headers['authorization'] as string | undefined;
      let apiKey = config.ssc.apiKey || '';
      if (authHeader) {
        // Support both "Bearer <token>" and "Token <key>" formats
        const parts = authHeader.split(' ');
        if (parts.length === 2) {
          apiKey = parts[1];
        }
      }

      if (!apiKey) {
        res.status(401).json({
          jsonrpc: '2.0',
          error: { code: -32000, message: 'SecurityScorecard API key required. Provide via Authorization header or SSC_API_KEY env var.' },
          id: null,
        });
        return;
      }

      setupTools(server, apiKey);

      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => {
          sessions.set(id, { transport, server });
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
        error: { code: -32000, message: 'Invalid session. Send an initialize request without a session ID to start a new session.' },
        id: null,
      });
      return;
    }

    await transport.handleRequest(req, res, req.body);
  });

  // GET endpoint for SSE stream (optional notification support)
  app.get('/mcp', async (req, res) => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    if (!sessionId || !sessions.has(sessionId)) {
      res.status(400).json({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'Invalid or missing session ID' },
        id: null,
      });
      return;
    }
    const session = sessions.get(sessionId)!;
    await session.transport.handleRequest(req, res);
  });

  // DELETE endpoint for session cleanup
  app.delete('/mcp', async (req, res) => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    if (!sessionId || !sessions.has(sessionId)) {
      res.status(400).json({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'Invalid or missing session ID' },
        id: null,
      });
      return;
    }
    const session = sessions.get(sessionId)!;
    await session.transport.handleRequest(req, res);
  });

  const port = config.port;
  app.listen(port, () => {
    logger.info({ port, transport: 'streamable-http' }, 'SecurityScorecard MCP server running');
    logger.info(`MCP endpoint: http://localhost:${port}/mcp`);
    logger.info(`Health check: http://localhost:${port}/health`);
  });
}

// Main entry point
async function main(): Promise<void> {
  logger.info({
    transport: config.transportMode,
    nodeEnv: config.nodeEnv,
  }, 'Starting SecurityScorecard MCP server');

  if (config.transportMode === 'http') {
    await startHttpTransport();
  } else {
    await startStdioTransport();
  }
}

main().catch((error) => {
  logger.fatal({ err: error }, 'Failed to start server');
  process.exit(1);
});
