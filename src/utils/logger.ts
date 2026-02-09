import pino from 'pino';

const isStdioMode = (process.env.TRANSPORT_MODE || 'stdio') === 'stdio';

export const logger = pino(
  {
    level: process.env.LOG_LEVEL || 'info',
    formatters: {
      level: (label) => ({ level: label }),
    },
    timestamp: pino.stdTimeFunctions.isoTime,
  },
  // Use synchronous destination to stderr (fd 2) in stdio mode.
  // Pino's transport worker threads can leak output to stdout during init,
  // which corrupts the MCP JSON-RPC protocol and causes disconnections.
  isStdioMode ? pino.destination({ dest: 2, sync: true }) : undefined
);
