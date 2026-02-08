import pino from 'pino';

const isStdioMode = (process.env.TRANSPORT_MODE || 'stdio') === 'stdio';

export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: isStdioMode
    ? { target: 'pino/file', options: { destination: 2 } } // stderr in stdio mode
    : undefined,
  formatters: {
    level: (label) => ({ level: label }),
  },
  timestamp: pino.stdTimeFunctions.isoTime,
});
