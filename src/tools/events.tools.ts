import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { handleToolCall } from '../utils/error.js';
import { domainSchema, isodateSchema } from '../utils/validation.js';

export function registerEventsTools(server: McpServer, ssc: SecurityScorecardService): void {
  server.tool(
    'get-security-events',
    'Get security events and changes for a company over a time period',
    {
      domain: domainSchema.describe('Company domain (e.g., example.com)'),
      from: isodateSchema.optional().describe('Start date (YYYY-MM-DD)'),
      to: isodateSchema.optional().describe('End date (YYYY-MM-DD)'),
    },
    ({ domain, from, to }) => handleToolCall(() => ssc.getSecurityEvents(domain, { from, to }))
  );

  server.tool(
    'get-breach-events',
    'Get breach-related events for a company including data leaks and compromises',
    { domain: domainSchema.describe('Company domain (e.g., example.com)') },
    ({ domain }) => handleToolCall(() => ssc.getBreachEvents(domain))
  );

  server.tool(
    'generate-report',
    'Generate a summary security report for a company',
    {
      domain: domainSchema.describe('Company domain (e.g., example.com)'),
      report_type: z
        .enum(['summary', 'detailed', 'full-scorecard'])
        .describe('Report type: summary, detailed, or full-scorecard'),
    },
    ({ domain, report_type }) => {
      const generators = {
        'summary': () => ssc.generateSummaryReport(domain),
        'detailed': () => ssc.generateDetailedReport(domain),
        'full-scorecard': () => ssc.generateFullScorecardJson(domain),
      } as const;
      return handleToolCall(generators[report_type]);
    }
  );

  server.tool(
    'list-recent-reports',
    'List recently generated reports available for download',
    {},
    () => handleToolCall(() => ssc.listRecentReports())
  );
}
