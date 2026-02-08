import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { formatMcpError } from '../utils/error.js';

export function registerEventsTools(server: McpServer, ssc: SecurityScorecardService): void {
  // ── get-security-events ──
  server.tool(
    'get-security-events',
    'Get security events and changes for a company over a time period',
    {
      domain: z.string().describe('Company domain (e.g., example.com)'),
      from: z.string().optional().describe('Start date (YYYY-MM-DD format)'),
      to: z.string().optional().describe('End date (YYYY-MM-DD format)'),
    },
    async ({ domain, from, to }) => {
      try {
        const data = await ssc.getSecurityEvents(domain, { from, to });
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-breach-events ──
  server.tool(
    'get-breach-events',
    'Get breach-related events for a company including data leaks and compromises',
    {
      domain: z.string().describe('Company domain (e.g., example.com)'),
    },
    async ({ domain }) => {
      try {
        const data = await ssc.getBreachEvents(domain);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── generate-report ──
  server.tool(
    'generate-report',
    'Generate a summary security report for a company',
    {
      domain: z.string().describe('Company domain (e.g., example.com)'),
      report_type: z.enum(['summary', 'detailed', 'full-scorecard']).describe('Report type: summary, detailed, or full-scorecard'),
    },
    async ({ domain, report_type }) => {
      try {
        let data;
        switch (report_type) {
          case 'summary':
            data = await ssc.generateSummaryReport(domain);
            break;
          case 'detailed':
            data = await ssc.generateDetailedReport(domain);
            break;
          case 'full-scorecard':
            data = await ssc.generateFullScorecardJson(domain);
            break;
        }
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── list-recent-reports ──
  server.tool(
    'list-recent-reports',
    'List recently generated reports available for download',
    {},
    async () => {
      try {
        const data = await ssc.listRecentReports();
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );
}
