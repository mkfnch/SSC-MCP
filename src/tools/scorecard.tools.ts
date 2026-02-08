import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { formatMcpError } from '../utils/error.js';

export function registerScorecardTools(server: McpServer, ssc: SecurityScorecardService): void {
  // ── get-company-score ──
  server.tool(
    'get-company-score',
    'Retrieve the overall security score, grade (A-F), and factor breakdown for any company by domain',
    {
      domain: z.string().describe('Company domain (e.g., example.com)'),
    },
    async ({ domain }) => {
      try {
        const data = await ssc.getCompanyScore(domain);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-company-info ──
  server.tool(
    'get-company-info',
    'Get detailed company information including industry, size, and scorecard metadata',
    {
      domain: z.string().describe('Company domain (e.g., example.com)'),
    },
    async ({ domain }) => {
      try {
        const data = await ssc.getCompanyInfo(domain);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── search-companies ──
  server.tool(
    'search-companies',
    'Bulk search for multiple companies by their domains to get scores and grades',
    {
      domains: z.array(z.string()).min(1).max(100).describe('Array of company domains to search'),
    },
    async ({ domains }) => {
      try {
        const data = await ssc.searchCompanies(domains);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-factor-details ──
  server.tool(
    'get-factor-details',
    'Get detailed breakdown of all security factors (network security, patching cadence, etc.) for a company',
    {
      domain: z.string().describe('Company domain (e.g., example.com)'),
    },
    async ({ domain }) => {
      try {
        const data = await ssc.getFactorDetails(domain);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-historical-scores ──
  server.tool(
    'get-historical-scores',
    'Retrieve historical security score data for a company over time',
    {
      domain: z.string().describe('Company domain (e.g., example.com)'),
      from: z.string().optional().describe('Start date (YYYY-MM-DD format)'),
      to: z.string().optional().describe('End date (YYYY-MM-DD format)'),
    },
    async ({ domain, from, to }) => {
      try {
        const data = await ssc.getHistoricalScores(domain, from, to);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-historical-factor-scores ──
  server.tool(
    'get-historical-factor-scores',
    'Retrieve historical factor-level scores for a company over time',
    {
      domain: z.string().describe('Company domain (e.g., example.com)'),
      from: z.string().optional().describe('Start date (YYYY-MM-DD format)'),
      to: z.string().optional().describe('End date (YYYY-MM-DD format)'),
    },
    async ({ domain, from, to }) => {
      try {
        const data = await ssc.getHistoricalFactorScores(domain, from, to);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-active-issues ──
  server.tool(
    'get-active-issues',
    'Get a summary of all active security issues for a company, grouped by type and severity',
    {
      domain: z.string().describe('Company domain (e.g., example.com)'),
    },
    async ({ domain }) => {
      try {
        const data = await ssc.getActiveIssues(domain);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-expanded-risk ──
  server.tool(
    'get-expanded-risk',
    'Get expanded risk analysis for a company including supply chain and concentration risk',
    {
      domain: z.string().describe('Company domain (e.g., example.com)'),
    },
    async ({ domain }) => {
      try {
        const data = await ssc.getExpandedRisk(domain);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-score-improvement-plan ──
  server.tool(
    'get-score-improvement-plan',
    'Get recommendations for how a company can improve their security score to a target level',
    {
      domain: z.string().describe('Company domain (e.g., example.com)'),
      target_score: z.number().min(0).max(100).describe('Target score to achieve (0-100)'),
    },
    async ({ domain, target_score }) => {
      try {
        const data = await ssc.getScoreImprovementPlan(domain, target_score);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );
}
