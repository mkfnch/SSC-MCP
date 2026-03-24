import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { handleToolCall } from '../utils/error.js';
import { domainSchema, isodateSchema } from '../utils/validation.js';

export function registerScorecardTools(server: McpServer, ssc: SecurityScorecardService): void {
  server.tool(
    'get-company-score',
    'Retrieve the overall security score, grade (A-F), and factor breakdown for any company by domain',
    { domain: domainSchema.describe('Company domain (e.g., example.com)') },
    ({ domain }) => handleToolCall(() => ssc.getCompanyScore(domain))
  );

  server.tool(
    'get-company-info',
    'Get detailed company information including industry, size, and scorecard metadata',
    { domain: domainSchema.describe('Company domain (e.g., example.com)') },
    ({ domain }) => handleToolCall(() => ssc.getCompanyInfo(domain))
  );

  server.tool(
    'search-companies',
    'Bulk search for multiple companies by their domains to get scores and grades',
    {
      domains: z
        .array(domainSchema)
        .min(1)
        .max(100)
        .describe('Array of company domains to search'),
    },
    ({ domains }) => handleToolCall(() => ssc.searchCompanies(domains))
  );

  server.tool(
    'get-factor-details',
    'Get detailed breakdown of all security factors (network security, patching cadence, etc.) for a company',
    { domain: domainSchema.describe('Company domain (e.g., example.com)') },
    ({ domain }) => handleToolCall(() => ssc.getFactorDetails(domain))
  );

  server.tool(
    'get-historical-scores',
    'Retrieve historical security score data for a company over time',
    {
      domain: domainSchema.describe('Company domain (e.g., example.com)'),
      from: isodateSchema.optional().describe('Start date (YYYY-MM-DD)'),
      to: isodateSchema.optional().describe('End date (YYYY-MM-DD)'),
    },
    ({ domain, from, to }) => handleToolCall(() => ssc.getHistoricalScores(domain, from, to))
  );

  server.tool(
    'get-historical-factor-scores',
    'Retrieve historical factor-level scores for a company over time',
    {
      domain: domainSchema.describe('Company domain (e.g., example.com)'),
      from: isodateSchema.optional().describe('Start date (YYYY-MM-DD)'),
      to: isodateSchema.optional().describe('End date (YYYY-MM-DD)'),
    },
    ({ domain, from, to }) => handleToolCall(() => ssc.getHistoricalFactorScores(domain, from, to))
  );

  server.tool(
    'get-active-issues',
    'Get a summary of all active security issues for a company, grouped by type and severity',
    { domain: domainSchema.describe('Company domain (e.g., example.com)') },
    ({ domain }) => handleToolCall(() => ssc.getActiveIssues(domain))
  );

  server.tool(
    'get-expanded-risk',
    'Get expanded risk analysis for a company including supply chain and concentration risk',
    { domain: domainSchema.describe('Company domain (e.g., example.com)') },
    ({ domain }) => handleToolCall(() => ssc.getExpandedRisk(domain))
  );

  server.tool(
    'get-score-improvement-plan',
    'Get recommendations for how a company can improve their security score to a target level',
    {
      domain: domainSchema.describe('Company domain (e.g., example.com)'),
      target_score: z.number().min(0).max(100).describe('Target score to achieve (0-100)'),
    },
    ({ domain, target_score }) => handleToolCall(() => ssc.getScoreImprovementPlan(domain, target_score))
  );
}
