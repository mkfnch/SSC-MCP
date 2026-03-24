import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { handleToolCall } from '../utils/error.js';
import { domainSchema, isodateSchema } from '../utils/validation.js';

const ISSUE_TYPES = [
  'active_cve_exploitation_attempted',
  'cve_in_use_by_threat_actor',
  'potentially_vulnerable',
  'exploited_product',
  'adware_installation',
  'malware_infection',
  'ransomware_infection',
  'malware_detected',
  'attack_detected',
  'open_port',
  'insecure_ftp',
  'ssh_weak_cipher',
  'csp_no_policy_v2',
  'domain_missing_https_v2',
  'hsts_incorrect_v2',
  'compromised_credentials_found',
  'data_leak_detected',
  'alleged_breach_incident',
  'ransomware_victim',
  'targeted_by_threat_actor_group',
] as const;

export function registerFindingsTools(server: McpServer, ssc: SecurityScorecardService): void {
  server.tool(
    'get-issue-details',
    'Get detailed information about a specific type of security issue for a company',
    {
      domain: domainSchema.describe('Company domain (e.g., example.com)'),
      issue_type: z
        .string()
        .min(1)
        .max(100)
        .regex(/^[a-zA-Z0-9_-]+$/, 'Issue type must be alphanumeric with underscores/hyphens')
        .describe(
          `Issue type to query. Common types: ${ISSUE_TYPES.slice(0, 10).join(', ')}, and more`
        ),
      page: z.number().int().min(1).max(10_000).optional().describe('Page number (default: 1)'),
      size: z.number().int().min(1).max(100).optional().describe('Results per page (default: 50)'),
    },
    ({ domain, issue_type, page, size }) => handleToolCall(() => ssc.getIssueDetails(domain, issue_type, { page, size }))
  );

  server.tool(
    'get-issue-context',
    'Get scoring context and impact information for a specific issue type',
    {
      domain: domainSchema.describe('Company domain (e.g., example.com)'),
      issue_type: z
        .string()
        .min(1)
        .max(100)
        .regex(/^[a-zA-Z0-9_-]+$/, 'Issue type must be alphanumeric with underscores/hyphens')
        .describe('Issue type to get context for'),
    },
    ({ domain, issue_type }) => handleToolCall(() => ssc.getIssueContext(domain, issue_type))
  );

  server.tool(
    'get-industry-benchmark',
    'Get the average security score and grade for a specific industry vertical',
    {
      industry: z
        .string()
        .min(1)
        .max(100)
        .regex(/^[a-zA-Z0-9_-]+$/, 'Industry name must be alphanumeric with underscores/hyphens')
        .describe(
          'Industry name (e.g., technology, healthcare, financial_services, retail, manufacturing, education, government, energy, telecommunications)'
        ),
    },
    ({ industry }) => handleToolCall(() => ssc.getIndustryScore(industry))
  );

  server.tool(
    'get-industry-factors',
    'Get factor-level score breakdown for an industry benchmark',
    {
      industry: z
        .string()
        .min(1)
        .max(100)
        .regex(/^[a-zA-Z0-9_-]+$/, 'Industry name must be alphanumeric with underscores/hyphens')
        .describe('Industry name (e.g., technology, healthcare, financial_services)'),
    },
    ({ industry }) => handleToolCall(() => ssc.getIndustryFactors(industry))
  );

  server.tool(
    'get-industry-historical-scores',
    'Get historical score trends for an industry over time',
    {
      industry: z
        .string()
        .min(1)
        .max(100)
        .regex(/^[a-zA-Z0-9_-]+$/, 'Industry name must be alphanumeric with underscores/hyphens')
        .describe('Industry name (e.g., technology, healthcare)'),
      from: isodateSchema.optional().describe('Start date (YYYY-MM-DD)'),
      to: isodateSchema.optional().describe('End date (YYYY-MM-DD)'),
    },
    ({ industry, from, to }) => handleToolCall(() => ssc.getIndustryHistoricalScores(industry, from, to))
  );
}
