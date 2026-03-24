import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { handleToolCall } from '../utils/error.js';

export function registerFindingsTools(server: McpServer, ssc: SecurityScorecardService): void {
  server.tool(
    'get-issue-details',
    'Get detailed information about a specific type of security issue for a company',
    {
      domain: z.string().describe('Company domain (e.g., example.com)'),
      issue_type: z.string().describe('Issue type (e.g., open_port, malware_infection, csp_no_policy_v2, compromised_credentials_found)'),
      page: z.number().int().min(1).optional().describe('Page number (default: 1)'),
      size: z.number().int().min(1).max(100).optional().describe('Results per page (default: 50)'),
    },
    ({ domain, issue_type, page, size }) => handleToolCall(() => ssc.getIssueDetails(domain, issue_type, { page, size }))
  );

  server.tool(
    'get-issue-context',
    'Get scoring context and impact information for a specific issue type',
    {
      domain: z.string().describe('Company domain (e.g., example.com)'),
      issue_type: z.string().describe('Issue type to get context for'),
    },
    ({ domain, issue_type }) => handleToolCall(() => ssc.getIssueContext(domain, issue_type))
  );

  server.tool(
    'get-industry-benchmark',
    'Get the average security score and grade for a specific industry vertical',
    {
      industry: z.string().describe('Industry name (e.g., technology, healthcare, financial_services, retail, manufacturing, education, government, energy, telecommunications)'),
    },
    ({ industry }) => handleToolCall(() => ssc.getIndustryScore(industry))
  );

  server.tool(
    'get-industry-factors',
    'Get factor-level score breakdown for an industry benchmark',
    { industry: z.string().describe('Industry name (e.g., technology, healthcare, financial_services)') },
    ({ industry }) => handleToolCall(() => ssc.getIndustryFactors(industry))
  );

  server.tool(
    'get-industry-historical-scores',
    'Get historical score trends for an industry over time',
    {
      industry: z.string().describe('Industry name (e.g., technology, healthcare)'),
      from: z.string().optional().describe('Start date (YYYY-MM-DD format)'),
      to: z.string().optional().describe('End date (YYYY-MM-DD format)'),
    },
    ({ industry, from, to }) => handleToolCall(() => ssc.getIndustryHistoricalScores(industry, from, to))
  );
}
