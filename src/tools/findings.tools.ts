import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { formatMcpError } from '../utils/error.js';

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
  // ── get-issue-details ──
  server.tool(
    'get-issue-details',
    'Get detailed information about a specific type of security issue for a company',
    {
      domain: z.string().describe('Company domain (e.g., example.com)'),
      issue_type: z.string().describe(
        `Issue type to query. Common types: ${ISSUE_TYPES.slice(0, 10).join(', ')}, and more`
      ),
      page: z.number().int().min(1).optional().describe('Page number (default: 1)'),
      size: z.number().int().min(1).max(100).optional().describe('Results per page (default: 50)'),
    },
    async ({ domain, issue_type, page, size }) => {
      try {
        const data = await ssc.getIssueDetails(domain, issue_type, { page, size });
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-issue-context ──
  server.tool(
    'get-issue-context',
    'Get scoring context and impact information for a specific issue type',
    {
      domain: z.string().describe('Company domain (e.g., example.com)'),
      issue_type: z.string().describe('Issue type to get context for'),
    },
    async ({ domain, issue_type }) => {
      try {
        const data = await ssc.getIssueContext(domain, issue_type);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-industry-benchmark ──
  server.tool(
    'get-industry-benchmark',
    'Get the average security score and grade for a specific industry vertical',
    {
      industry: z.string().describe('Industry name (e.g., technology, healthcare, financial_services, retail, manufacturing, education, government, energy, telecommunications)'),
    },
    async ({ industry }) => {
      try {
        const data = await ssc.getIndustryScore(industry);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-industry-factors ──
  server.tool(
    'get-industry-factors',
    'Get factor-level score breakdown for an industry benchmark',
    {
      industry: z.string().describe('Industry name (e.g., technology, healthcare, financial_services)'),
    },
    async ({ industry }) => {
      try {
        const data = await ssc.getIndustryFactors(industry);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-industry-historical-scores ──
  server.tool(
    'get-industry-historical-scores',
    'Get historical score trends for an industry over time',
    {
      industry: z.string().describe('Industry name (e.g., technology, healthcare)'),
      from: z.string().optional().describe('Start date (YYYY-MM-DD format)'),
      to: z.string().optional().describe('End date (YYYY-MM-DD format)'),
    },
    async ({ industry, from, to }) => {
      try {
        const data = await ssc.getIndustryHistoricalScores(industry, from, to);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );
}
