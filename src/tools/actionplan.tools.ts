import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { formatMcpError } from '../utils/error.js';

export function registerActionPlanTools(server: McpServer, ssc: SecurityScorecardService): void {
  // ── list-action-plans ──
  server.tool(
    'list-action-plans',
    'List all action plans in your SecurityScorecard account',
    {},
    async () => {
      try {
        const data = await ssc.listActionPlans();
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── create-issue-resolution-plan ──
  server.tool(
    'create-issue-resolution-plan',
    'Create an action plan to resolve specific security issue types by a target date',
    {
      name: z.string().min(1).describe('Plan name'),
      target_date: z.string().describe('Target completion date (YYYY-MM-DD)'),
      issue_types: z.array(z.string()).min(1).describe('Issue types to resolve (e.g., ["open_port", "malware_infection"])'),
      domains: z.array(z.string()).optional().describe('Specific domains to target (optional, defaults to all)'),
    },
    async ({ name, target_date, issue_types, domains }) => {
      try {
        const data = await ssc.createIssueResolutionPlan({ name, target_date, issue_types, domains });
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── create-score-improvement-plan ──
  server.tool(
    'create-score-improvement-plan',
    'Create an action plan to improve overall security score to a target level',
    {
      name: z.string().min(1).describe('Plan name'),
      target_date: z.string().describe('Target completion date (YYYY-MM-DD)'),
      target_score: z.number().min(0).max(100).describe('Target score to achieve (0-100)'),
    },
    async ({ name, target_date, target_score }) => {
      try {
        const data = await ssc.createScoreImprovementPlan({ name, target_date, target_score });
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── delete-action-plan ──
  server.tool(
    'delete-action-plan',
    'Delete an existing action plan',
    {
      plan_id: z.string().describe('Action plan ID to delete'),
    },
    async ({ plan_id }) => {
      try {
        await ssc.deleteActionPlan(plan_id);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Action plan ${plan_id} deleted` }) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );
}
