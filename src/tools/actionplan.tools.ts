import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { handleToolCall, handleVoidToolCall } from '../utils/error.js';

export function registerActionPlanTools(server: McpServer, ssc: SecurityScorecardService): void {
  server.tool(
    'list-action-plans',
    'List all action plans in your SecurityScorecard account',
    {},
    () => handleToolCall(() => ssc.listActionPlans())
  );

  server.tool(
    'create-issue-resolution-plan',
    'Create an action plan to resolve specific security issue types by a target date',
    {
      name: z.string().min(1).describe('Plan name'),
      target_date: z.string().describe('Target completion date (YYYY-MM-DD)'),
      issue_types: z.array(z.string()).min(1).describe('Issue types to resolve (e.g., ["open_port", "malware_infection"])'),
      domains: z.array(z.string()).optional().describe('Specific domains to target (optional, defaults to all)'),
    },
    ({ name, target_date, issue_types, domains }) =>
      handleToolCall(() => ssc.createIssueResolutionPlan({ name, target_date, issue_types, domains }))
  );

  server.tool(
    'create-score-improvement-plan',
    'Create an action plan to improve overall security score to a target level',
    {
      name: z.string().min(1).describe('Plan name'),
      target_date: z.string().describe('Target completion date (YYYY-MM-DD)'),
      target_score: z.number().min(0).max(100).describe('Target score to achieve (0-100)'),
    },
    ({ name, target_date, target_score }) =>
      handleToolCall(() => ssc.createScoreImprovementPlan({ name, target_date, target_score }))
  );

  server.tool(
    'delete-action-plan',
    'Delete an existing action plan',
    { plan_id: z.string().describe('Action plan ID to delete') },
    ({ plan_id }) => handleVoidToolCall(
      () => ssc.deleteActionPlan(plan_id),
      `Action plan ${plan_id} deleted`
    )
  );
}
