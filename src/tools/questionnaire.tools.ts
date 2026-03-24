import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { handleToolCall } from '../utils/error.js';
import { domainSchema, opaqueIdSchema } from '../utils/validation.js';

export function registerQuestionnaireTools(server: McpServer, ssc: SecurityScorecardService): void {
  server.tool(
    'get-questionnaire-templates',
    'List available questionnaire templates (SIG, NIST, PCI, etc.) for your account',
    {},
    () => handleToolCall(() => ssc.getAvailableTemplates())
  );

  server.tool(
    'send-questionnaire',
    'Send a security questionnaire to a vendor/company for completion',
    {
      recipient_domain: domainSchema.describe('Domain of the company to send the questionnaire to'),
      template_id: opaqueIdSchema.describe('Template ID to use (get available templates first)'),
      message: z
        .string()
        .max(2000)
        .optional()
        .describe('Optional message to include with the questionnaire request (max 2000 characters)'),
    },
    ({ recipient_domain, template_id, message }) =>
      handleToolCall(() => ssc.sendQuestionnaire({ recipient_domain, template_id, message }))
  );

  server.tool(
    'get-questionnaire-status',
    'Check the status of a sent questionnaire request',
    { request_id: opaqueIdSchema.describe('Questionnaire request ID') },
    ({ request_id }) => handleToolCall(() => ssc.getQuestionnaireStatus(request_id))
  );

  server.tool(
    'get-questionnaire-responses',
    'Get the responses/answers from a completed questionnaire',
    { form_id: opaqueIdSchema.describe('Form ID of the questionnaire') },
    ({ form_id }) => handleToolCall(() => ssc.getQuestionnaireResponses(form_id))
  );
}
