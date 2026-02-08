import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { formatMcpError } from '../utils/error.js';

export function registerQuestionnaireTools(server: McpServer, ssc: SecurityScorecardService): void {
  // ── get-questionnaire-templates ──
  server.tool(
    'get-questionnaire-templates',
    'List available questionnaire templates (SIG, NIST, PCI, etc.) for your account',
    {},
    async () => {
      try {
        const data = await ssc.getAvailableTemplates();
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── send-questionnaire ──
  server.tool(
    'send-questionnaire',
    'Send a security questionnaire to a vendor/company for completion',
    {
      recipient_domain: z.string().describe('Domain of the company to send the questionnaire to'),
      template_id: z.string().describe('Template ID to use (get available templates first)'),
      message: z.string().optional().describe('Optional message to include with the questionnaire request'),
    },
    async ({ recipient_domain, template_id, message }) => {
      try {
        const data = await ssc.sendQuestionnaire({ recipient_domain, template_id, message });
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-questionnaire-status ──
  server.tool(
    'get-questionnaire-status',
    'Check the status of a sent questionnaire request',
    {
      request_id: z.string().describe('Questionnaire request ID'),
    },
    async ({ request_id }) => {
      try {
        const data = await ssc.getQuestionnaireStatus(request_id);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-questionnaire-responses ──
  server.tool(
    'get-questionnaire-responses',
    'Get the responses/answers from a completed questionnaire',
    {
      form_id: z.string().describe('Form ID of the questionnaire'),
    },
    async ({ form_id }) => {
      try {
        const data = await ssc.getQuestionnaireResponses(form_id);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );
}
