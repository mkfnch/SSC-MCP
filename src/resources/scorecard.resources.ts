import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { formatMcpError } from '../utils/error.js';

export function registerResources(server: McpServer, ssc: SecurityScorecardService): void {
  // Resource: Company scorecard by domain
  server.resource(
    'scorecard',
    'scorecard://{domain}',
    {
      description: 'Security scorecard for a company identified by domain',
      mimeType: 'application/json',
    },
    async (uri) => {
      const domain = uri.pathname.replace(/^\/\//, '');
      try {
        const data = await ssc.getCompanyScore(domain);
        return {
          contents: [{
            uri: uri.href,
            mimeType: 'application/json',
            text: JSON.stringify(data, null, 2),
          }],
        };
      } catch (error) {
        const errorContent = formatMcpError(error);
        return {
          contents: [{
            uri: uri.href,
            mimeType: 'application/json',
            text: errorContent[0].text,
          }],
        };
      }
    }
  );

  // Resource: Portfolio listing
  server.resource(
    'portfolios',
    'portfolios://list',
    {
      description: 'List of all SecurityScorecard portfolios',
      mimeType: 'application/json',
    },
    async (uri) => {
      try {
        const data = await ssc.listPortfolios();
        return {
          contents: [{
            uri: uri.href,
            mimeType: 'application/json',
            text: JSON.stringify(data, null, 2),
          }],
        };
      } catch (error) {
        const errorContent = formatMcpError(error);
        return {
          contents: [{
            uri: uri.href,
            mimeType: 'application/json',
            text: errorContent[0].text,
          }],
        };
      }
    }
  );
}
