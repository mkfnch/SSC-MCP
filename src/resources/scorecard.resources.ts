import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { formatResourceError } from '../utils/error.js';

export function registerResources(server: McpServer, ssc: SecurityScorecardService): void {
  server.resource(
    'scorecard',
    'scorecard://{domain}',
    { description: 'Security scorecard for a company identified by domain', mimeType: 'application/json' },
    async (uri) => {
      const domain = uri.pathname.replace(/^\/\//, '');
      try {
        const data = await ssc.getCompanyScore(domain);
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(data, null, 2) }] };
      } catch (error) {
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: formatResourceError(error) }] };
      }
    }
  );

  server.resource(
    'portfolios',
    'portfolios://list',
    { description: 'List of all SecurityScorecard portfolios', mimeType: 'application/json' },
    async (uri) => {
      try {
        const data = await ssc.listPortfolios();
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(data, null, 2) }] };
      } catch (error) {
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: formatResourceError(error) }] };
      }
    }
  );
}
