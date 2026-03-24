import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { handleToolCall } from '../utils/error.js';

export function registerVendorTools(server: McpServer, ssc: SecurityScorecardService): void {
  server.tool(
    'get-vendor-detection',
    'Discover third-party vendors and technologies used by a company',
    { domain: z.string().describe('Company domain (e.g., example.com)') },
    ({ domain }) => handleToolCall(() => ssc.getThirdPartyVendors(domain))
  );

  server.tool(
    'get-fourth-party-risk',
    'Discover fourth-party (supply chain) vendors - the vendors of your vendors',
    { domain: z.string().describe('Company domain (e.g., example.com)') },
    ({ domain }) => handleToolCall(() => ssc.getFourthPartyVendors(domain))
  );

  server.tool(
    'get-vendor-products',
    'Get products and technologies detected for a company domain',
    { domain: z.string().describe('Company domain (e.g., example.com)') },
    ({ domain }) => handleToolCall(() => ssc.getVendorProducts(domain))
  );

  server.tool(
    'get-vendor-risk',
    'Get the overall vendor risk score for a company',
    { domain: z.string().describe('Company domain (e.g., example.com)') },
    ({ domain }) => handleToolCall(() => ssc.getVendorRisk(domain))
  );

  server.tool(
    'get-portfolio-vendors',
    'Get third-party vendor analysis across all companies in a portfolio',
    { portfolio_id: z.string().describe('Portfolio ID') },
    ({ portfolio_id }) => handleToolCall(() => ssc.getPortfolioVendors(portfolio_id))
  );
}
