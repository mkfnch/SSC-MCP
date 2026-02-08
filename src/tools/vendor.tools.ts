import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { formatMcpError } from '../utils/error.js';

export function registerVendorTools(server: McpServer, ssc: SecurityScorecardService): void {
  // ── get-vendor-detection ──
  server.tool(
    'get-vendor-detection',
    'Discover third-party vendors and technologies used by a company',
    {
      domain: z.string().describe('Company domain (e.g., example.com)'),
    },
    async ({ domain }) => {
      try {
        const data = await ssc.getThirdPartyVendors(domain);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-fourth-party-risk ──
  server.tool(
    'get-fourth-party-risk',
    'Discover fourth-party (supply chain) vendors - the vendors of your vendors',
    {
      domain: z.string().describe('Company domain (e.g., example.com)'),
    },
    async ({ domain }) => {
      try {
        const data = await ssc.getFourthPartyVendors(domain);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-vendor-products ──
  server.tool(
    'get-vendor-products',
    'Get products and technologies detected for a company domain',
    {
      domain: z.string().describe('Company domain (e.g., example.com)'),
    },
    async ({ domain }) => {
      try {
        const data = await ssc.getVendorProducts(domain);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-vendor-risk ──
  server.tool(
    'get-vendor-risk',
    'Get the overall vendor risk score for a company',
    {
      domain: z.string().describe('Company domain (e.g., example.com)'),
    },
    async ({ domain }) => {
      try {
        const data = await ssc.getVendorRisk(domain);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-portfolio-vendors ──
  server.tool(
    'get-portfolio-vendors',
    'Get third-party vendor analysis across all companies in a portfolio',
    {
      portfolio_id: z.string().describe('Portfolio ID'),
    },
    async ({ portfolio_id }) => {
      try {
        const data = await ssc.getPortfolioVendors(portfolio_id);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );
}
