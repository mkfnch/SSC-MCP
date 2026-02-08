import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { formatMcpError } from '../utils/error.js';

export function registerPortfolioTools(server: McpServer, ssc: SecurityScorecardService): void {
  // ── list-portfolios ──
  server.tool(
    'list-portfolios',
    'List all security monitoring portfolios in your SecurityScorecard account',
    {},
    async () => {
      try {
        const data = await ssc.listPortfolios();
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-portfolio-companies ──
  server.tool(
    'get-portfolio-companies',
    'List all companies within a specific portfolio with their scores and grades',
    {
      portfolio_id: z.string().describe('Portfolio ID'),
      page: z.number().int().min(1).optional().describe('Page number (default: 1)'),
      size: z.number().int().min(1).max(200).optional().describe('Results per page (default: 50, max: 200)'),
    },
    async ({ portfolio_id, page, size }) => {
      try {
        const data = await ssc.getPortfolioCompanies(portfolio_id, { page, size });
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── create-portfolio ──
  server.tool(
    'create-portfolio',
    'Create a new portfolio for monitoring a group of companies',
    {
      name: z.string().min(1).describe('Portfolio name'),
      description: z.string().optional().describe('Portfolio description'),
      privacy: z.enum(['private', 'shared']).optional().describe('Portfolio visibility (default: private)'),
    },
    async ({ name, description, privacy }) => {
      try {
        const data = await ssc.createPortfolio(name, description, privacy);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── update-portfolio ──
  server.tool(
    'update-portfolio',
    'Update an existing portfolio name or description',
    {
      portfolio_id: z.string().describe('Portfolio ID'),
      name: z.string().min(1).describe('New portfolio name'),
      description: z.string().optional().describe('New portfolio description'),
    },
    async ({ portfolio_id, name, description }) => {
      try {
        const data = await ssc.updatePortfolio(portfolio_id, name, description);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── delete-portfolio ──
  server.tool(
    'delete-portfolio',
    'Delete a portfolio (does not affect the companies within it)',
    {
      portfolio_id: z.string().describe('Portfolio ID to delete'),
    },
    async ({ portfolio_id }) => {
      try {
        await ssc.deletePortfolio(portfolio_id);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Portfolio ${portfolio_id} deleted` }) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── add-company-to-portfolio ──
  server.tool(
    'add-company-to-portfolio',
    'Add a company to an existing portfolio for monitoring',
    {
      portfolio_id: z.string().describe('Portfolio ID'),
      domain: z.string().describe('Company domain to add (e.g., example.com)'),
    },
    async ({ portfolio_id, domain }) => {
      try {
        await ssc.addCompanyToPortfolio(portfolio_id, domain);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `${domain} added to portfolio ${portfolio_id}` }) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── remove-company-from-portfolio ──
  server.tool(
    'remove-company-from-portfolio',
    'Remove a company from a portfolio',
    {
      portfolio_id: z.string().describe('Portfolio ID'),
      domain: z.string().describe('Company domain to remove (e.g., example.com)'),
    },
    async ({ portfolio_id, domain }) => {
      try {
        await ssc.removeCompanyFromPortfolio(portfolio_id, domain);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `${domain} removed from portfolio ${portfolio_id}` }) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-portfolio-risk ──
  server.tool(
    'get-portfolio-risk',
    'Get expanded risk analysis for all companies in a portfolio',
    {
      portfolio_id: z.string().describe('Portfolio ID'),
    },
    async ({ portfolio_id }) => {
      try {
        const data = await ssc.getPortfolioExpandedRisk(portfolio_id);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );
}
