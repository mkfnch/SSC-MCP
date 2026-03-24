import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { handleToolCall, handleVoidToolCall } from '../utils/error.js';

export function registerPortfolioTools(server: McpServer, ssc: SecurityScorecardService): void {
  server.tool(
    'list-portfolios',
    'List all security monitoring portfolios in your SecurityScorecard account',
    {},
    () => handleToolCall(() => ssc.listPortfolios())
  );

  server.tool(
    'get-portfolio-companies',
    'List all companies within a specific portfolio with their scores and grades',
    {
      portfolio_id: z.string().describe('Portfolio ID'),
      page: z.number().int().min(1).optional().describe('Page number (default: 1)'),
      size: z.number().int().min(1).max(200).optional().describe('Results per page (default: 50, max: 200)'),
    },
    ({ portfolio_id, page, size }) => handleToolCall(() => ssc.getPortfolioCompanies(portfolio_id, { page, size }))
  );

  server.tool(
    'create-portfolio',
    'Create a new portfolio for monitoring a group of companies',
    {
      name: z.string().min(1).describe('Portfolio name'),
      description: z.string().optional().describe('Portfolio description'),
      privacy: z.enum(['private', 'shared']).optional().describe('Portfolio visibility (default: private)'),
    },
    ({ name, description, privacy }) => handleToolCall(() => ssc.createPortfolio(name, description, privacy))
  );

  server.tool(
    'update-portfolio',
    'Update an existing portfolio name or description',
    {
      portfolio_id: z.string().describe('Portfolio ID'),
      name: z.string().min(1).describe('New portfolio name'),
      description: z.string().optional().describe('New portfolio description'),
    },
    ({ portfolio_id, name, description }) => handleToolCall(() => ssc.updatePortfolio(portfolio_id, name, description))
  );

  server.tool(
    'delete-portfolio',
    'Delete a portfolio (does not affect the companies within it)',
    { portfolio_id: z.string().describe('Portfolio ID to delete') },
    ({ portfolio_id }) => handleVoidToolCall(
      () => ssc.deletePortfolio(portfolio_id),
      `Portfolio ${portfolio_id} deleted`
    )
  );

  server.tool(
    'add-company-to-portfolio',
    'Add a company to an existing portfolio for monitoring',
    {
      portfolio_id: z.string().describe('Portfolio ID'),
      domain: z.string().describe('Company domain to add (e.g., example.com)'),
    },
    ({ portfolio_id, domain }) => handleVoidToolCall(
      () => ssc.addCompanyToPortfolio(portfolio_id, domain),
      `${domain} added to portfolio ${portfolio_id}`
    )
  );

  server.tool(
    'remove-company-from-portfolio',
    'Remove a company from a portfolio',
    {
      portfolio_id: z.string().describe('Portfolio ID'),
      domain: z.string().describe('Company domain to remove (e.g., example.com)'),
    },
    ({ portfolio_id, domain }) => handleVoidToolCall(
      () => ssc.removeCompanyFromPortfolio(portfolio_id, domain),
      `${domain} removed from portfolio ${portfolio_id}`
    )
  );

  server.tool(
    'get-portfolio-risk',
    'Get expanded risk analysis for all companies in a portfolio',
    { portfolio_id: z.string().describe('Portfolio ID') },
    ({ portfolio_id }) => handleToolCall(() => ssc.getPortfolioExpandedRisk(portfolio_id))
  );
}
