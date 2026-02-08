import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { formatMcpError } from '../utils/error.js';

export function registerASITools(server: McpServer, ssc: SecurityScorecardService): void {
  // ── search-attack-surface ──
  server.tool(
    'search-attack-surface',
    'Search SecurityScorecard Attack Surface Intelligence (ASI) for exposed assets, services, and vulnerabilities',
    {
      query: z.string().describe('Search query (e.g., domain, IP range, CVE, technology)'),
      filters: z.record(z.unknown()).optional().describe('Additional search filters as key-value pairs'),
    },
    async ({ query, filters }) => {
      try {
        const data = await ssc.searchAttackSurface(query, filters);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-asset-details ──
  server.tool(
    'get-asset-details',
    'Get detailed information about a specific IP address/asset from Attack Surface Intelligence',
    {
      ip: z.string().describe('IP address of the asset'),
    },
    async ({ ip }) => {
      try {
        const data = await ssc.getAssetDetails(ip);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-cve-details ──
  server.tool(
    'get-cve-details',
    'Get detailed information about a specific CVE from Attack Surface Intelligence',
    {
      cve: z.string().describe('CVE identifier (e.g., CVE-2024-1234)'),
    },
    async ({ cve }) => {
      try {
        const data = await ssc.getCveDetails(cve);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-threat-actor-details ──
  server.tool(
    'get-threat-actor-details',
    'Get detailed information about a specific threat actor group including tactics and targets',
    {
      name: z.string().describe('Threat actor name or group identifier'),
    },
    async ({ name }) => {
      try {
        const data = await ssc.getThreatActorDetails(name);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );

  // ── get-ransomware-details ──
  server.tool(
    'get-ransomware-details',
    'Get detailed information about a specific ransomware strain including affected organizations',
    {
      name: z.string().describe('Ransomware name or family'),
    },
    async ({ name }) => {
      try {
        const data = await ssc.getRansomwareDetails(name);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return { content: formatMcpError(error), isError: true };
      }
    }
  );
}
