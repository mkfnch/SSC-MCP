import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { handleToolCall } from '../utils/error.js';

export function registerASITools(server: McpServer, ssc: SecurityScorecardService): void {
  server.tool(
    'search-attack-surface',
    'Search SecurityScorecard Attack Surface Intelligence (ASI) for exposed assets, services, and vulnerabilities',
    {
      query: z.string().describe('Search query (e.g., domain, IP range, CVE, technology)'),
      filters: z.record(z.unknown()).optional().describe('Additional search filters as key-value pairs'),
    },
    ({ query, filters }) => handleToolCall(() => ssc.searchAttackSurface(query, filters))
  );

  server.tool(
    'get-asset-details',
    'Get detailed information about a specific IP address/asset from Attack Surface Intelligence',
    { ip: z.string().describe('IP address of the asset') },
    ({ ip }) => handleToolCall(() => ssc.getAssetDetails(ip))
  );

  server.tool(
    'get-cve-details',
    'Get detailed information about a specific CVE from Attack Surface Intelligence',
    { cve: z.string().describe('CVE identifier (e.g., CVE-2024-1234)') },
    ({ cve }) => handleToolCall(() => ssc.getCveDetails(cve))
  );

  server.tool(
    'get-threat-actor-details',
    'Get detailed information about a specific threat actor group including tactics and targets',
    { name: z.string().describe('Threat actor name or group identifier') },
    ({ name }) => handleToolCall(() => ssc.getThreatActorDetails(name))
  );

  server.tool(
    'get-ransomware-details',
    'Get detailed information about a specific ransomware strain including affected organizations',
    { name: z.string().describe('Ransomware name or family') },
    ({ name }) => handleToolCall(() => ssc.getRansomwareDetails(name))
  );
}
