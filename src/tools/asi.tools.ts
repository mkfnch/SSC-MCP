import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { handleToolCall } from '../utils/error.js';
import { cveIdSchema, ipAddressSchema } from '../utils/validation.js';

export function registerASITools(server: McpServer, ssc: SecurityScorecardService): void {
  server.tool(
    'search-attack-surface',
    'Search SecurityScorecard Attack Surface Intelligence (ASI) for exposed assets, services, and vulnerabilities',
    {
      query: z.string().min(1).max(500).describe('Search query (e.g., domain, IP range, CVE, technology)'),
      filters: z
        .record(z.union([z.string(), z.number(), z.boolean()]))
        .optional()
        .describe('Additional search filters as key-value pairs'),
    },
    ({ query, filters }) => handleToolCall(() => ssc.searchAttackSurface(query, filters))
  );

  server.tool(
    'get-asset-details',
    'Get detailed information about a specific IP address/asset from Attack Surface Intelligence',
    { ip: ipAddressSchema.describe('IP address of the asset (IPv4 or IPv6)') },
    ({ ip }) => handleToolCall(() => ssc.getAssetDetails(ip))
  );

  server.tool(
    'get-cve-details',
    'Get detailed information about a specific CVE from Attack Surface Intelligence',
    { cve: cveIdSchema.describe('CVE identifier (e.g., CVE-2024-12345)') },
    ({ cve }) => handleToolCall(() => ssc.getCveDetails(cve))
  );

  server.tool(
    'get-threat-actor-details',
    'Get detailed information about a specific threat actor group including tactics and targets',
    {
      name: z
        .string()
        .min(1)
        .max(200)
        .regex(/^[a-zA-Z0-9\s\-_.]+$/, 'Threat actor name contains invalid characters')
        .describe('Threat actor name or group identifier'),
    },
    ({ name }) => handleToolCall(() => ssc.getThreatActorDetails(name))
  );

  server.tool(
    'get-ransomware-details',
    'Get detailed information about a specific ransomware strain including affected organizations',
    {
      name: z
        .string()
        .min(1)
        .max(200)
        .regex(/^[a-zA-Z0-9\s\-_.]+$/, 'Ransomware name contains invalid characters')
        .describe('Ransomware name or family'),
    },
    ({ name }) => handleToolCall(() => ssc.getRansomwareDetails(name))
  );
}
