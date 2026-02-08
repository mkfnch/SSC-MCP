import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SecurityScorecardService } from '../services/securityscorecard.service.js';
import { registerScorecardTools } from './scorecard.tools.js';
import { registerPortfolioTools } from './portfolio.tools.js';
import { registerFindingsTools } from './findings.tools.js';
import { registerQuestionnaireTools } from './questionnaire.tools.js';
import { registerVendorTools } from './vendor.tools.js';
import { registerActionPlanTools } from './actionplan.tools.js';
import { registerASITools } from './asi.tools.js';
import { registerEventsTools } from './events.tools.js';

export function registerAllTools(server: McpServer, ssc: SecurityScorecardService): void {
  // Phase 1: Core tools (scorecards, portfolios, findings)
  registerScorecardTools(server, ssc);
  registerPortfolioTools(server, ssc);
  registerFindingsTools(server, ssc);

  // Phase 2: Advanced analytics (vendors)
  registerVendorTools(server, ssc);

  // Phase 3: Collaboration (questionnaires, action plans)
  registerQuestionnaireTools(server, ssc);
  registerActionPlanTools(server, ssc);

  // Phase 4: Real-time and advanced (ASI, events, reports)
  registerASITools(server, ssc);
  registerEventsTools(server, ssc);
}
