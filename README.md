# SecurityScorecard MCP Connector

A production-grade Model Context Protocol (MCP) server that integrates SecurityScorecard's cyber risk intelligence platform with Claude and other MCP-compatible AI assistants.

## Features

- **Security Ratings**: Retrieve company security scores, grades (A-F), and factor breakdowns
- **Portfolio Management**: Create, manage, and analyze portfolios of monitored companies
- **Findings & Issues**: Access detailed security findings, active issues, and vulnerability data
- **Vendor Risk Intelligence**: Discover third-party and fourth-party vendor relationships
- **Attack Surface Intelligence**: Search exposed assets, CVEs, threat actors, and ransomware data
- **Questionnaires**: Send and manage security assessment questionnaires (SIG, NIST, PCI)
- **Action Plans**: Create and track security improvement plans
- **Reports**: Generate summary, detailed, and full scorecard reports
- **Industry Benchmarks**: Compare companies against industry averages

## Quick Start

### Prerequisites

- Node.js 18+
- SecurityScorecard API key ([generate one here](https://platform.securityscorecard.io))

### Installation

```bash
npm install
npm run build
```

### Running with Claude Desktop (stdio mode)

Add to your Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "securityscorecard": {
      "command": "node",
      "args": ["/path/to/securityscorecard-mcp/dist/index.js"],
      "env": {
        "SSC_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

### Running as HTTP Server

```bash
TRANSPORT_MODE=http SSC_API_KEY=your_api_key_here npm start
```

The server will start on port 3000 (configurable via `PORT` env var).

### Running with Docker

```bash
SSC_API_KEY=your_api_key_here docker compose up
```

## Available Tools (25+)

### Scorecards & Company Information
| Tool | Description |
|------|-------------|
| `get-company-score` | Get security score, grade, and factor breakdown for any company |
| `get-company-info` | Get detailed company information and metadata |
| `search-companies` | Bulk search multiple companies by domain |
| `get-factor-details` | Detailed breakdown of all security factors |
| `get-historical-scores` | Historical score data over time |
| `get-historical-factor-scores` | Historical factor-level scores |
| `get-active-issues` | Active security issues summary |
| `get-expanded-risk` | Expanded risk analysis including supply chain |
| `get-score-improvement-plan` | Recommendations to reach a target score |

### Portfolios
| Tool | Description |
|------|-------------|
| `list-portfolios` | List all monitoring portfolios |
| `get-portfolio-companies` | Companies in a portfolio with scores |
| `create-portfolio` | Create a new monitoring portfolio |
| `update-portfolio` | Update portfolio name/description |
| `delete-portfolio` | Delete a portfolio |
| `add-company-to-portfolio` | Add a company to a portfolio |
| `remove-company-from-portfolio` | Remove a company from a portfolio |
| `get-portfolio-risk` | Portfolio-wide risk analysis |

### Findings & Industry
| Tool | Description |
|------|-------------|
| `get-issue-details` | Details on specific issue types |
| `get-issue-context` | Scoring context for an issue type |
| `get-industry-benchmark` | Industry average scores |
| `get-industry-factors` | Industry factor breakdown |
| `get-industry-historical-scores` | Industry score trends |

### Vendor Detection
| Tool | Description |
|------|-------------|
| `get-vendor-detection` | Third-party vendors for a company |
| `get-fourth-party-risk` | Fourth-party (supply chain) vendors |
| `get-vendor-products` | Products/technologies detected |
| `get-vendor-risk` | Vendor risk score |
| `get-portfolio-vendors` | Vendor analysis across a portfolio |

### Questionnaires & Action Plans
| Tool | Description |
|------|-------------|
| `get-questionnaire-templates` | Available questionnaire templates |
| `send-questionnaire` | Send a questionnaire to a vendor |
| `get-questionnaire-status` | Check questionnaire status |
| `get-questionnaire-responses` | Get questionnaire responses |
| `list-action-plans` | List all action plans |
| `create-issue-resolution-plan` | Create issue resolution plan |
| `create-score-improvement-plan` | Create score improvement plan |
| `delete-action-plan` | Delete an action plan |

### Attack Surface Intelligence & Events
| Tool | Description |
|------|-------------|
| `search-attack-surface` | Search ASI for exposed assets and vulnerabilities |
| `get-asset-details` | Details on a specific IP/asset |
| `get-cve-details` | CVE details from ASI |
| `get-threat-actor-details` | Threat actor group information |
| `get-ransomware-details` | Ransomware strain details |
| `get-security-events` | Security events over time |
| `get-breach-events` | Breach-related events |
| `generate-report` | Generate security reports |
| `list-recent-reports` | List recently generated reports |

## Example Prompts

### 1. Vendor Risk Assessment
```
"What's the security score for acme.com? Show me their factor breakdown and any active security issues."
```

### 2. Portfolio Analysis
```
"List my portfolios and show me all companies in my 'Critical Vendors' portfolio that have a score below 70."
```

### 3. Threat Intelligence
```
"Search the attack surface for any exposed assets related to example.com and check if they have any CVEs being actively exploited."
```

### 4. Supply Chain Risk
```
"Who are the fourth-party vendors for microsoft.com? Are any of them below a B grade?"
```

### 5. Industry Benchmarking
```
"How does acme.com compare to the healthcare industry average? Show me the historical trend for the past year."
```

## Architecture

```
src/
├── cli/                  # CLI entry point
├── controllers/          # Business logic (extensible)
├── services/
│   ├── securityscorecard.service.ts   # SSC API client
│   └── securityscorecard.types.ts     # Type definitions
├── tools/
│   ├── index.ts          # Tool registration hub
│   ├── scorecard.tools.ts
│   ├── portfolio.tools.ts
│   ├── findings.tools.ts
│   ├── vendor.tools.ts
│   ├── questionnaire.tools.ts
│   ├── actionplan.tools.ts
│   ├── asi.tools.ts
│   └── events.tools.ts
├── resources/
│   └── scorecard.resources.ts  # MCP resources
├── utils/
│   ├── config.ts         # Zod-validated config
│   ├── logger.ts         # Pino structured logging
│   └── error.ts          # Error formatting
└── index.ts              # Server entry point
```

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TRANSPORT_MODE` | `stdio` or `http` | `stdio` |
| `PORT` | HTTP server port | `3000` |
| `SSC_API_KEY` | SecurityScorecard API key | required |
| `SSC_API_BASE_URL` | API base URL | `https://api.securityscorecard.io` |
| `LOG_LEVEL` | Logging level | `info` |
| `NODE_ENV` | Environment | `production` |

## API Endpoints (HTTP mode)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/mcp` | POST | MCP Streamable HTTP endpoint |
| `/mcp` | GET | SSE notification stream |
| `/mcp` | DELETE | Session cleanup |
| `/health` | GET | Health check |
| `/.well-known/oauth-protected-resource` | GET | OAuth metadata (RFC 9728) |

## License

MIT
