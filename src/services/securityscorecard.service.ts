import { logger } from '../utils/logger.js';
import {
  SecurityScorecardError,
  AuthenticationError,
  RateLimitError,
} from '../utils/error.js';
import type {
  CompanyFactorSummary,
  HistoricalScore,
  ActiveIssue,
  Portfolio,
  PortfolioCompany,
  IndustryScore,
  IssueDetail,
  VendorInfo,
  ScoreImprovement,
  QuestionnaireRequest,
  ActionPlan,
  ASISearchResult,
  ThreatActorInfo,
  SecurityEvent,
  PaginatedResponse,
} from './securityscorecard.types.js';

export class SecurityScorecardService {
  private baseUrl: string;
  private apiKey: string;

  constructor(baseUrl: string, apiKey: string) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.apiKey = apiKey;
  }

  private static readonly REQUEST_TIMEOUT_MS = 30_000; // 30 seconds

  private async request<T>(
    endpoint: string,
    options: {
      method?: string;
      body?: unknown;
      params?: Record<string, string | number | undefined>;
    } = {}
  ): Promise<T> {
    const { method = 'GET', body, params } = options;

    let url = `${this.baseUrl}${endpoint}`;
    if (params) {
      const searchParams = new URLSearchParams();
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined) {
          searchParams.set(key, String(value));
        }
      }
      const qs = searchParams.toString();
      if (qs) url += `?${qs}`;
    }

    const headers: Record<string, string> = {
      'Authorization': `Token ${this.apiKey}`,
      'Accept': 'application/json',
    };

    if (body) {
      headers['Content-Type'] = 'application/json';
    }

    logger.debug({ method, url }, 'SSC API request');

    const response = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(SecurityScorecardService.REQUEST_TIMEOUT_MS),
    });

    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        throw new AuthenticationError();
      }
      if (response.status === 429) {
        const retryAfter = parseInt(response.headers.get('Retry-After') || '60', 10);
        throw new RateLimitError(endpoint, retryAfter);
      }
      const errorBody = await response.text().catch(() => 'Unknown error');
      throw new SecurityScorecardError(
        `API request failed: ${response.status} ${response.statusText} - ${errorBody}`,
        response.status,
        endpoint
      );
    }

    // 204 No Content (common for DELETE/PUT) has no body to parse.
    if (response.status === 204 || response.headers.get('content-length') === '0') {
      return undefined as T;
    }

    // Defend against an upstream that returns HTML (e.g. WAF block page,
    // proxy error) with a 200 status. response.json() would throw a
    // SyntaxError that hides the real cause; surfacing a typed error with
    // the actual content-type is more diagnosable.
    const contentType = response.headers.get('content-type') ?? '';
    if (!/\bapplication\/(?:[\w.+-]+\+)?json\b/i.test(contentType)) {
      throw new SecurityScorecardError(
        `Unexpected response content-type: ${contentType || '(missing)'}`,
        response.status,
        endpoint
      );
    }

    return response.json() as Promise<T>;
  }

  // ── Scorecards & Company Information ──

  async getCompanyScore(domain: string): Promise<CompanyFactorSummary> {
    return this.request<CompanyFactorSummary>(`/companies/${encodeURIComponent(domain)}/summary/factors`);
  }

  async getCompanyInfo(domain: string): Promise<Record<string, unknown>> {
    return this.request(`/companies/${encodeURIComponent(domain)}`);
  }

  async getFactorDetails(domain: string): Promise<Record<string, unknown>> {
    return this.request(`/companies/${encodeURIComponent(domain)}/factors`);
  }

  async getHistoricalScores(domain: string, from?: string, to?: string): Promise<{ entries: HistoricalScore[] }> {
    return this.request(`/companies/${encodeURIComponent(domain)}/history/score`, {
      params: { from, to },
    });
  }

  async getHistoricalFactorScores(domain: string, from?: string, to?: string): Promise<Record<string, unknown>> {
    return this.request(`/companies/${encodeURIComponent(domain)}/history/factors/score`, {
      params: { from, to },
    });
  }

  async getActiveIssues(domain: string): Promise<{ entries: ActiveIssue[] }> {
    return this.request(`/companies/${encodeURIComponent(domain)}/active-issues`);
  }

  async getExpandedRisk(domain: string): Promise<Record<string, unknown>> {
    return this.request(`/companies/${encodeURIComponent(domain)}/expanded-risk`);
  }

  async getScoreImprovementPlan(domain: string, targetScore: number): Promise<ScoreImprovement> {
    return this.request(`/companies/${encodeURIComponent(domain)}/score-plans/by-target-score`, {
      params: { target: targetScore },
    });
  }

  async searchCompanies(domains: string[]): Promise<Record<string, unknown>> {
    return this.request('/companies/bulk-searches', {
      method: 'POST',
      body: { domains },
    });
  }

  // ── Issue Details ──

  async getIssueDetails(domain: string, issueType: string, params?: { page?: number; size?: number }): Promise<PaginatedResponse<IssueDetail>> {
    return this.request(`/companies/${encodeURIComponent(domain)}/issues/${encodeURIComponent(issueType)}`, {
      params: params as Record<string, string | number | undefined>,
    });
  }

  async getIssueContext(domain: string, issueType: string): Promise<Record<string, unknown>> {
    return this.request(`/companies/${encodeURIComponent(domain)}/issue-context/${encodeURIComponent(issueType)}`);
  }

  // ── Portfolios ──

  async listPortfolios(): Promise<{ entries: Portfolio[] }> {
    return this.request('/portfolios');
  }

  async createPortfolio(name: string, description?: string, privacy?: string): Promise<Portfolio> {
    return this.request('/portfolios', {
      method: 'POST',
      body: { name, description, privacy: privacy || 'private' },
    });
  }

  async updatePortfolio(id: string, name: string, description?: string): Promise<Portfolio> {
    return this.request(`/portfolios/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: { name, description },
    });
  }

  async deletePortfolio(id: string): Promise<void> {
    await this.request(`/portfolios/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  async getPortfolioCompanies(
    portfolioId: string,
    params?: { page?: number; size?: number }
  ): Promise<PaginatedResponse<PortfolioCompany>> {
    return this.request(`/portfolios/${encodeURIComponent(portfolioId)}/companies`, {
      params: params as Record<string, string | number | undefined>,
    });
  }

  async addCompanyToPortfolio(portfolioId: string, domain: string): Promise<void> {
    await this.request(`/portfolios/${encodeURIComponent(portfolioId)}/companies/${encodeURIComponent(domain)}`, {
      method: 'PUT',
    });
  }

  async removeCompanyFromPortfolio(portfolioId: string, domain: string): Promise<void> {
    await this.request(`/portfolios/${encodeURIComponent(portfolioId)}/companies/${encodeURIComponent(domain)}`, {
      method: 'DELETE',
    });
  }

  async getPortfolioExpandedRisk(portfolioId: string): Promise<Record<string, unknown>> {
    return this.request(`/portfolios/${encodeURIComponent(portfolioId)}/expanded-risk`);
  }

  // ── Industry Benchmarks ──

  async getIndustryScore(industry: string): Promise<IndustryScore> {
    return this.request(`/industries/${encodeURIComponent(industry)}/score`);
  }

  async getIndustryFactors(industry: string): Promise<Record<string, unknown>> {
    return this.request(`/industries/${encodeURIComponent(industry)}/factors`);
  }

  async getIndustryHistoricalScores(industry: string, from?: string, to?: string): Promise<Record<string, unknown>> {
    return this.request(`/industries/${encodeURIComponent(industry)}/history/score`, {
      params: { from, to },
    });
  }

  // ── Vendor Detection ──

  async getThirdPartyVendors(domain: string): Promise<{ entries: VendorInfo[] }> {
    return this.request(`/vendor-detection/${encodeURIComponent(domain)}/third-party`);
  }

  async getFourthPartyVendors(domain: string): Promise<{ entries: VendorInfo[] }> {
    return this.request(`/vendor-detection/${encodeURIComponent(domain)}/fourth-party`);
  }

  async getVendorProducts(domain: string): Promise<Record<string, unknown>> {
    return this.request(`/vendor-detection/${encodeURIComponent(domain)}/products`);
  }

  async getVendorRisk(domain: string): Promise<Record<string, unknown>> {
    return this.request(`/vendor-detection/${encodeURIComponent(domain)}/risk`);
  }

  async getPortfolioVendors(portfolioId: string): Promise<Record<string, unknown>> {
    return this.request(`/vendor-detection/portfolios/${encodeURIComponent(portfolioId)}`);
  }

  // ── Questionnaires (Atlas API) ──

  async getCurrentUserInfo(): Promise<Record<string, unknown>> {
    return this.request('/atlas/users/current/info');
  }

  async getAvailableTemplates(): Promise<Record<string, unknown>> {
    return this.request('/atlas/companies/current/standards');
  }

  async sendQuestionnaire(body: {
    recipient_domain: string;
    template_id: string;
    message?: string;
  }): Promise<QuestionnaireRequest> {
    return this.request('/atlas/requests', {
      method: 'POST',
      body,
    });
  }

  async getQuestionnaireStatus(requestId: string): Promise<QuestionnaireRequest> {
    return this.request(`/atlas/requests/${encodeURIComponent(requestId)}`);
  }

  async getQuestionnaireResponses(formId: string): Promise<Record<string, unknown>> {
    return this.request(`/atlas/forms/${encodeURIComponent(formId)}/questions`);
  }

  // ── Action Plans ──

  async listActionPlans(): Promise<{ entries: ActionPlan[] }> {
    return this.request('/plans');
  }

  async createIssueResolutionPlan(body: {
    name: string;
    target_date: string;
    issue_types: string[];
    domains?: string[];
  }): Promise<ActionPlan> {
    return this.request('/plans/issue-resolution', {
      method: 'POST',
      body,
    });
  }

  async createScoreImprovementPlan(body: {
    name: string;
    target_date: string;
    target_score: number;
  }): Promise<ActionPlan> {
    return this.request('/plans/overall-score-improvement', {
      method: 'POST',
      body,
    });
  }

  async deleteActionPlan(planId: string): Promise<void> {
    await this.request(`/plans/${encodeURIComponent(planId)}`, { method: 'DELETE' });
  }

  // ── Reports ──

  async generateSummaryReport(domain: string): Promise<Record<string, unknown>> {
    return this.request('/reports/summary', {
      method: 'POST',
      body: { domain },
    });
  }

  async generateDetailedReport(domain: string): Promise<Record<string, unknown>> {
    return this.request('/reports/detailed', {
      method: 'POST',
      body: { domain },
    });
  }

  async generateFullScorecardJson(domain: string): Promise<Record<string, unknown>> {
    return this.request('/reports/full-scorecard/json', {
      method: 'POST',
      body: { domain },
    });
  }

  async listRecentReports(): Promise<Record<string, unknown>> {
    return this.request('/reports/recent');
  }

  // ── Attack Surface Intelligence (ASI) ──

  async searchAttackSurface(query: string, filters?: Record<string, unknown>): Promise<ASISearchResult> {
    // Build the filters object first, explicitly excluding the 'query' key to
    // prevent a caller-supplied filter from overriding the required query field
    // (property-override / object-injection vulnerability).
    const safeFilters: Record<string, unknown> = {};
    if (filters) {
      for (const [key, value] of Object.entries(filters)) {
        if (key !== 'query') {
          safeFilters[key] = value;
        }
      }
    }
    return this.request('/asi/search', {
      method: 'POST',
      body: { ...safeFilters, query },
    });
  }

  async getAssetDetails(ip: string): Promise<Record<string, unknown>> {
    return this.request(`/asi/details/asset/${encodeURIComponent(ip)}`);
  }

  async getCveDetails(cve: string): Promise<Record<string, unknown>> {
    return this.request(`/asi/details/cve/${encodeURIComponent(cve)}`);
  }

  async getThreatActorDetails(name: string): Promise<ThreatActorInfo> {
    return this.request(`/asi/details/threat-actor/${encodeURIComponent(name)}`);
  }

  async getRansomwareDetails(name: string): Promise<Record<string, unknown>> {
    return this.request(`/asi/details/ransomware/${encodeURIComponent(name)}`);
  }

  // ── Security Events ──

  async getSecurityEvents(domain: string, params?: { from?: string; to?: string }): Promise<{ entries: SecurityEvent[] }> {
    return this.request(`/companies/${encodeURIComponent(domain)}/history/events`, {
      params: params as Record<string, string | number | undefined>,
    });
  }

  async getBreachEvents(domain: string): Promise<{ entries: SecurityEvent[] }> {
    return this.request(`/companies/${encodeURIComponent(domain)}/history/events/breaches`);
  }
}
