export interface CompanySummary {
  name: string;
  domain: string;
  grade: string;
  score: number;
  industry: string;
  size: string;
  last30days_score_change: number;
}

export interface FactorScore {
  name: string;
  grade: string;
  score: number;
  issue_count?: number;
}

export interface CompanyFactorSummary {
  name: string;
  domain: string;
  grade: string;
  score: number;
  industry: string;
  factors: FactorScore[];
}

export interface HistoricalScore {
  date: string;
  score: number;
}

export interface ActiveIssue {
  type: string;
  count: number;
  severity: string;
  factor: string;
  detail_url: string;
}

export interface Portfolio {
  id: string;
  name: string;
  description?: string;
  privacy: string;
  created_at: string;
  updated_at: string;
}

export interface PortfolioCompany {
  domain: string;
  name: string;
  grade: string;
  score: number;
  industry: string;
  last30days_score_change: number;
}

export interface IndustryScore {
  industry: string;
  score: number;
  grade: string;
}

export interface IssueDetail {
  type: string;
  severity: string;
  first_seen_time: string;
  last_seen_time: string;
  count: number;
  detail: Record<string, unknown>;
}

export interface VendorInfo {
  domain: string;
  name: string;
  score: number;
  grade: string;
  products: string[];
}

export interface ScoreImprovement {
  target_score: number;
  current_score: number;
  issues_to_resolve: Array<{
    type: string;
    count: number;
    score_impact: number;
  }>;
}

export interface QuestionnaireRequest {
  id: string;
  status: string;
  created_at: string;
  template: string;
  recipient_domain: string;
}

export interface ActionPlan {
  id: string;
  name: string;
  status: string;
  created_at: string;
  target_date: string;
  issues: Array<{
    type: string;
    count: number;
  }>;
}

export interface ASISearchResult {
  total: number;
  results: Array<{
    ip: string;
    domain: string;
    port: number;
    service: string;
    vulnerabilities: string[];
  }>;
}

export interface ThreatActorInfo {
  name: string;
  aliases: string[];
  description: string;
  targets: string[];
  techniques: string[];
}

export interface SecurityEvent {
  date: string;
  type: string;
  description: string;
  severity: string;
  domain: string;
}

export interface PaginatedResponse<T> {
  entries: T[];
  total: number;
  size: number;
  offset?: number;
  cursor?: string;
  has_more: boolean;
}
