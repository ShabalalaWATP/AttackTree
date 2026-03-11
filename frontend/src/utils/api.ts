import type {
  AttackNodeData,
  AuthLoginResponseData,
  AuthUserData,
  EnvironmentCatalogData,
  EnvironmentCatalogSummary,
  LLMAgentRequestData,
  LLMAgentResponseData,
  LLMSuggestRequestData,
  LLMSuggestResponseData,
  PlanningProfile,
  ProjectData,
  TemplateData,
  TemplateInfo,
} from '@/types';
import { clearStoredAuthSession, getStoredToken } from '@/utils/authStorage';

const BASE = '/api';

type ApiRequestOptions = RequestInit & {
  noAuth?: boolean;
};

function normalizeHeaders(headers?: HeadersInit): Record<string, string> {
  if (!headers) return {};
  if (headers instanceof Headers) {
    return Object.fromEntries(headers.entries());
  }
  if (Array.isArray(headers)) {
    return Object.fromEntries(headers);
  }
  return headers;
}

function buildHeaders(headers?: HeadersInit, noAuth?: boolean): HeadersInit {
  const authToken = noAuth ? null : getStoredToken();
  return {
    'Content-Type': 'application/json',
    ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
    ...normalizeHeaders(headers),
  };
}

function handleUnauthorized(res: Response): void {
  if (res.status === 401) {
    clearStoredAuthSession();
    window.dispatchEvent(new Event('atb-auth-expired'));
  }
}

async function request<T>(url: string, options?: ApiRequestOptions): Promise<T> {
  const { noAuth, headers, ...rest } = options || {};
  const res = await fetch(`${BASE}${url}`, {
    ...rest,
    headers: buildHeaders(headers, noAuth),
  });
  if (!res.ok) {
    handleUnauthorized(res);
    const text = await res.text().catch(() => 'Unknown error');
    throw new Error(`${res.status}: ${text}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

async function fetchExport(url: string, body: Record<string, unknown>): Promise<Response> {
  const authToken = getStoredToken();
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    handleUnauthorized(res);
    const text = await res.text().catch(() => 'Export failed');
    throw new Error(`${res.status}: ${text}`);
  }
  return res;
}

// Projects
export const api = {
  // Auth
  login: (data: { identifier: string; password: string }) =>
    request<AuthLoginResponseData>('/auth/login', { method: 'POST', body: JSON.stringify(data), noAuth: true }),
  signup: (data: { name: string; email: string; username: string; password: string }) =>
    request<AuthLoginResponseData>('/auth/signup', { method: 'POST', body: JSON.stringify(data), noAuth: true }),
  getCurrentUser: () => request<AuthUserData>('/auth/me'),
  changePassword: (data: { current_password: string; new_password: string }) =>
    request<void>('/auth/change-password', { method: 'POST', body: JSON.stringify(data) }),
  listUsers: () => request<AuthUserData[]>('/auth/users'),
  createUser: (data: { name: string; email: string; username?: string; password: string; role: 'admin' | 'user' }) =>
    request<AuthUserData>('/auth/users', { method: 'POST', body: JSON.stringify(data) }),
  updateUser: (id: string, data: { name?: string; email?: string; username?: string; role?: 'admin' | 'user'; is_active?: boolean }) =>
    request<AuthUserData>(`/auth/users/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  resetUserPassword: (id: string, data: { new_password: string; require_reset?: boolean }) =>
    request<void>(`/auth/users/${id}/reset-password`, { method: 'POST', body: JSON.stringify(data) }),
  deleteUser: (id: string) => request<void>(`/auth/users/${id}`, { method: 'DELETE' }),

  // Projects
  listProjects: () => request<{ projects: ProjectData[]; total: number }>('/projects'),
  getProject: (id: string) => request<ProjectData>(`/projects/${id}`),
  createProject: (data: any) => request<ProjectData>('/projects', { method: 'POST', body: JSON.stringify(data) }),
  updateProject: (id: string, data: any) => request<ProjectData>(`/projects/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteProject: (id: string) => request<void>(`/projects/${id}`, { method: 'DELETE' }),
  searchAcrossProjects: (q: string) =>
    request<{ count: number; results: Array<{ node_id: string; project_id: string; project_name: string; title: string; node_type: string; description: string; inherent_risk: number | null }> }>(
      `/projects/search/nodes?q=${encodeURIComponent(q)}`
  ),

  // Nodes
  listNodes: (projectId: string) => request<AttackNodeData[]>(`/nodes/project/${projectId}`),
  createNode: (data: any) => request<AttackNodeData>('/nodes', { method: 'POST', body: JSON.stringify(data) }),
  updateNode: (id: string, data: any) => request<AttackNodeData>(`/nodes/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteNode: (id: string) => request<void>(`/nodes/${id}`, { method: 'DELETE' }),
  duplicateNode: (id: string) => request<any>(`/nodes/${id}/duplicate`, { method: 'POST' }),
  bulkUpdateNodes: (node_ids: string[], updates: Record<string, unknown>) =>
    request<{ updated: number }>('/nodes/bulk/update', { method: 'POST', body: JSON.stringify({ node_ids, updates }) }),
  bulkDeleteNodes: (node_ids: string[]) =>
    request<{ deleted: number }>('/nodes/bulk/delete', { method: 'POST', body: JSON.stringify({ node_ids }) }),
  getCriticalPath: (projectId: string) =>
    request<{ path: string[]; cumulative_risk: number; path_details: Array<{ id: string; title: string; node_type: string; inherent_risk: number | null; residual_risk: number | null; mitigation_count: number; max_mitigation_effectiveness: number }>; all_paths: Array<{ path: string[]; cumulative_risk: number }> }>(
      `/nodes/project/${projectId}/critical-path`
    ),

  // Mitigations
  listMitigations: (nodeId: string) => request<any[]>(`/mitigations/node/${nodeId}`),
  createMitigation: (data: any) => request<any>('/mitigations', { method: 'POST', body: JSON.stringify(data) }),
  updateMitigation: (id: string, data: any) => request<any>(`/mitigations/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteMitigation: (id: string) => request<void>(`/mitigations/${id}`, { method: 'DELETE' }),

  // Detections
  createDetection: (data: any) => request<any>('/detections', { method: 'POST', body: JSON.stringify(data) }),
  updateDetection: (id: string, data: any) => request<any>(`/detections/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteDetection: (id: string) => request<void>(`/detections/${id}`, { method: 'DELETE' }),

  // Reference mappings
  createMapping: (data: any) => request<any>('/references', { method: 'POST', body: JSON.stringify(data) }),
  updateMapping: (id: string, data: any) => request<any>(`/references/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteMapping: (id: string) => request<void>(`/references/${id}`, { method: 'DELETE' }),
  browseReferences: (framework: string, q?: string, filter?: string) => {
    const params = new URLSearchParams();
    if (q) params.set('q', q);
    if (filter) params.set('filter', filter);
    return request<{ framework: string; total: number; count: number; items: any[]; filter_field: string | null; filter_options: string[] }>(`/references/browse/${framework}?${params.toString()}`);
  },
  listEnvironmentCatalogs: () => request<{ total: number; catalogs: EnvironmentCatalogSummary[] }>('/references/environment-catalogs'),
  getEnvironmentCatalog: (catalogId: string) => request<EnvironmentCatalogData>(`/references/environment-catalogs/${catalogId}`),

  // Comments
  listComments: (nodeId: string) => request<any[]>(`/comments/node/${nodeId}`),
  createComment: (data: any) => request<any>('/comments', { method: 'POST', body: JSON.stringify(data) }),
  deleteComment: (id: string) => request<void>(`/comments/${id}`, { method: 'DELETE' }),

  // Tags
  listTags: () => request<any[]>('/tags'),
  createTag: (data: { name: string }) => request<any>('/tags', { method: 'POST', body: JSON.stringify(data) }),
  addTagToNode: (nodeId: string, tagId: string) => request<void>(`/tags/node/${nodeId}/${tagId}`, { method: 'POST' }),
  removeTagFromNode: (nodeId: string, tagId: string) => request<void>(`/tags/node/${nodeId}/${tagId}`, { method: 'DELETE' }),

  // Audit
  listAuditEvents: (projectId: string, limit = 50, offset = 0) =>
    request<any[]>(`/audit/project/${projectId}?limit=${limit}&offset=${offset}`),

  // Snapshots
  listSnapshots: (projectId: string) => request<any[]>(`/snapshots/project/${projectId}`),
  createSnapshot: (data: any) => request<any>('/snapshots', { method: 'POST', body: JSON.stringify(data) }),
  getSnapshot: (id: string) => request<any>(`/snapshots/${id}`),

  // Export (return checked Response — callers use .blob())
  exportJson: (projectId: string) =>
    fetchExport(`${BASE}/export/json`, { project_id: projectId }),
  exportCsv: (projectId: string) =>
    fetchExport(`${BASE}/export/csv`, { project_id: projectId }),
  exportMarkdown: (projectId: string, reportType = 'technical') =>
    fetchExport(`${BASE}/export/markdown`, { project_id: projectId, report_type: reportType }),
  exportPdf: (projectId: string, reportType = 'technical') =>
    fetchExport(`${BASE}/export/pdf`, { project_id: projectId, report_type: reportType }),
  importJson: (data: any) => request<any>('/export/import', { method: 'POST', body: JSON.stringify(data) }),
  recalculateRisk: (projectId: string) => request<any>(`/export/risk-engine/${projectId}`),

  // Templates
  listTemplates: () => request<{ templates: TemplateInfo[] }>('/templates'),
  getTemplate: (id: string) => request<TemplateData>(`/templates/${id}`),

  // LLM
  listProviders: () => request<any[]>('/llm/providers'),
  createProvider: (data: any) => request<any>('/llm/providers', { method: 'POST', body: JSON.stringify(data) }),
  updateProvider: (id: string, data: any) => request<any>(`/llm/providers/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteProvider: (id: string) => request<void>(`/llm/providers/${id}`, { method: 'DELETE' }),
  testProvider: (id: string) => request<any>(`/llm/providers/${id}/test`, { method: 'POST' }),
  suggestBranches: (data: LLMSuggestRequestData) => request<LLMSuggestResponseData>('/llm/suggest', { method: 'POST', body: JSON.stringify(data) }),
  generateSummary: (data: any) => request<any>('/llm/summarize', { method: 'POST', body: JSON.stringify(data) }),
  agentGenerateTree: (data: LLMAgentRequestData) => request<LLMAgentResponseData>('/llm/agent', { method: 'POST', body: JSON.stringify(data) }),

  // Scenarios
  listScenarios: (projectId?: string, scope = projectId ? 'project' : 'standalone') => {
    const params = new URLSearchParams();
    if (projectId) params.set('project_id', projectId);
    if (scope) params.set('scope', scope);
    return request<any[]>(`/scenarios?${params.toString()}`);
  },
  listScenarioWorkspace: (projectId?: string) => {
    const params = new URLSearchParams();
    params.set('scope', projectId ? 'workspace' : 'standalone');
    if (projectId) params.set('project_id', projectId);
    return request<any[]>(`/scenarios?${params.toString()}`);
  },
  createScenario: (data: any) => request<any>('/scenarios', { method: 'POST', body: JSON.stringify(data) }),
  getScenario: (id: string) => request<any>(`/scenarios/${id}`),
  updateScenario: (id: string, data: any) => request<any>(`/scenarios/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteScenario: (id: string) => request<void>(`/scenarios/${id}`, { method: 'DELETE' }),
  simulateScenario: (id: string, data: any) => request<any>(`/scenarios/${id}/simulate`, { method: 'POST', body: JSON.stringify(data) }),
  aiAnalyzeScenario: (id: string, data: { question?: string; planning_profile?: PlanningProfile }) => request<any>(`/scenarios/${id}/ai-analyze`, { method: 'POST', body: JSON.stringify(data) }),
  aiGenerateScenarios: (projectId: string) => request<any>(`/scenarios/project/${projectId}/ai-generate`, { method: 'POST' }),
  generateScenarioSuggestions: (data: { project_id?: string; focus?: string; count?: number; planning_profile?: PlanningProfile }) =>
    request<any>('/scenarios/ai-generate', { method: 'POST', body: JSON.stringify(data) }),

  // Kill Chains
  listKillChains: (projectId: string) => request<any[]>(`/kill-chains/project/${projectId}`),
  createKillChain: (data: any) => request<any>('/kill-chains', { method: 'POST', body: JSON.stringify(data) }),
  getKillChain: (id: string) => request<any>(`/kill-chains/${id}`),
  deleteKillChain: (id: string) => request<void>(`/kill-chains/${id}`, { method: 'DELETE' }),
  aiMapKillChain: (id: string, data: { user_guidance?: string; planning_profile?: PlanningProfile }) => request<any>(`/kill-chains/${id}/ai-map`, { method: 'POST', body: JSON.stringify(data) }),
  aiGenerateKillChain: (projectId: string, data?: { framework?: string; user_guidance?: string; planning_profile?: PlanningProfile }) => request<any>(`/kill-chains/project/${projectId}/ai-generate`, { method: 'POST', body: data ? JSON.stringify(data) : undefined }),

  // Threat Models
  listThreatModels: (projectId: string) => request<any[]>(`/threat-models/project/${projectId}`),
  createThreatModel: (data: any) => request<any>('/threat-models', { method: 'POST', body: JSON.stringify(data) }),
  getThreatModel: (id: string) => request<any>(`/threat-models/${id}`),
  updateThreatModel: (id: string, data: any) => request<any>(`/threat-models/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteThreatModel: (id: string) => request<void>(`/threat-models/${id}`, { method: 'DELETE' }),
  aiGenerateDFD: (id: string, data: { system_description: string; user_guidance?: string; methodology?: string; name?: string; planning_profile?: PlanningProfile; refresh?: boolean }) => request<any>(`/threat-models/${id}/ai-generate-dfd`, { method: 'POST', body: JSON.stringify(data) }),
  aiGenerateThreats: (id: string, data: { user_guidance?: string; planning_profile?: PlanningProfile }) => request<any>(`/threat-models/${id}/ai-generate-threats`, { method: 'POST', body: JSON.stringify(data) }),
  aiDeepDiveThreat: (tmId: string, data: { threat_id: string; refresh?: boolean }) => request<any>(`/threat-models/${tmId}/ai-deep-dive`, { method: 'POST', body: JSON.stringify(data) }),
  linkThreatsToTree: (id: string, data: any) => request<any>(`/threat-models/${id}/link-to-tree`, { method: 'POST', body: JSON.stringify(data) }),
  aiFullThreatModel: (projectId: string, data: { system_description: string; user_guidance?: string; methodology?: string; name?: string; planning_profile?: PlanningProfile }) => request<any>(`/threat-models/project/${projectId}/ai-full-analysis`, { method: 'POST', body: JSON.stringify(data) }),

  // AI Chat (Brainstorm, Advisor, Challenger)
  aiBrainstorm: (data: {
    provider_id: string;
    project_name?: string;
    root_objective?: string;
    context_preset?: string;
    workspace_mode?: string;
    planning_profile?: PlanningProfile;
    technical_depth?: string;
    focus_mode?: string;
    tree_context?: string;
    context_packets?: string[];
    messages: Array<{ role: string; content: string }>;
  }) =>
    request<{ status: string; content: string; model: string; tokens: number; elapsed_ms: number }>('/ai-chat/brainstorm', { method: 'POST', body: JSON.stringify(data) }),
  aiAdvisor: (data: { provider_id: string; question: string; project_name?: string; root_objective?: string; tree_context?: string }) =>
    request<{ status: string; content: string; model: string; tokens: number; elapsed_ms: number }>('/ai-chat/advisor', { method: 'POST', body: JSON.stringify(data) }),
  aiChallengeScores: (data: { provider_id: string; node_title: string; node_description?: string; node_type?: string; likelihood?: number; impact?: number; effort?: number; exploitability?: number; detectability?: number; inherent_risk?: number; mitigations_summary?: string; tree_context?: string }) =>
    request<{ status: string; content: string; model: string; tokens: number; elapsed_ms: number }>('/ai-chat/challenge-scores', { method: 'POST', body: JSON.stringify(data) }),

  // Infrastructure Maps
  listInfraMaps: (projectId: string) => request<any[]>(`/infra-maps/project/${projectId}`),
  listStandaloneInfraMaps: () => request<any[]>('/infra-maps/standalone'),
  createInfraMap: (data: any) => request<any>('/infra-maps', { method: 'POST', body: JSON.stringify(data) }),
  getInfraMap: (id: string) => request<any>(`/infra-maps/${id}`),
  updateInfraMap: (id: string, data: any) => request<any>(`/infra-maps/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteInfraMap: (id: string) => request<void>(`/infra-maps/${id}`, { method: 'DELETE' }),
  aiExpandInfraNode: (id: string, data: { node_id: string; user_guidance?: string; planning_profile?: PlanningProfile }) => request<any>(`/infra-maps/${id}/ai-expand`, { method: 'POST', body: JSON.stringify(data) }),
  aiGenerateInfraMap: (projectId: string, data?: { root_label?: string; user_guidance?: string; planning_profile?: PlanningProfile }) => request<any>(`/infra-maps/project/${projectId}/ai-generate`, { method: 'POST', body: data ? JSON.stringify(data) : undefined }),
  aiGenerateStandaloneInfraMap: (data?: { root_label?: string; user_guidance?: string; planning_profile?: PlanningProfile }) => request<any>('/infra-maps/standalone/ai-generate', { method: 'POST', body: data ? JSON.stringify(data) : undefined }),
};
