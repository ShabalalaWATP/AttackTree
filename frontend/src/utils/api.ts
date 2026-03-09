const BASE = '/api';

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${url}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => 'Unknown error');
    throw new Error(`${res.status}: ${text}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

async function fetchExport(url: string, body: Record<string, unknown>): Promise<Response> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => 'Export failed');
    throw new Error(`${res.status}: ${text}`);
  }
  return res;
}

// Projects
export const api = {
  // Projects
  listProjects: () => request<{ projects: any[]; total: number }>('/projects'),
  getProject: (id: string) => request<any>(`/projects/${id}`),
  createProject: (data: any) => request<any>('/projects', { method: 'POST', body: JSON.stringify(data) }),
  updateProject: (id: string, data: any) => request<any>(`/projects/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteProject: (id: string) => request<void>(`/projects/${id}`, { method: 'DELETE' }),
  searchAcrossProjects: (q: string) =>
    request<{ count: number; results: Array<{ node_id: string; project_id: string; project_name: string; title: string; node_type: string; description: string; inherent_risk: number | null }> }>(
      `/projects/search/nodes?q=${encodeURIComponent(q)}`
    ),

  // Nodes
  listNodes: (projectId: string) => request<any[]>(`/nodes/project/${projectId}`),
  createNode: (data: any) => request<any>('/nodes', { method: 'POST', body: JSON.stringify(data) }),
  updateNode: (id: string, data: any) => request<any>(`/nodes/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
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
  listTemplates: () => request<{ templates: any[] }>('/templates'),
  getTemplate: (id: string) => request<any>(`/templates/${id}`),

  // LLM
  listProviders: () => request<any[]>('/llm/providers'),
  createProvider: (data: any) => request<any>('/llm/providers', { method: 'POST', body: JSON.stringify(data) }),
  updateProvider: (id: string, data: any) => request<any>(`/llm/providers/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteProvider: (id: string) => request<void>(`/llm/providers/${id}`, { method: 'DELETE' }),
  testProvider: (id: string) => request<any>(`/llm/providers/${id}/test`, { method: 'POST' }),
  suggestBranches: (data: any) => request<any>('/llm/suggest', { method: 'POST', body: JSON.stringify(data) }),
  generateSummary: (data: any) => request<any>('/llm/summarize', { method: 'POST', body: JSON.stringify(data) }),
  agentGenerateTree: (data: any) => request<any>('/llm/agent', { method: 'POST', body: JSON.stringify(data) }),

  // Scenarios
  listScenarios: (projectId: string) => request<any[]>(`/scenarios/project/${projectId}`),
  createScenario: (data: any) => request<any>('/scenarios', { method: 'POST', body: JSON.stringify(data) }),
  getScenario: (id: string) => request<any>(`/scenarios/${id}`),
  updateScenario: (id: string, data: any) => request<any>(`/scenarios/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteScenario: (id: string) => request<void>(`/scenarios/${id}`, { method: 'DELETE' }),
  simulateScenario: (id: string, data: any) => request<any>(`/scenarios/${id}/simulate`, { method: 'POST', body: JSON.stringify(data) }),
  aiAnalyzeScenario: (id: string, data: any) => request<any>(`/scenarios/${id}/ai-analyze`, { method: 'POST', body: JSON.stringify(data) }),
  aiGenerateScenarios: (projectId: string) => request<any>(`/scenarios/project/${projectId}/ai-generate`, { method: 'POST' }),

  // Kill Chains
  listKillChains: (projectId: string) => request<any[]>(`/kill-chains/project/${projectId}`),
  createKillChain: (data: any) => request<any>('/kill-chains', { method: 'POST', body: JSON.stringify(data) }),
  getKillChain: (id: string) => request<any>(`/kill-chains/${id}`),
  deleteKillChain: (id: string) => request<void>(`/kill-chains/${id}`, { method: 'DELETE' }),
  aiMapKillChain: (id: string, data: any) => request<any>(`/kill-chains/${id}/ai-map`, { method: 'POST', body: JSON.stringify(data) }),
  aiGenerateKillChain: (projectId: string, data?: any) => request<any>(`/kill-chains/project/${projectId}/ai-generate`, { method: 'POST', body: data ? JSON.stringify(data) : undefined }),

  // Threat Models
  listThreatModels: (projectId: string) => request<any[]>(`/threat-models/project/${projectId}`),
  createThreatModel: (data: any) => request<any>('/threat-models', { method: 'POST', body: JSON.stringify(data) }),
  getThreatModel: (id: string) => request<any>(`/threat-models/${id}`),
  updateThreatModel: (id: string, data: any) => request<any>(`/threat-models/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteThreatModel: (id: string) => request<void>(`/threat-models/${id}`, { method: 'DELETE' }),
  aiGenerateDFD: (id: string, data: any) => request<any>(`/threat-models/${id}/ai-generate-dfd`, { method: 'POST', body: JSON.stringify(data) }),
  aiGenerateThreats: (id: string, data: any) => request<any>(`/threat-models/${id}/ai-generate-threats`, { method: 'POST', body: JSON.stringify(data) }),
  aiDeepDiveThreat: (tmId: string, data: { threat_id: string }) => request<any>(`/threat-models/${tmId}/ai-deep-dive`, { method: 'POST', body: JSON.stringify(data) }),
  linkThreatsToTree: (id: string, data: any) => request<any>(`/threat-models/${id}/link-to-tree`, { method: 'POST', body: JSON.stringify(data) }),
  aiFullThreatModel: (projectId: string, data: any) => request<any>(`/threat-models/project/${projectId}/ai-full-analysis`, { method: 'POST', body: JSON.stringify(data) }),

  // AI Chat (Brainstorm, Advisor, Challenger)
  aiBrainstorm: (data: { provider_id: string; project_name?: string; root_objective?: string; messages: Array<{ role: string; content: string }> }) =>
    request<{ status: string; content: string; model: string; tokens: number; elapsed_ms: number }>('/ai-chat/brainstorm', { method: 'POST', body: JSON.stringify(data) }),
  aiAdvisor: (data: { provider_id: string; question: string; project_name?: string; root_objective?: string; tree_context?: string }) =>
    request<{ status: string; content: string; model: string; tokens: number; elapsed_ms: number }>('/ai-chat/advisor', { method: 'POST', body: JSON.stringify(data) }),
  aiChallengeScores: (data: { provider_id: string; node_title: string; node_description?: string; node_type?: string; likelihood?: number; impact?: number; effort?: number; exploitability?: number; detectability?: number; inherent_risk?: number; mitigations_summary?: string; tree_context?: string }) =>
    request<{ status: string; content: string; model: string; tokens: number; elapsed_ms: number }>('/ai-chat/challenge-scores', { method: 'POST', body: JSON.stringify(data) }),
};
