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

  // Nodes
  listNodes: (projectId: string) => request<any[]>(`/nodes/project/${projectId}`),
  createNode: (data: any) => request<any>('/nodes', { method: 'POST', body: JSON.stringify(data) }),
  updateNode: (id: string, data: any) => request<any>(`/nodes/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteNode: (id: string) => request<void>(`/nodes/${id}`, { method: 'DELETE' }),
  duplicateNode: (id: string) => request<any>(`/nodes/${id}/duplicate`, { method: 'POST' }),

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
  browseReferences: (framework: string, q?: string) =>
    request<{ framework: string; count: number; items: any[] }>(`/references/browse/${framework}?q=${encodeURIComponent(q || '')}`),

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
};
