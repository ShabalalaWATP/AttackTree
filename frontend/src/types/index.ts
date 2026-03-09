// === Domain Types ===

export type NodeType =
  | 'goal' | 'sub_goal' | 'attack_step' | 'precondition' | 'assumption'
  | 'asset' | 'trust_boundary' | 'weakness' | 'mitigation' | 'detection_point'
  | 'evidence' | 'pivot_point' | 'post_condition' | 'note';

export type LogicType = 'AND' | 'OR' | 'SEQUENCE';

export type NodeStatus = 'draft' | 'validated' | 'mitigated' | 'accepted' | 'archived';

export interface MitigationData {
  id: string;
  node_id: string;
  title: string;
  description: string;
  effectiveness: number;
  status: string;
  control_ref: string;
  created_at: string;
}

export interface DetectionData {
  id: string;
  node_id: string;
  title: string;
  description: string;
  coverage: number;
  data_source: string;
  created_at: string;
}

export interface ReferenceMappingData {
  id: string;
  node_id: string;
  framework: string;
  ref_id: string;
  ref_name: string;
}

export interface CommentData {
  id: string;
  node_id: string;
  author: string;
  text: string;
  created_at: string;
}

export interface TagData {
  id: string;
  name: string;
}

export interface AuditEventData {
  id: string;
  project_id: string;
  event_type: string;
  entity_type: string;
  entity_id: string;
  detail: Record<string, unknown>;
  actor: string;
  timestamp: string;
}

export interface AttackNodeData {
  id: string;
  project_id: string;
  parent_id: string | null;
  node_type: NodeType;
  title: string;
  description: string;
  notes: string;
  logic_type: LogicType;
  status: NodeStatus;
  sort_order: number;
  position_x: number;
  position_y: number;
  threat_category: string;
  attack_surface: string;
  platform: string;
  required_access: string;
  required_privileges: string;
  required_tools: string;
  required_skill: string;
  likelihood: number | null;
  impact: number | null;
  effort: number | null;
  exploitability: number | null;
  detectability: number | null;
  confidence: number | null;
  inherent_risk: number | null;
  residual_risk: number | null;
  probability: number | null;
  cost_to_attacker: number | null;
  time_estimate: string;
  rolled_up_risk: number | null;
  rolled_up_likelihood: number | null;
  assumptions: string;
  analyst: string;
  cve_references: string;
  extended_metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  mitigations: MitigationData[];
  detections: DetectionData[];
  reference_mappings: ReferenceMappingData[];
  tags: TagData[];
}

export interface ProjectData {
  id: string;
  name: string;
  description: string;
  context_preset: string;
  root_objective: string;
  owner: string;
  created_at: string;
  updated_at: string;
  node_count: number;
}

export interface TemplateInfo {
  id: string;
  name: string;
  description: string;
  context_preset: string;
  node_count: number;
}

export interface TemplateData {
  name: string;
  description: string;
  context_preset: string;
  root_objective: string;
  nodes: Partial<AttackNodeData>[];
}

export interface SnapshotData {
  id: string;
  project_id: string;
  label: string;
  created_at: string;
  created_by: string;
}

export interface LLMProviderData {
  id: string;
  name: string;
  base_url: string;
  has_api_key: boolean;
  model: string;
  custom_headers: Record<string, string>;
  timeout: number;
  stream_enabled: boolean;
  tls_verify: boolean;
  ca_bundle_path: string;
  client_cert_path: string;
  client_key_path: string;
  is_active: boolean;
  last_tested_at: string | null;
  last_test_result: string;
  last_test_message: string;
  created_at: string;
  updated_at: string;
}

export interface SuggestedNode {
  title: string;
  description: string;
  node_type: string;
  logic_type: string;
  threat_category: string;
  likelihood: number | null;
  impact: number | null;
}

export interface ReferenceItem {
  id: string;
  name: string;
  description?: string;
  tactic?: string;
  severity?: string;
  category?: string;
}

// Node type display configuration
export const NODE_TYPE_CONFIG: Record<NodeType, { label: string; color: string; icon: string }> = {
  goal: { label: 'Goal', color: '#dc2626', icon: '🎯' },
  sub_goal: { label: 'Sub-Goal', color: '#ea580c', icon: '◎' },
  attack_step: { label: 'Attack Step', color: '#d97706', icon: '⚔️' },
  precondition: { label: 'Precondition', color: '#7c3aed', icon: '🔑' },
  assumption: { label: 'Assumption', color: '#6b7280', icon: '💭' },
  asset: { label: 'Asset/Target', color: '#2563eb', icon: '🏢' },
  trust_boundary: { label: 'Trust Boundary', color: '#0891b2', icon: '🛡️' },
  weakness: { label: 'Weakness', color: '#be123c', icon: '🔓' },
  mitigation: { label: 'Mitigation', color: '#16a34a', icon: '✅' },
  detection_point: { label: 'Detection', color: '#0d9488', icon: '👁️' },
  evidence: { label: 'Evidence', color: '#4b5563', icon: '📎' },
  pivot_point: { label: 'Pivot Point', color: '#9333ea', icon: '↗️' },
  post_condition: { label: 'Outcome', color: '#1d4ed8', icon: '🏁' },
  note: { label: 'Note', color: '#9ca3af', icon: '📝' },
};

export const CONTEXT_PRESETS = [
  { id: 'general', name: 'General' },
  { id: 'web_application', name: 'Web Application' },
  { id: 'api_microservice', name: 'API / Microservice' },
  { id: 'android_application', name: 'Android Application' },
  { id: 'thick_client', name: 'Thick Client / Desktop' },
  { id: 'enterprise', name: 'Enterprise / Active Directory' },
  { id: 'cloud_iam', name: 'Cloud / IAM / Kubernetes' },
  { id: 'data_centre', name: 'Data Centre / Facilities' },
  { id: 'ot_ics', name: 'OT / ICS' },
  { id: 'hybrid_it_ot', name: 'Hybrid IT/OT' },
  { id: 'ai_llm', name: 'AI / LLM / Agentic System' },
  { id: 'supply_chain', name: 'Supply Chain / Third Party' },
];
