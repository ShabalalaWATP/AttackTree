import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { NODE_TYPE_CONFIG, type AttackNodeData, type NodeType } from '@/types';
import { cn } from '@/utils/cn';

function getRiskBadge(risk: number | null | undefined): string {
  if (risk == null) return 'badge-risk-none';
  if (risk >= 7) return 'badge-risk-critical';
  if (risk >= 4) return 'badge-risk-medium';
  return 'badge-risk-low';
}

function getStatusBadge(status: string): string {
  switch (status) {
    case 'validated': return 'badge-status-validated';
    case 'mitigated': return 'badge-status-mitigated';
    case 'accepted': return 'badge-status-accepted';
    case 'archived': return 'badge-risk-none';
    default: return 'badge-status-draft';
  }
}

function getLogicBadge(logic: string): string {
  switch (logic) {
    case 'AND': return 'badge-logic-and';
    case 'SEQUENCE': return 'badge-logic-seq';
    default: return 'badge-logic-or';
  }
}

function AttackTreeNodeInner({ data, selected }: NodeProps) {
  const nodeData = data as unknown as AttackNodeData & { _heatmapMode?: boolean; _criticalPath?: boolean };
  const config = NODE_TYPE_CONFIG[nodeData.node_type as NodeType] || NODE_TYPE_CONFIG.attack_step;
  const risk = nodeData.inherent_risk ?? nodeData.rolled_up_risk;
  const hasMitigations = (nodeData.mitigations?.length || 0) > 0;
  const hasMappings = (nodeData.reference_mappings?.length || 0) > 0;

  // Heatmap background color
  let heatmapBg: string | undefined;
  if (nodeData._heatmapMode) {
    if (risk == null || risk === 0) {
      heatmapBg = 'rgba(107,114,128,0.1)';
    } else if (!hasMitigations) {
      heatmapBg = 'rgba(239,68,68,0.25)';
    } else {
      const maxEff = Math.max(...(nodeData.mitigations?.map(m => m.effectiveness) || [0]));
      if (maxEff >= 0.7) {
        heatmapBg = 'rgba(34,197,94,0.25)';
      } else {
        heatmapBg = 'rgba(245,158,11,0.25)';
      }
    }
  }

  const isCritical = nodeData._criticalPath;

  return (
    <div
      className={cn(
        'rounded-lg border-2 shadow-sm bg-card min-w-[180px] max-w-[260px] transition-all',
        selected ? 'border-primary ring-2 ring-primary/20' : 'border-border hover:border-primary/40',
        isCritical && 'ring-2 ring-red-500/40 border-red-500',
      )}
      style={{
        borderLeftColor: config.color,
        borderLeftWidth: 4,
        backgroundColor: heatmapBg,
      }}
    >
      <Handle type="target" position={Position.Top} className="!w-3 !h-3 !bg-muted-foreground !border-background" />

      {/* Header */}
      <div className="px-3 py-2">
        <div className="flex items-center gap-1.5 mb-1">
          <span className="text-sm">{config.icon}</span>
          <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{config.label}</span>
          <span className={cn('text-[10px] px-1.5 py-0.5 rounded-full ml-auto font-medium', getStatusBadge(nodeData.status))}>
            {nodeData.status}
          </span>
        </div>
        <div className="font-semibold text-xs leading-snug">{nodeData.title}</div>
        {nodeData.description && (
          <div className="text-[10px] text-muted-foreground mt-1 line-clamp-2">{nodeData.description}</div>
        )}
      </div>

      {/* Logic + Score bar */}
      <div className="flex items-center gap-1.5 px-3 py-1.5 border-t bg-muted/30 text-[10px]">
        <span className={cn('px-1.5 py-0.5 rounded font-bold', getLogicBadge(nodeData.logic_type))}>
          {nodeData.logic_type}
        </span>

        {risk != null && (
          <span className={cn('px-1.5 py-0.5 rounded font-bold', getRiskBadge(risk))}>
            Risk: {risk}
          </span>
        )}

        {nodeData.residual_risk != null && hasMitigations && (
          <span className="px-1.5 py-0.5 rounded badge-risk-low font-bold">
            Res: {nodeData.residual_risk}
          </span>
        )}

        <div className="flex items-center gap-0.5 ml-auto">
          {hasMitigations && <span title="Has mitigations">✅</span>}
          {hasMappings && <span title="Has mappings">📋</span>}
        </div>
      </div>

      <Handle type="source" position={Position.Bottom} className="!w-3 !h-3 !bg-muted-foreground !border-background" />
    </div>
  );
}

export const AttackTreeNode = memo(AttackTreeNodeInner);
