import { useMemo } from 'react';
import { useStore } from '@/stores/useStore';
import { NODE_TYPE_CONFIG, type NodeType } from '@/types';
import { cn } from '@/utils/cn';
import { AlertTriangle, Shield, Eye, Target, TrendingUp, BarChart3, Activity, Clock } from 'lucide-react';
import { AuditLogPanel } from '@/components/AuditLogPanel';

function getRiskTextClass(risk: number): string {
  if (risk >= 7) return 'text-risk-critical';
  if (risk >= 4) return 'text-risk-medium';
  return 'text-risk-low';
}

function getRiskBarColor(risk: number): string {
  if (risk >= 7) return 'bg-[hsl(var(--risk-critical-text))]';
  if (risk >= 4) return 'bg-[hsl(var(--risk-medium-text))]';
  return 'bg-[hsl(var(--risk-low-text))]';
}

export function DashboardView() {
  const { currentProject, nodes } = useStore();

  const analysis = useMemo(() => {
    if (!nodes.length) return null;

    const scored = nodes.filter(n => n.inherent_risk != null);
    const topRisks = [...scored].sort((a, b) => (b.inherent_risk || 0) - (a.inherent_risk || 0)).slice(0, 10);
    const unmitigated = scored.filter(n => !n.mitigations?.length).sort((a, b) => (b.inherent_risk || 0) - (a.inherent_risk || 0));
    const mitigated = nodes.filter(n => n.mitigations?.length);
    const withDetections = nodes.filter(n => n.detections?.length);
    const withMappings = nodes.filter(n => n.reference_mappings?.length);
    const lowEffort = [...scored].sort((a, b) => (a.effort || 10) - (b.effort || 10)).slice(0, 5);
    const highLikelihood = [...scored].sort((a, b) => (b.likelihood || 0) - (a.likelihood || 0)).slice(0, 5);

    const byType: Record<string, number> = {};
    const byStatus: Record<string, number> = {};
    nodes.forEach(n => {
      byType[n.node_type] = (byType[n.node_type] || 0) + 1;
      byStatus[n.status] = (byStatus[n.status] || 0) + 1;
    });

    const avgRisk = scored.length ? scored.reduce((s, n) => s + (n.inherent_risk || 0), 0) / scored.length : 0;

    // Risk distribution buckets
    const riskBuckets = [
      { label: '0-2 Low', min: 0, max: 2, count: 0, color: 'bg-[hsl(var(--risk-low-text))]' },
      { label: '2-4', min: 2, max: 4, count: 0, color: 'bg-[hsl(var(--risk-low-text))]' },
      { label: '4-6 Medium', min: 4, max: 6, count: 0, color: 'bg-[hsl(var(--risk-medium-text))]' },
      { label: '6-8 High', min: 6, max: 8, count: 0, color: 'bg-[hsl(var(--risk-high-text))]' },
      { label: '8-10 Critical', min: 8, max: 10.1, count: 0, color: 'bg-[hsl(var(--risk-critical-text))]' },
    ];
    scored.forEach(n => {
      const r = n.inherent_risk || 0;
      const bucket = riskBuckets.find(b => r >= b.min && r < b.max);
      if (bucket) bucket.count++;
    });

    return {
      totalNodes: nodes.length, scored: scored.length, topRisks, unmitigated, mitigated,
      withDetections, withMappings, lowEffort, highLikelihood, byType, byStatus, avgRisk,
      riskBuckets,
    };
  }, [nodes]);

  if (!currentProject) {
    return (
      <div className="h-full flex items-center justify-center text-muted-foreground">
        <div className="text-center">
          <p className="mb-2">Open a project to view its dashboard</p>
          <button
            onClick={() => useStore.getState().setViewMode('projects')}
            className="text-primary text-sm hover:underline"
          >
            Go to Projects
          </button>
        </div>
      </div>
    );
  }

  if (!analysis) {
    return (
      <div className="h-full flex items-center justify-center text-muted-foreground">
        <div className="text-center">
          <p className="mb-2">No nodes in this project yet.</p>
          <button
            onClick={() => useStore.getState().setViewMode('tree')}
            className="text-primary text-sm hover:underline"
          >
            Open Tree Editor to add nodes
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto p-6">
      <div className="max-w-6xl mx-auto space-y-6">
        <div>
          <h1 className="text-xl font-bold">{currentProject.name} — Dashboard</h1>
          <p className="text-sm text-muted-foreground">{currentProject.root_objective}</p>
        </div>

        {/* Summary cards */}
        <div className="grid grid-cols-4 gap-4">
          <StatCard icon={<Target size={18} />} label="Total Nodes" value={analysis.totalNodes} />
          <StatCard icon={<BarChart3 size={18} />} label="Avg Risk" value={analysis.avgRisk.toFixed(1)} color={getRiskTextClass(analysis.avgRisk)} />
          <StatCard icon={<Shield size={18} />} label="Mitigated" value={`${analysis.mitigated.length}/${analysis.totalNodes}`} color="text-success" />
          <StatCard icon={<Eye size={18} />} label="With Detections" value={`${analysis.withDetections.length}/${analysis.totalNodes}`} color="text-info" />
        </div>

        <div className="grid grid-cols-2 gap-6">
          {/* Risk Distribution Chart */}
          <div className="border rounded-lg p-4 bg-card">
            <h3 className="font-semibold text-sm mb-3 flex items-center gap-2">
              <Activity size={15} className="text-primary" /> Risk Distribution
            </h3>
            {analysis.scored > 0 ? (
              <div className="space-y-2.5">
                {analysis.riskBuckets.map(bucket => {
                  const maxCount = Math.max(...analysis.riskBuckets.map(b => b.count), 1);
                  const pct = (bucket.count / maxCount) * 100;
                  return (
                    <div key={bucket.label} className="flex items-center gap-2">
                      <span className="text-[11px] font-medium w-20 text-right text-muted-foreground shrink-0">{bucket.label}</span>
                      <div className="flex-1 h-6 bg-muted rounded-md overflow-hidden">
                        <div
                          className={cn('h-full rounded-md bar-fill', bucket.color)}
                          style={{ width: `${pct}%`, minWidth: bucket.count > 0 ? '8px' : '0' }}
                        />
                      </div>
                      <span className="text-xs font-bold w-6 text-right">{bucket.count}</span>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-xs text-muted-foreground text-center py-4">No scored nodes yet</div>
            )}
          </div>

          {/* Top risks */}
          <div className="border rounded-lg p-4 bg-card">
            <h3 className="font-semibold text-sm mb-3 flex items-center gap-2">
              <AlertTriangle size={15} className="text-risk-critical" /> Top Risks
            </h3>
            <div className="space-y-1">
              {analysis.topRisks.map(n => (
                <div key={n.id} className="flex items-center gap-2 py-1.5 px-2 rounded hover:bg-muted text-xs">
                  <span className="shrink-0">{NODE_TYPE_CONFIG[n.node_type as NodeType]?.icon}</span>
                  <span className="truncate flex-1">{n.title}</span>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <div className="w-16 h-2 bg-muted rounded-full overflow-hidden">
                      <div
                        className={cn('h-full rounded-full bar-fill', getRiskBarColor(n.inherent_risk || 0))}
                        style={{ width: `${((n.inherent_risk || 0) / 10) * 100}%` }}
                      />
                    </div>
                    <span className={cn('font-bold w-5 text-right', getRiskTextClass(n.inherent_risk || 0))}>
                      {n.inherent_risk}
                    </span>
                  </div>
                </div>
              ))}
              {!analysis.topRisks.length && <div className="text-xs text-muted-foreground text-center py-2">No scored nodes</div>}
            </div>
          </div>

          {/* Unmitigated */}
          <div className="border rounded-lg p-4 bg-card">
            <h3 className="font-semibold text-sm mb-3 flex items-center gap-2">
              <Shield size={15} className="text-warning" /> Unmitigated Risks
            </h3>
            <div className="space-y-1">
              {analysis.unmitigated.slice(0, 10).map(n => (
                <div key={n.id} className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-muted text-xs">
                  <span className="truncate">{n.title}</span>
                  <span className="font-bold text-risk-critical">{n.inherent_risk}</span>
                </div>
              ))}
              {!analysis.unmitigated.length && <div className="text-xs text-success text-center py-2">All scored nodes have mitigations &#10003;</div>}
            </div>
          </div>

          {/* Lowest effort for attacker */}
          <div className="border rounded-lg p-4 bg-card">
            <h3 className="font-semibold text-sm mb-3 flex items-center gap-2">
              <TrendingUp size={15} className="text-risk-high" /> Lowest Attacker Effort
            </h3>
            <div className="space-y-1">
              {analysis.lowEffort.map(n => (
                <div key={n.id} className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-muted text-xs">
                  <span className="truncate">{n.title}</span>
                  <div className="flex gap-2 shrink-0">
                    <span className="text-muted-foreground">Effort: {n.effort || '—'}</span>
                    <span className="font-bold">Risk: {n.inherent_risk}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Node type breakdown with bars */}
          <div className="border rounded-lg p-4 bg-card">
            <h3 className="font-semibold text-sm mb-3">Node Type Breakdown</h3>
            <div className="space-y-2">
              {Object.entries(analysis.byType).sort((a, b) => b[1] - a[1]).map(([type, count]) => {
                const maxCount = Math.max(...Object.values(analysis.byType), 1);
                const pct = (count / maxCount) * 100;
                return (
                  <div key={type} className="flex items-center gap-2">
                    <span className="flex items-center gap-1.5 w-28 shrink-0 text-xs">
                      <span>{NODE_TYPE_CONFIG[type as NodeType]?.icon}</span>
                      <span className="truncate">{NODE_TYPE_CONFIG[type as NodeType]?.label || type}</span>
                    </span>
                    <div className="flex-1 h-5 bg-muted rounded-md overflow-hidden">
                      <div
                        className="h-full rounded-md bg-primary/60 bar-fill"
                        style={{ width: `${pct}%`, minWidth: count > 0 ? '6px' : '0' }}
                      />
                    </div>
                    <span className="text-xs font-bold w-6 text-right">{count}</span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Status breakdown */}
          <div className="border rounded-lg p-4 bg-card">
            <h3 className="font-semibold text-sm mb-3">Status Breakdown</h3>
            <div className="space-y-2">
              {Object.entries(analysis.byStatus).sort((a, b) => b[1] - a[1]).map(([status, count]) => {
                const maxCount = Math.max(...Object.values(analysis.byStatus), 1);
                const pct = (count / maxCount) * 100;
                const statusColors: Record<string, string> = {
                  draft: 'bg-[hsl(var(--status-draft-text))]',
                  validated: 'bg-[hsl(var(--status-validated-text))]',
                  mitigated: 'bg-[hsl(var(--status-mitigated-text))]',
                  accepted: 'bg-[hsl(var(--status-accepted-text))]',
                  archived: 'bg-muted-foreground',
                };
                return (
                  <div key={status} className="flex items-center gap-2">
                    <span className="text-xs w-20 shrink-0 capitalize">{status}</span>
                    <div className="flex-1 h-5 bg-muted rounded-md overflow-hidden">
                      <div
                        className={cn('h-full rounded-md bar-fill', statusColors[status] || 'bg-muted-foreground')}
                        style={{ width: `${pct}%`, minWidth: count > 0 ? '6px' : '0' }}
                      />
                    </div>
                    <span className="text-xs font-bold w-6 text-right">{count}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Mapping coverage */}
        <div className="border rounded-lg p-4 bg-card">
          <h3 className="font-semibold text-sm mb-3">Mapping Coverage</h3>
          <div className="flex gap-8 items-center">
            <div className="flex gap-6 text-sm">
              <div><span className="font-bold text-lg">{analysis.withMappings.length}</span> <span className="text-muted-foreground">with mappings</span></div>
              <div><span className="font-bold text-lg">{analysis.totalNodes - analysis.withMappings.length}</span> <span className="text-muted-foreground">without mappings</span></div>
            </div>
            <div className="flex-1 h-4 bg-muted rounded-full overflow-hidden">
              <div
                className="h-full rounded-full bg-primary bar-fill"
                style={{ width: `${(analysis.withMappings.length / analysis.totalNodes) * 100}%` }}
              />
            </div>
            <span className="text-sm font-bold">{((analysis.withMappings.length / analysis.totalNodes) * 100).toFixed(0)}%</span>
          </div>
        </div>

        {/* Recent Activity (Audit Log) */}
        <div className="border rounded-lg p-4 bg-card">
          <h3 className="font-semibold text-sm mb-3 flex items-center gap-2">
            <Clock size={15} className="text-primary" /> Recent Activity
          </h3>
          <AuditLogPanel projectId={currentProject.id} />
        </div>
      </div>
    </div>
  );
}

function StatCard({ icon, label, value, color = '' }: { icon: React.ReactNode; label: string; value: string | number; color?: string }) {
  return (
    <div className="border rounded-lg p-4 bg-card">
      <div className="flex items-center gap-2 text-muted-foreground mb-1">{icon}<span className="text-xs font-medium">{label}</span></div>
      <div className={cn('text-2xl font-bold', color)}>{value}</div>
    </div>
  );
}
