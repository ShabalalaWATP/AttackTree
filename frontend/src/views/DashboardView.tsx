import { useMemo } from 'react';
import { useStore } from '@/stores/useStore';
import { NODE_TYPE_CONFIG, type NodeType } from '@/types';
import { cn } from '@/utils/cn';
import { AlertTriangle, Shield, Eye, Target, TrendingUp, BarChart3, Activity, Clock, Crosshair, Zap, Layers } from 'lucide-react';
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

function riskGrade(avg: number): { letter: string; label: string; gradient: string } {
  if (avg >= 8) return { letter: 'F', label: 'Critical', gradient: 'from-red-500 to-rose-600' };
  if (avg >= 6) return { letter: 'D', label: 'High Risk', gradient: 'from-orange-500 to-red-500' };
  if (avg >= 4) return { letter: 'C', label: 'Moderate', gradient: 'from-amber-400 to-orange-500' };
  if (avg >= 2) return { letter: 'B', label: 'Low Risk', gradient: 'from-blue-400 to-cyan-400' };
  return { letter: 'A', label: 'Minimal', gradient: 'from-emerald-400 to-green-500' };
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
    const maxRisk = scored.length ? Math.max(...scored.map(n => n.inherent_risk || 0)) : 0;

    // Risk distribution buckets
    const riskBuckets = [
      { label: 'Low', range: '0-2', min: 0, max: 2, count: 0, color: 'bg-emerald-500' },
      { label: 'Guarded', range: '2-4', min: 2, max: 4, count: 0, color: 'bg-blue-500' },
      { label: 'Medium', range: '4-6', min: 4, max: 6, count: 0, color: 'bg-amber-500' },
      { label: 'High', range: '6-8', min: 6, max: 8, count: 0, color: 'bg-orange-500' },
      { label: 'Critical', range: '8-10', min: 8, max: 10.1, count: 0, color: 'bg-red-500' },
    ];
    scored.forEach(n => {
      const r = n.inherent_risk || 0;
      const bucket = riskBuckets.find(b => r >= b.min && r < b.max);
      if (bucket) bucket.count++;
    });

    // Coverage stats
    const mitigationPct = nodes.length ? (mitigated.length / nodes.length) * 100 : 0;
    const detectionPct = nodes.length ? (withDetections.length / nodes.length) * 100 : 0;
    const mappingPct = nodes.length ? (withMappings.length / nodes.length) * 100 : 0;

    // Attack surface distribution
    const bySurface: Record<string, number> = {};
    nodes.forEach(n => {
      const s = (n as any).attack_surface || 'Unknown';
      bySurface[s] = (bySurface[s] || 0) + 1;
    });

    return {
      totalNodes: nodes.length, scored: scored.length, topRisks, unmitigated, mitigated,
      withDetections, withMappings, lowEffort, highLikelihood, byType, byStatus, avgRisk,
      maxRisk, riskBuckets, mitigationPct, detectionPct, mappingPct, bySurface,
    };
  }, [nodes]);

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

  const grade = riskGrade(analysis.avgRisk);

  return (
    <div className="h-full overflow-auto">
      {/* Hero header */}
      <div className="relative px-6 pt-6 pb-4 overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/5 via-blue-500/5 to-purple-500/5" />
        <div className="relative max-w-7xl mx-auto">
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-xl font-bold">{currentProject?.name ?? 'Risk Dashboard'}</h1>
              <p className="text-sm text-muted-foreground mt-0.5">{currentProject?.root_objective ?? 'Standalone analysis'}</p>
            </div>
            {/* Risk grade badge */}
            <div className="flex items-center gap-3">
              <div className="text-right">
                <div className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium">Risk Posture</div>
                <div className="text-xs text-muted-foreground">{grade.label}</div>
              </div>
              <div className={cn('w-12 h-12 rounded-xl bg-gradient-to-br flex items-center justify-center shadow-lg', grade.gradient)}>
                <span className="text-white text-xl font-black">{grade.letter}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="px-6 pb-6">
        <div className="max-w-7xl mx-auto space-y-5">

          {/* Quick stat cards with gradients */}
          <div className="grid grid-cols-6 gap-3">
            <GlassCard>
              <div className="flex items-center gap-2 mb-2">
                <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-500/20 flex items-center justify-center">
                  <Target size={14} className="text-cyan-400" />
                </div>
                <span className="text-[11px] text-muted-foreground font-medium">Total Nodes</span>
              </div>
              <div className="text-2xl font-black">{analysis.totalNodes}</div>
              <div className="text-[10px] text-muted-foreground">{analysis.scored} scored</div>
            </GlassCard>

            <GlassCard>
              <div className="flex items-center gap-2 mb-2">
                <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-amber-500/20 to-red-500/20 flex items-center justify-center">
                  <BarChart3 size={14} className="text-amber-400" />
                </div>
                <span className="text-[11px] text-muted-foreground font-medium">Avg Risk</span>
              </div>
              <div className={cn('text-2xl font-black', getRiskTextClass(analysis.avgRisk))}>{analysis.avgRisk.toFixed(1)}</div>
              <div className="text-[10px] text-muted-foreground">max: {analysis.maxRisk.toFixed(1)}</div>
            </GlassCard>

            <GlassCard>
              <div className="flex items-center gap-2 mb-2">
                <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-green-500/20 to-emerald-500/20 flex items-center justify-center">
                  <Shield size={14} className="text-green-400" />
                </div>
                <span className="text-[11px] text-muted-foreground font-medium">Mitigated</span>
              </div>
              <div className="text-2xl font-black text-green-400">{analysis.mitigationPct.toFixed(0)}%</div>
              <div className="text-[10px] text-muted-foreground">{analysis.mitigated.length}/{analysis.totalNodes} nodes</div>
            </GlassCard>

            <GlassCard>
              <div className="flex items-center gap-2 mb-2">
                <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-blue-500/20 to-indigo-500/20 flex items-center justify-center">
                  <Eye size={14} className="text-blue-400" />
                </div>
                <span className="text-[11px] text-muted-foreground font-medium">Detection</span>
              </div>
              <div className="text-2xl font-black text-blue-400">{analysis.detectionPct.toFixed(0)}%</div>
              <div className="text-[10px] text-muted-foreground">{analysis.withDetections.length}/{analysis.totalNodes} nodes</div>
            </GlassCard>

            <GlassCard>
              <div className="flex items-center gap-2 mb-2">
                <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-purple-500/20 to-fuchsia-500/20 flex items-center justify-center">
                  <Layers size={14} className="text-purple-400" />
                </div>
                <span className="text-[11px] text-muted-foreground font-medium">Mapped</span>
              </div>
              <div className="text-2xl font-black text-purple-400">{analysis.mappingPct.toFixed(0)}%</div>
              <div className="text-[10px] text-muted-foreground">{analysis.withMappings.length}/{analysis.totalNodes} refs</div>
            </GlassCard>

            <GlassCard>
              <div className="flex items-center gap-2 mb-2">
                <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-red-500/20 to-rose-500/20 flex items-center justify-center">
                  <AlertTriangle size={14} className="text-red-400" />
                </div>
                <span className="text-[11px] text-muted-foreground font-medium">Exposed</span>
              </div>
              <div className="text-2xl font-black text-red-400">{analysis.unmitigated.length}</div>
              <div className="text-[10px] text-muted-foreground">no mitigations</div>
            </GlassCard>
          </div>

          {/* Coverage progress bars */}
          <GlassCard>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Defence Coverage</h3>
            <div className="grid grid-cols-3 gap-6">
              <CoverageBar label="Mitigation" pct={analysis.mitigationPct} gradient="from-green-500 to-emerald-400" />
              <CoverageBar label="Detection" pct={analysis.detectionPct} gradient="from-blue-500 to-cyan-400" />
              <CoverageBar label="Framework Mapping" pct={analysis.mappingPct} gradient="from-purple-500 to-fuchsia-400" />
            </div>
          </GlassCard>

          <div className="grid grid-cols-3 gap-5">

            {/* Risk Distribution - visual chart */}
            <GlassCard className="col-span-1">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <Activity size={13} className="text-primary" /> Risk Distribution
              </h3>
              {analysis.scored > 0 ? (
                <div className="space-y-2">
                  {analysis.riskBuckets.map(bucket => {
                    const total = analysis.scored || 1;
                    const pct = (bucket.count / total) * 100;
                    return (
                      <div key={bucket.label} className="group">
                        <div className="flex items-center justify-between mb-0.5">
                          <span className="text-[10px] font-medium text-muted-foreground">{bucket.label}</span>
                          <span className="text-[10px] font-bold">{bucket.count} <span className="text-muted-foreground font-normal">({pct.toFixed(0)}%)</span></span>
                        </div>
                        <div className="h-3 bg-muted/50 rounded-full overflow-hidden">
                          <div
                            className={cn('h-full rounded-full bar-fill transition-all', bucket.color)}
                            style={{ width: `${pct}%`, minWidth: bucket.count > 0 ? '6px' : '0' }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="text-xs text-muted-foreground text-center py-4">No scored nodes yet</div>
              )}
            </GlassCard>

            {/* Top Risks */}
            <GlassCard className="col-span-2">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <Crosshair size={13} className="text-red-400" /> Top Risks
              </h3>
              <div className="space-y-0.5">
                {analysis.topRisks.map((n, i) => (
                  <div key={n.id} className="flex items-center gap-2 py-1.5 px-2 rounded-lg hover:bg-white/5 text-xs group">
                    <span className="w-4 text-[10px] text-muted-foreground font-mono">{i + 1}</span>
                    <span className="shrink-0 opacity-70">{NODE_TYPE_CONFIG[n.node_type as NodeType]?.icon}</span>
                    <span className="truncate flex-1">{n.title}</span>
                    <div className="flex items-center gap-2 shrink-0">
                      <div className="w-20 h-2 bg-muted/50 rounded-full overflow-hidden">
                        <div
                          className={cn('h-full rounded-full bar-fill', getRiskBarColor(n.inherent_risk || 0))}
                          style={{ width: `${((n.inherent_risk || 0) / 10) * 100}%` }}
                        />
                      </div>
                      <span className={cn('font-bold w-6 text-right tabular-nums text-xs', getRiskTextClass(n.inherent_risk || 0))}>
                        {(n.inherent_risk || 0).toFixed(1)}
                      </span>
                    </div>
                  </div>
                ))}
                {!analysis.topRisks.length && <div className="text-xs text-muted-foreground text-center py-2">No scored nodes</div>}
              </div>
            </GlassCard>
          </div>

          <div className="grid grid-cols-2 gap-5">
            {/* Unmitigated */}
            <GlassCard>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <Shield size={13} className="text-amber-400" /> Unmitigated Risks
              </h3>
              <div className="space-y-0.5">
                {analysis.unmitigated.slice(0, 8).map(n => (
                  <div key={n.id} className="flex items-center justify-between py-1.5 px-2 rounded-lg hover:bg-white/5 text-xs">
                    <span className="truncate mr-2">{n.title}</span>
                    <span className={cn('font-bold shrink-0 tabular-nums', getRiskTextClass(n.inherent_risk || 0))}>{(n.inherent_risk || 0).toFixed(1)}</span>
                  </div>
                ))}
                {!analysis.unmitigated.length && <div className="text-xs text-green-400 text-center py-3">All scored nodes mitigated</div>}
              </div>
            </GlassCard>

            {/* Lowest effort */}
            <GlassCard>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <Zap size={13} className="text-orange-400" /> Lowest Attacker Effort
              </h3>
              <div className="space-y-0.5">
                {analysis.lowEffort.map(n => (
                  <div key={n.id} className="flex items-center justify-between py-1.5 px-2 rounded-lg hover:bg-white/5 text-xs">
                    <span className="truncate mr-2">{n.title}</span>
                    <div className="flex gap-3 shrink-0 text-[11px]">
                      <span className="text-muted-foreground tabular-nums">E:{n.effort || '—'}</span>
                      <span className={cn('font-bold tabular-nums', getRiskTextClass(n.inherent_risk || 0))}>{(n.inherent_risk || 0).toFixed(1)}</span>
                    </div>
                  </div>
                ))}
              </div>
            </GlassCard>
          </div>

          <div className="grid grid-cols-2 gap-5">
            {/* Node type breakdown */}
            <GlassCard>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Node Types</h3>
              <div className="space-y-1.5">
                {Object.entries(analysis.byType).sort((a, b) => b[1] - a[1]).map(([type, count]) => {
                  const pct = (count / analysis.totalNodes) * 100;
                  return (
                    <div key={type} className="flex items-center gap-2">
                      <span className="flex items-center gap-1.5 w-28 shrink-0 text-[11px]">
                        <span className="opacity-70">{NODE_TYPE_CONFIG[type as NodeType]?.icon}</span>
                        <span className="truncate">{NODE_TYPE_CONFIG[type as NodeType]?.label || type}</span>
                      </span>
                      <div className="flex-1 h-4 bg-muted/50 rounded-full overflow-hidden">
                        <div className="h-full rounded-full bg-primary/50 bar-fill" style={{ width: `${pct}%`, minWidth: count > 0 ? '6px' : '0' }} />
                      </div>
                      <span className="text-[11px] font-bold w-8 text-right tabular-nums">{count}</span>
                    </div>
                  );
                })}
              </div>
            </GlassCard>

            {/* Status breakdown */}
            <GlassCard>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Status</h3>
              <div className="space-y-1.5">
                {Object.entries(analysis.byStatus).sort((a, b) => b[1] - a[1]).map(([status, count]) => {
                  const pct = (count / analysis.totalNodes) * 100;
                  const statusColors: Record<string, string> = {
                    draft: 'bg-slate-400', validated: 'bg-blue-500', mitigated: 'bg-green-500',
                    accepted: 'bg-amber-500', archived: 'bg-muted-foreground',
                  };
                  return (
                    <div key={status} className="flex items-center gap-2">
                      <div className="flex items-center gap-1.5 w-24 shrink-0">
                        <div className={cn('w-2 h-2 rounded-full', statusColors[status] || 'bg-muted-foreground')} />
                        <span className="text-[11px] capitalize">{status}</span>
                      </div>
                      <div className="flex-1 h-4 bg-muted/50 rounded-full overflow-hidden">
                        <div
                          className={cn('h-full rounded-full bar-fill', statusColors[status] || 'bg-muted-foreground')}
                          style={{ width: `${pct}%`, minWidth: count > 0 ? '6px' : '0' }}
                        />
                      </div>
                      <span className="text-[11px] font-bold w-8 text-right tabular-nums">{count}</span>
                    </div>
                  );
                })}
              </div>
            </GlassCard>
          </div>

          {/* Most likely attack vectors */}
          {analysis.highLikelihood.length > 0 && (
            <GlassCard>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <TrendingUp size={13} className="text-red-400" /> Highest Likelihood Vectors
              </h3>
              <div className="grid grid-cols-5 gap-2">
                {analysis.highLikelihood.map(n => (
                  <div key={n.id} className="px-3 py-2.5 rounded-lg bg-muted/30 border border-border/30 text-center">
                    <div className={cn('text-lg font-black tabular-nums', getRiskTextClass(n.likelihood || 0))}>{n.likelihood}</div>
                    <div className="text-[10px] text-muted-foreground truncate mt-0.5">{n.title}</div>
                  </div>
                ))}
              </div>
            </GlassCard>
          )}

          {/* Recent Activity */}
          <GlassCard>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-1.5">
              <Clock size={13} className="text-primary" /> Recent Activity
            </h3>
            <AuditLogPanel projectId={currentProject?.id ?? ''} />
          </GlassCard>
        </div>
      </div>
    </div>
  );
}

/* ── Reusable card components ── */

function GlassCard({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn('rounded-xl border border-border/40 bg-card/60 backdrop-blur-sm p-4', className)}>
      {children}
    </div>
  );
}

function CoverageBar({ label, pct, gradient }: { label: string; pct: number; gradient: string }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-xs font-medium">{label}</span>
        <span className="text-sm font-bold tabular-nums">{pct.toFixed(0)}%</span>
      </div>
      <div className="h-2.5 bg-muted/50 rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full bg-gradient-to-r bar-fill', gradient)} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}
