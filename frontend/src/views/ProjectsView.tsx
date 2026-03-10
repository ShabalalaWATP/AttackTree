import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/utils/api';
import { useStore } from '@/stores/useStore';
import { CONTEXT_PRESETS, type TemplateInfo } from '@/types';
import toast from 'react-hot-toast';
import { Plus, Trash2, FolderOpen, Copy, FileText, GitBranch, Search, X, Sparkles, ChevronRight, Shield, Crosshair, Route, ShieldCheck, FlaskConical, Clock } from 'lucide-react';
import { cn } from '@/utils/cn';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import ocpLogo from '@/assets/ocp.png';

export function ProjectsView() {
  const queryClient = useQueryClient();
  const { setCurrentProject, setViewMode, setNodes } = useStore();
  const [showCreate, setShowCreate] = useState(false);
  const [showTemplates, setShowTemplates] = useState(false);
  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newObjective, setNewObjective] = useState('');
  const [newPreset, setNewPreset] = useState('general');
  const [newWorkspaceMode, setNewWorkspaceMode] = useState<'project_scan' | 'standalone_scan'>('project_scan');
  const [deleteProjectId, setDeleteProjectId] = useState<string | null>(null);
  const [globalSearch, setGlobalSearch] = useState('');
  const [globalSearchTerm, setGlobalSearchTerm] = useState('');

  const { data, isLoading } = useQuery({ queryKey: ['projects'], queryFn: api.listProjects });
  const deleteProjectName = deleteProjectId
    ? (data?.projects?.find((p: any) => p.id === deleteProjectId)?.name || 'this project')
    : '';
  const { data: templates } = useQuery({ queryKey: ['templates'], queryFn: api.listTemplates });

  const { data: searchResults, isLoading: searchLoading } = useQuery({
    queryKey: ['globalSearch', globalSearchTerm],
    queryFn: () => api.searchAcrossProjects(globalSearchTerm),
    enabled: globalSearchTerm.length > 0,
  });

  const createMutation = useMutation({
    mutationFn: api.createProject,
    onSuccess: (_, variables: any) => {
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      setShowCreate(false);
      toast.success(variables?.workspace_mode === 'standalone_scan' ? 'Standalone scan created' : 'Project scan created');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: api.deleteProject,
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['projects'] }); toast.success('Workspace deleted'); },
  });

  const openProject = async (project: any) => {
    setCurrentProject(project);
    const nodes = await api.listNodes(project.id);
    setNodes(nodes);
    setViewMode('project_home');
  };

  const openNodeInProject = async (projectId: string, nodeId: string) => {
    const project = await api.getProject(projectId);
    setCurrentProject(project);
    const nodes = await api.listNodes(projectId);
    setNodes(nodes);
    useStore.getState().setSelectedNodeId(nodeId);
    setViewMode('tree');
  };

  const createFromTemplate = async (templateId: string) => {
    try {
      const template = await api.getTemplate(templateId);
      const result = await api.importJson({
        project: {
          name: template.name,
          description: template.description,
          context_preset: template.context_preset,
          root_objective: template.root_objective,
          workspace_mode: 'project_scan',
        },
        nodes: template.nodes,
      });
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      toast.success(`Created from template: ${template.name}`);
      setShowTemplates(false);
      const project = await api.getProject(result.project_id);
      openProject(project);
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const projectCount = data?.projects?.length || 0;
  const standaloneCount = data?.projects?.filter((p: any) => p.workspace_mode === 'standalone_scan').length || 0;
  const projectScanCount = projectCount - standaloneCount;

  return (
    <div className="h-full overflow-auto">
      {/* ——— Hero section ——— */}
      <div className="relative overflow-hidden">
        {/* Gradient backdrop */}
        <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/5 via-blue-500/5 to-purple-500/5" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_left,_var(--tw-gradient-stops))] from-cyan-500/10 via-transparent to-transparent" />
        {/* Grid pattern */}
        <div className="absolute inset-0 opacity-[0.03]" style={{
          backgroundImage: 'linear-gradient(hsl(var(--foreground)) 1px, transparent 1px), linear-gradient(90deg, hsl(var(--foreground)) 1px, transparent 1px)',
          backgroundSize: '40px 40px'
        }} />

        <div className="relative max-w-6xl mx-auto px-6 pt-10 pb-8">
          <div className="flex items-start justify-between">
            <div>
              <div className="flex items-center gap-5 mb-4">
                <div className="relative">
                  <div className="absolute -inset-2 rounded-2xl bg-gradient-to-br from-cyan-500/30 via-blue-500/20 to-purple-500/30 blur-lg" />
                  <img src={ocpLogo} alt="OCP" className="relative w-20 h-20 rounded-2xl shadow-2xl shadow-primary/30 ring-2 ring-white/10" />
                </div>
                <div>
                  <h1 className="text-4xl font-black tracking-tight bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-500 bg-clip-text text-transparent">
                    Offensive Cyber Planner
                  </h1>
                  <p className="text-sm text-muted-foreground mt-1">
                    Create either a standalone scan workspace or a full project scan workspace
                  </p>
                </div>
              </div>

              {/* Quick stats */}
              <div className="flex gap-6 mt-5">
                <QuickStat icon={<FolderOpen size={14} />} label="Workspaces" value={projectCount} />
                <QuickStat icon={<Crosshair size={14} />} label="Standalone" value={standaloneCount} accent="orange" />
                <QuickStat icon={<GitBranch size={14} />} label="Project Scan" value={projectScanCount} accent="cyan" />
                <QuickStat icon={<FlaskConical size={14} />} label="Scenarios" value="--" accent="purple" />
                <QuickStat icon={<ShieldCheck size={14} />} label="Threat Models" value="--" accent="emerald" />
              </div>
            </div>

            {/* Action buttons */}
            <div className="flex flex-col gap-2 mt-1">
              <button
                onClick={() => setShowCreate(!showCreate)}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white text-sm font-semibold shadow-lg shadow-blue-500/25 hover:shadow-blue-500/40 hover:translate-y-[-1px] transition-all"
              >
                <Plus size={16} /> New Workspace
              </button>
              <button
                onClick={() => setShowTemplates(!showTemplates)}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl border border-border/50 bg-card/50 backdrop-blur-sm text-sm font-medium hover:bg-card hover:border-primary/30 transition-all"
              >
                <Copy size={16} /> From Template
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-6xl mx-auto px-6 pb-8">
        {/* ——— Search ——— */}
        <div className="mb-6 -mt-2">
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Search size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
              <input
                value={globalSearch}
                onChange={(e) => setGlobalSearch(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && setGlobalSearchTerm(globalSearch)}
                placeholder="Search nodes across all workspaces..."
                className="w-full pl-10 pr-4 py-2.5 rounded-xl border border-border/50 bg-card/50 backdrop-blur-sm text-sm focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary/40 transition-all"
              />
            </div>
            {globalSearchTerm && (
              <button onClick={() => { setGlobalSearch(''); setGlobalSearchTerm(''); }} className="p-2.5 rounded-xl border border-border/50 bg-card/50 hover:bg-destructive/10">
                <X size={14} />
              </button>
            )}
            <button onClick={() => setGlobalSearchTerm(globalSearch)} disabled={!globalSearch.trim()}
              className="px-5 py-2.5 rounded-xl bg-card border border-border/50 text-sm font-medium hover:border-primary/40 disabled:opacity-40 transition-all">
              Search
            </button>
          </div>

          {globalSearchTerm && (
            <div className="mt-3 border border-border/50 rounded-xl bg-card/80 backdrop-blur-sm divide-y divide-border/30 max-h-64 overflow-auto shadow-lg">
              {searchLoading ? (
                <div className="p-4 text-center text-sm text-muted-foreground">Searching...</div>
              ) : searchResults && searchResults.count > 0 ? (
                <>
                  <div className="px-4 py-2 text-xs text-muted-foreground bg-muted/30 rounded-t-xl">{searchResults.count} matching nodes</div>
                  {searchResults.results.map((r: any) => (
                    <button
                      key={r.node_id}
                      onClick={() => openNodeInProject(r.project_id, r.node_id)}
                      className="w-full text-left px-4 py-2.5 hover:bg-accent/50 flex items-start gap-3 text-sm transition-colors"
                    >
                      <span className="text-[10px] font-bold uppercase text-primary bg-primary/10 px-1.5 py-0.5 rounded-md mt-0.5 shrink-0">{r.node_type.replace('_', ' ')}</span>
                      <div className="min-w-0 flex-1">
                        <div className="font-medium truncate">{r.title}</div>
                        {r.description && <div className="text-xs text-muted-foreground line-clamp-1 mt-0.5">{r.description}</div>}
                      </div>
                      <span className="text-[10px] text-muted-foreground shrink-0">{r.project_name}</span>
                      {r.inherent_risk != null && (
                        <span className={cn(
                          'text-[10px] px-1.5 py-0.5 rounded-md font-bold shrink-0',
                          r.inherent_risk >= 7 ? 'bg-red-500/10 text-red-600 dark:text-red-400' :
                          r.inherent_risk >= 4 ? 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400' :
                          'bg-green-500/10 text-green-600 dark:text-green-400'
                        )}>
                          Risk: {r.inherent_risk}
                        </span>
                      )}
                    </button>
                  ))}
                </>
              ) : (
                <div className="p-4 text-center text-sm text-muted-foreground">No matching nodes found</div>
              )}
            </div>
          )}
        </div>

        {/* ——— Create form ——— */}
        {showCreate && (
          <div className="border border-border/50 rounded-xl p-5 mb-6 bg-card/80 backdrop-blur-sm shadow-lg">
            <h3 className="font-semibold mb-4 flex items-center gap-2">
              <Plus size={16} className="text-primary" /> Create New Workspace
            </h3>
            <div className="grid grid-cols-2 gap-4">
              <div className="col-span-2">
                <label className="text-xs font-medium text-muted-foreground">Workspace Mode</label>
                <div className="mt-1 grid grid-cols-2 gap-2">
                  <button
                    onClick={() => setNewWorkspaceMode('project_scan')}
                    className={cn(
                      'rounded-lg border px-3 py-2.5 text-left text-sm transition-colors',
                      newWorkspaceMode === 'project_scan' ? 'border-primary bg-primary/10 text-primary' : 'border-border/50 bg-background hover:bg-accent'
                    )}
                  >
                    <div className="font-semibold">Project Scan</div>
                    <div className="text-xs text-muted-foreground mt-0.5">Persistent workspace for a specific client, product, or engagement.</div>
                  </button>
                  <button
                    onClick={() => setNewWorkspaceMode('standalone_scan')}
                    className={cn(
                      'rounded-lg border px-3 py-2.5 text-left text-sm transition-colors',
                      newWorkspaceMode === 'standalone_scan' ? 'border-primary bg-primary/10 text-primary' : 'border-border/50 bg-background hover:bg-accent'
                    )}
                  >
                    <div className="font-semibold">Standalone Scan</div>
                    <div className="text-xs text-muted-foreground mt-0.5">Ad hoc workspace for one-off scanning, rapid assessment, or exploratory analysis.</div>
                  </button>
                </div>
              </div>
              <div>
                <label className="text-xs font-medium text-muted-foreground">{newWorkspaceMode === 'standalone_scan' ? 'Scan Name' : 'Project Name'}</label>
                <input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder={newWorkspaceMode === 'standalone_scan' ? 'e.g., External Attack Surface Sweep' : 'e.g., Q1 Web App Risk Assessment'}
                  className="w-full mt-1 px-3 py-2.5 rounded-lg border border-border/50 bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary/30" />
              </div>
              <div>
                <label className="text-xs font-medium text-muted-foreground">Context Preset</label>
                <select value={newPreset} onChange={(e) => setNewPreset(e.target.value)}
                  className="w-full mt-1 px-3 py-2.5 rounded-lg border border-border/50 bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary/30">
                  {CONTEXT_PRESETS.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                </select>
              </div>
              <div className="col-span-2">
                <label className="text-xs font-medium text-muted-foreground">{newWorkspaceMode === 'standalone_scan' ? 'Scan Objective' : 'Root Attacker Objective'}</label>
                <input value={newObjective} onChange={(e) => setNewObjective(e.target.value)} placeholder={newWorkspaceMode === 'standalone_scan' ? 'e.g., Rapidly assess plausible attack paths against the exposed estate' : 'e.g., Exfiltrate customer data from the SaaS platform'}
                  className="w-full mt-1 px-3 py-2.5 rounded-lg border border-border/50 bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary/30" />
              </div>
              <div className="col-span-2">
                <label className="text-xs font-medium text-muted-foreground">Description</label>
                <textarea value={newDesc} onChange={(e) => setNewDesc(e.target.value)} placeholder="Optional description..." rows={2}
                  className="w-full mt-1 px-3 py-2.5 rounded-lg border border-border/50 bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary/30" />
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-4">
              <button onClick={() => setShowCreate(false)} className="px-4 py-2 text-sm rounded-lg border border-border/50 hover:bg-accent transition-colors">Cancel</button>
              <button
                onClick={() => createMutation.mutate({
                  name: newName || (newWorkspaceMode === 'standalone_scan' ? 'Untitled Scan' : 'Untitled Project'),
                  description: newDesc,
                  root_objective: newObjective,
                  context_preset: newPreset,
                  workspace_mode: newWorkspaceMode,
                })}
                disabled={!newName.trim()}
                className="px-5 py-2 text-sm rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-medium shadow-lg shadow-blue-500/20 hover:shadow-blue-500/30 disabled:opacity-50 transition-all"
              >
                {newWorkspaceMode === 'standalone_scan' ? 'Create Standalone Scan' : 'Create Project Scan'}
              </button>
            </div>
          </div>
        )}

        {/* ——— Template picker ——— */}
        {showTemplates && templates && (
          <div className="border border-border/50 rounded-xl p-5 mb-6 bg-card/80 backdrop-blur-sm shadow-lg">
            <h3 className="font-semibold mb-4 flex items-center gap-2">
              <Sparkles size={16} className="text-amber-500" /> Starter Templates
            </h3>
            <div className="grid grid-cols-2 gap-3">
              {templates.templates.map((t: TemplateInfo) => (
                <button
                  key={t.id}
                  onClick={() => createFromTemplate(t.id)}
                  className="group flex items-start gap-3 p-4 rounded-xl border border-border/50 bg-background/50 hover:bg-accent/50 hover:border-primary/30 text-left transition-all"
                >
                  <div className="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center shrink-0 group-hover:bg-primary/20 transition-colors">
                    <FileText size={16} className="text-primary" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="font-medium text-sm">{t.name}</div>
                    <div className="text-xs text-muted-foreground mt-0.5 line-clamp-2">{t.description}</div>
                    <div className="mt-2 flex flex-wrap gap-1">
                      <span className="inline-flex rounded-full bg-muted px-2 py-0.5 text-[10px] font-medium text-muted-foreground">
                        {t.node_count} nodes
                      </span>
                      <span className="inline-flex rounded-full bg-muted px-2 py-0.5 text-[10px] font-medium text-muted-foreground">
                        {t.context_preset}
                      </span>
                      <span className={cn(
                        'inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium',
                        t.technical_profile === 'standard'
                          ? 'bg-muted text-muted-foreground'
                          : 'bg-primary/10 text-primary'
                      )}>
                        {t.technical_profile === 'standard' ? 'Standard' : 'Deep Technical'}
                      </span>
                    </div>
                    {t.focus_areas.length > 0 && (
                      <div className="text-[10px] text-muted-foreground mt-1.5 line-clamp-2">
                        Focus: {t.focus_areas.slice(0, 2).join(' • ')}
                      </div>
                    )}
                    <div className="text-[10px] text-muted-foreground mt-1">
                      Family: {t.template_family}
                    </div>
                  </div>
                  <ChevronRight size={14} className="text-muted-foreground mt-1 opacity-0 group-hover:opacity-100 transition-opacity" />
                </button>
              ))}
            </div>
          </div>
        )}

        {/* ——— Project list ——— */}
        {isLoading ? (
          <div className="grid gap-3">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="flex items-center gap-4 p-5 rounded-xl border border-border/40 bg-card/50">
                <div className="w-11 h-11 rounded-xl skeleton" />
                <div className="flex-1 space-y-2">
                  <div className="h-4 w-48 skeleton rounded-lg" />
                  <div className="h-3 w-72 skeleton rounded-lg" />
                </div>
              </div>
            ))}
          </div>
        ) : !data?.projects.length ? (
          <div className="text-center py-20">
            <div className="w-20 h-20 rounded-2xl bg-gradient-to-br from-cyan-500/10 to-blue-500/10 flex items-center justify-center mx-auto mb-5">
              <Shield size={36} className="text-primary/60" />
            </div>
            <h2 className="text-lg font-semibold mb-2">No workspaces yet</h2>
              <p className="text-sm text-muted-foreground mb-6 max-w-xs mx-auto">Create a standalone scan or project scan workspace, or start from a template to begin modelling adversary operations.</p>
            <div className="flex justify-center gap-3">
              <button onClick={() => setShowTemplates(true)}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl border border-border/50 hover:bg-accent text-sm font-medium transition-all">
                <Copy size={16} /> Browse Templates
              </button>
              <button onClick={() => setShowCreate(true)}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white text-sm font-semibold shadow-lg shadow-blue-500/25 hover:shadow-blue-500/40 transition-all">
                <Plus size={16} /> Create Workspace
              </button>
            </div>
          </div>
        ) : (
          <div className="grid gap-3">
            {data.projects.map((p: any) => (
              <div
                key={p.id}
                className="group flex items-center gap-4 p-4 rounded-xl border border-border/40 bg-card/60 hover:bg-card hover:border-primary/30 hover:shadow-lg hover:shadow-primary/5 transition-all cursor-pointer"
                onClick={() => openProject(p)}
              >
                <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-primary/20 to-primary/5 flex items-center justify-center shrink-0 group-hover:from-primary/30 group-hover:to-primary/10 transition-colors">
                  <GitBranch size={20} className="text-primary" />
                </div>
                <div className="flex-1 min-w-0">
              <div className="font-semibold text-sm group-hover:text-primary transition-colors">{p.name}</div>
              <div className="text-xs text-muted-foreground truncate mt-0.5">{p.root_objective || p.description || 'No objective set'}</div>
            </div>
            <div className="text-[11px] text-muted-foreground text-right space-y-0.5">
              <div className="flex items-center gap-1.5 justify-end">
                <GitBranch size={10} /> {p.node_count} nodes
              </div>
              <div className="flex items-center justify-end gap-1.5">
                <span className={cn(
                  'text-[10px] px-2 py-0.5 rounded-full inline-block',
                  p.workspace_mode === 'standalone_scan' ? 'bg-amber-500/10 text-amber-400' : 'bg-cyan-500/10 text-cyan-400'
                )}>
                  {p.workspace_mode === 'standalone_scan' ? 'Standalone Scan' : 'Project Scan'}
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-muted/50 inline-block">{p.context_preset}</span>
              </div>
            </div>
                <ChevronRight size={16} className="text-muted-foreground/40 group-hover:text-primary/60 transition-colors" />
                <button
                  onClick={(e) => { e.stopPropagation(); setDeleteProjectId(p.id); }}
                  className="p-1.5 rounded-lg hover:bg-destructive/10 text-muted-foreground/40 hover:text-destructive opacity-0 group-hover:opacity-100 transition-all"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ))}
          </div>
        )}

        {/* Confirm delete project dialog */}
        <ConfirmDialog
          open={!!deleteProjectId}
          onOpenChange={(open) => { if (!open) setDeleteProjectId(null); }}
          onConfirm={() => { if (deleteProjectId) { deleteMutation.mutate(deleteProjectId); setDeleteProjectId(null); } }}
          title="Delete Workspace"
          description={`Are you sure you want to delete "${deleteProjectName}"? All nodes, mitigations, and detections will be permanently removed.`}
          confirmLabel="Delete Workspace"
          destructive
        />
      </div>
    </div>
  );
}

function QuickStat({ icon, label, value, accent }: { icon: React.ReactNode; label: string; value: number | string; accent?: string }) {
  return (
    <div className="flex items-center gap-2">
      <div className={cn(
        'w-7 h-7 rounded-lg flex items-center justify-center',
        accent === 'cyan' ? 'bg-cyan-500/10 text-cyan-500' :
        accent === 'purple' ? 'bg-purple-500/10 text-purple-500' :
        accent === 'emerald' ? 'bg-emerald-500/10 text-emerald-500' :
        'bg-primary/10 text-primary'
      )}>
        {icon}
      </div>
      <div>
        <div className="text-lg font-bold leading-none">{value}</div>
        <div className="text-[10px] text-muted-foreground">{label}</div>
      </div>
    </div>
  );
}
