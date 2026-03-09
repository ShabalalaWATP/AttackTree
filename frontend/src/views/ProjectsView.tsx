import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/utils/api';
import { useStore } from '@/stores/useStore';
import { CONTEXT_PRESETS } from '@/types';
import toast from 'react-hot-toast';
import { Plus, Trash2, FolderOpen, Copy, FileText, GitBranch } from 'lucide-react';
import { cn } from '@/utils/cn';
import { ConfirmDialog } from '@/components/ConfirmDialog';

export function ProjectsView() {
  const queryClient = useQueryClient();
  const { setCurrentProject, setViewMode, setNodes } = useStore();
  const [showCreate, setShowCreate] = useState(false);
  const [showTemplates, setShowTemplates] = useState(false);
  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newObjective, setNewObjective] = useState('');
  const [newPreset, setNewPreset] = useState('general');
  const [deleteProjectId, setDeleteProjectId] = useState<string | null>(null);

  const { data, isLoading } = useQuery({ queryKey: ['projects'], queryFn: api.listProjects });
  const deleteProjectName = deleteProjectId
    ? (data?.projects?.find((p: any) => p.id === deleteProjectId)?.name || 'this project')
    : '';
  const { data: templates } = useQuery({ queryKey: ['templates'], queryFn: api.listTemplates });

  const createMutation = useMutation({
    mutationFn: api.createProject,
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['projects'] }); setShowCreate(false); toast.success('Project created'); },
  });

  const deleteMutation = useMutation({
    mutationFn: api.deleteProject,
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['projects'] }); toast.success('Project deleted'); },
  });

  const openProject = async (project: any) => {
    setCurrentProject(project);
    const nodes = await api.listNodes(project.id);
    setNodes(nodes);
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
        },
        nodes: template.nodes,
      });
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      toast.success(`Created from template: ${template.name}`);
      setShowTemplates(false);
      // Open the new project
      const project = await api.getProject(result.project_id);
      openProject(project);
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  return (
    <div className="h-full overflow-auto p-6">
      <div className="max-w-5xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold">Attack Tree Projects</h1>
            <p className="text-sm text-muted-foreground mt-1">Create, manage, and analyse cyber attack trees</p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => setShowTemplates(!showTemplates)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg border hover:bg-accent text-sm"
            >
              <Copy size={16} /> From Template
            </button>
            <button
              onClick={() => setShowCreate(!showCreate)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm hover:opacity-90"
            >
              <Plus size={16} /> New Project
            </button>
          </div>
        </div>

        {/* Create form */}
        {showCreate && (
          <div className="border rounded-lg p-4 mb-6 bg-card">
            <h3 className="font-semibold mb-3">Create New Project</h3>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-medium text-muted-foreground">Project Name</label>
                <input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="e.g., Q1 Web App Risk Assessment" className="w-full mt-1 px-3 py-2 rounded-md border bg-background text-sm" />
              </div>
              <div>
                <label className="text-xs font-medium text-muted-foreground">Context Preset</label>
                <select value={newPreset} onChange={(e) => setNewPreset(e.target.value)} className="w-full mt-1 px-3 py-2 rounded-md border bg-background text-sm">
                  {CONTEXT_PRESETS.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                </select>
              </div>
              <div className="col-span-2">
                <label className="text-xs font-medium text-muted-foreground">Root Attacker Objective</label>
                <input value={newObjective} onChange={(e) => setNewObjective(e.target.value)} placeholder="e.g., Exfiltrate customer data from the SaaS platform" className="w-full mt-1 px-3 py-2 rounded-md border bg-background text-sm" />
              </div>
              <div className="col-span-2">
                <label className="text-xs font-medium text-muted-foreground">Description</label>
                <textarea value={newDesc} onChange={(e) => setNewDesc(e.target.value)} placeholder="Optional description..." rows={2} className="w-full mt-1 px-3 py-2 rounded-md border bg-background text-sm" />
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-3">
              <button onClick={() => setShowCreate(false)} className="px-3 py-1.5 text-sm rounded-md border hover:bg-accent">Cancel</button>
              <button
                onClick={() => createMutation.mutate({ name: newName || 'Untitled', description: newDesc, root_objective: newObjective, context_preset: newPreset })}
                disabled={!newName.trim()}
                className="px-4 py-1.5 text-sm rounded-md bg-primary text-primary-foreground hover:opacity-90 disabled:opacity-50"
              >
                Create
              </button>
            </div>
          </div>
        )}

        {/* Template picker */}
        {showTemplates && templates && (
          <div className="border rounded-lg p-4 mb-6 bg-card">
            <h3 className="font-semibold mb-3">Starter Templates</h3>
            <div className="grid grid-cols-2 gap-2">
              {templates.templates.map((t: any) => (
                <button
                  key={t.id}
                  onClick={() => createFromTemplate(t.id)}
                  className="flex items-start gap-3 p-3 rounded-lg border hover:bg-accent text-left transition-colors"
                >
                  <FileText size={18} className="text-primary mt-0.5 shrink-0" />
                  <div>
                    <div className="font-medium text-sm">{t.name}</div>
                    <div className="text-xs text-muted-foreground mt-0.5">{t.description}</div>
                    <div className="text-xs text-muted-foreground mt-1">{t.node_count} nodes · {t.context_preset}</div>
                  </div>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Project list */}
        {isLoading ? (
          <div className="grid gap-3">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="flex items-center gap-4 p-4 rounded-lg border bg-card">
                <div className="w-10 h-10 rounded-lg skeleton" />
                <div className="flex-1 space-y-2">
                  <div className="h-4 w-48 skeleton" />
                  <div className="h-3 w-72 skeleton" />
                </div>
                <div className="space-y-1.5 text-right">
                  <div className="h-3 w-16 skeleton ml-auto" />
                  <div className="h-3 w-12 skeleton ml-auto" />
                </div>
              </div>
            ))}
          </div>
        ) : !data?.projects.length ? (
          <div className="text-center py-20">
            <div className="text-5xl mb-4">&#128737;&#65039;</div>
            <h2 className="text-lg font-semibold mb-2">No projects yet</h2>
            <p className="text-sm text-muted-foreground mb-4">Create a new attack tree project or start from a template.</p>
            <div className="flex justify-center gap-3">
              <button
                onClick={() => setShowTemplates(true)}
                className="flex items-center gap-2 px-4 py-2 rounded-lg border hover:bg-accent text-sm"
              >
                <Copy size={16} /> Browse Templates
              </button>
              <button
                onClick={() => setShowCreate(true)}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm hover:opacity-90"
              >
                <Plus size={16} /> Create Project
              </button>
            </div>
          </div>
        ) : (
          <div className="grid gap-3">
            {data.projects.map((p: any) => (
              <div
                key={p.id}
                className="flex items-center gap-4 p-4 rounded-lg border bg-card hover:border-primary/40 transition-colors cursor-pointer group"
                onClick={() => openProject(p)}
              >
                <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                  <GitBranch size={20} className="text-primary" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="font-semibold text-sm">{p.name}</div>
                  <div className="text-xs text-muted-foreground truncate">{p.root_objective || p.description || 'No objective set'}</div>
                </div>
                <div className="text-xs text-muted-foreground text-right">
                  <div>{p.node_count} nodes</div>
                  <div>{p.context_preset}</div>
                </div>
                <div className="flex gap-1 opacity-0 group-hover:opacity-100">
                  <button
                    onClick={(e) => { e.stopPropagation(); setDeleteProjectId(p.id); }}
                    className="p-1.5 rounded hover:bg-destructive/10 text-destructive"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Confirm delete project dialog */}
        <ConfirmDialog
          open={!!deleteProjectId}
          onOpenChange={(open) => { if (!open) setDeleteProjectId(null); }}
          onConfirm={() => { if (deleteProjectId) { deleteMutation.mutate(deleteProjectId); setDeleteProjectId(null); } }}
          title="Delete Project"
          description={`Are you sure you want to delete "${deleteProjectName}"? All nodes, mitigations, and detections will be permanently removed.`}
          confirmLabel="Delete Project"
          destructive
        />
      </div>
    </div>
  );
}
