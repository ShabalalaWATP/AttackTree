import { useStore, type ViewMode } from '@/stores/useStore';
import { cn } from '@/utils/cn';
import {
  GitBranch, Brain, FlaskConical, Route, ShieldCheck, LayoutDashboard,
  X, FolderOpen, Home, Crosshair, Network
} from 'lucide-react';

const PROJECT_TABS: { id: ViewMode; label: string; icon: React.ReactNode }[] = [
  { id: 'project_home', label: 'Home', icon: <Home size={14} /> },
  { id: 'tree', label: 'Attack Tree', icon: <GitBranch size={14} /> },
  { id: 'brainstorm', label: 'Brainstorm', icon: <Brain size={14} /> },
  { id: 'scenarios', label: 'Scenarios', icon: <FlaskConical size={14} /> },
  { id: 'kill_chain', label: 'Kill Chain', icon: <Route size={14} /> },
  { id: 'threat_model', label: 'Threat Model', icon: <ShieldCheck size={14} /> },
  { id: 'infra_map', label: 'Infra Map', icon: <Network size={14} /> },
  { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={14} /> },
];

// Views that belong inside the project workspace
const PROJECT_VIEWS = new Set<ViewMode>(['project_home', 'tree', 'brainstorm', 'scenarios', 'kill_chain', 'threat_model', 'infra_map', 'dashboard']);

export function ProjectToolBar() {
  const { currentProject, setCurrentProject, viewMode, setViewMode, setNodes, setSelectedNodeId } = useStore();

  if (!currentProject) return null;

  // Only show when the active view is a project tool or projects (after just opening)
  const isProjectView = PROJECT_VIEWS.has(viewMode);
  if (!isProjectView) return null;

  const closeProject = () => {
    setCurrentProject(null);
    setNodes([]);
    setSelectedNodeId(null);
    setViewMode('projects');
  };

  return (
    <div className="h-9 border-b border-border/40 bg-card/50 backdrop-blur-sm flex items-center px-4 gap-1 shrink-0">
      {/* Workspace name + close */}
      <div className="flex items-center gap-2 mr-3">
        {currentProject.workspace_mode === 'standalone_scan'
          ? <Crosshair size={13} className="text-amber-400" />
          : <FolderOpen size={13} className="text-primary" />}
        <span className="text-[11px] font-semibold text-primary truncate max-w-[180px]">
          {currentProject.name}
        </span>
        <span className={cn(
          'text-[10px] px-1.5 py-0.5 rounded-full font-medium',
          currentProject.workspace_mode === 'standalone_scan' ? 'bg-amber-500/10 text-amber-400' : 'bg-cyan-500/10 text-cyan-400'
        )}>
          {currentProject.workspace_mode === 'standalone_scan' ? 'Standalone Scan' : 'Project Scan'}
        </span>
        <button
          onClick={closeProject}
          className="p-0.5 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive transition-colors"
          title="Close workspace"
        >
          <X size={12} />
        </button>
      </div>

      <div className="w-px h-4 bg-border/40" />

      {/* Tool tabs */}
      <nav className="flex items-center gap-0.5 ml-1">
        {PROJECT_TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setViewMode(tab.id)}
            className={cn(
              'flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium transition-all duration-150',
              viewMode === tab.id
                ? 'bg-primary/15 text-primary shadow-[inset_0_0_0_1px] shadow-primary/20'
                : 'text-muted-foreground hover:text-foreground hover:bg-white/5'
            )}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </nav>
    </div>
  );
}
