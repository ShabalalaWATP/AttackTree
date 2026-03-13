import { useState, useEffect } from 'react';
import { useStore, type ViewMode } from '@/stores/useStore';
import { useAuthStore } from '@/stores/useAuthStore';
import { cn } from '@/utils/cn';
import { queryClient } from '@/lib/queryClient';
import { api } from '@/utils/api';
import { KeyboardShortcutsDialog } from '@/components/KeyboardShortcutsDialog';
import { HelpDialog } from '@/components/HelpDialog';
import { ChangePasswordDialog } from '@/components/ChangePasswordDialog';
import { UserManagementDialog } from '@/components/UserManagementDialog';
import toast from 'react-hot-toast';
import ocpLogo from '@/assets/ocp.png';
import {
  FolderOpen, GitBranch, LayoutDashboard, BookOpen, Settings,
  Undo2, Redo2, Save, Download, Upload, Sun, Moon, Keyboard, HelpCircle,
  FlaskConical, Route, ShieldCheck, ChevronRight, Brain, Swords, Network,
  KeyRound, LogOut, Users
} from 'lucide-react';
import { RedTeamAdvisorPanel } from '@/components/RedTeamAdvisorPanel';

const NAV_HOME: { id: ViewMode; label: string; icon: React.ReactNode }[] = [
  { id: 'projects', label: 'Workspaces', icon: <FolderOpen size={15} /> },
];

const NAV_TOOLS: { id: ViewMode; label: string; icon: React.ReactNode }[] = [
  { id: 'tree', label: 'Attack Tree', icon: <GitBranch size={15} /> },
  { id: 'brainstorm', label: 'Brainstorm', icon: <Brain size={15} /> },
  { id: 'scenarios', label: 'Scenarios', icon: <FlaskConical size={15} /> },
  { id: 'kill_chain', label: 'Kill Chain', icon: <Route size={15} /> },
  { id: 'threat_model', label: 'Threat Model', icon: <ShieldCheck size={15} /> },
  { id: 'infra_map', label: 'Infra Map', icon: <Network size={15} /> },
  { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={15} /> },
];

const NAV_UTIL: { id: ViewMode; label: string; icon: React.ReactNode }[] = [
  { id: 'references', label: 'References', icon: <BookOpen size={15} /> },
  { id: 'settings', label: 'Settings', icon: <Settings size={15} /> },
];

export function TopBar() {
  const { viewMode, setViewMode, currentProject, canUndo, canRedo, undo, redo, darkMode, toggleDarkMode, resetWorkspaceState } = useStore();
  const user = useAuthStore((state) => state.user);
  const logout = useAuthStore((state) => state.logout);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [advisorOpen, setAdvisorOpen] = useState(false);
  const [changePasswordOpen, setChangePasswordOpen] = useState(false);
  const [userManagementOpen, setUserManagementOpen] = useState(false);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement)?.closest?.('input,textarea,select')) return;
      if (e.key === '?' || (e.key === '/' && e.shiftKey)) {
        e.preventDefault();
        setShortcutsOpen(true);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  const handleExportJson = async () => {
    if (!currentProject) return;
    try {
      const resp = await api.exportJson(currentProject.id);
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${currentProject.name}.json`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success('Exported JSON');
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const handleExportPdf = async () => {
    if (!currentProject) return;
    try {
      const resp = await api.exportPdf(currentProject.id);
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${currentProject.name}_report.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success('Exported PDF report');
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const handleExportMarkdown = async () => {
    if (!currentProject) return;
    try {
      const resp = await api.exportMarkdown(currentProject.id);
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${currentProject.name}_report.md`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success('Exported Markdown report');
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const handleImport = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = async (e: any) => {
      const file = e.target.files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const data = JSON.parse(text);
        const result = await api.importJson(data);
        toast.success(`Imported: ${result.nodes_imported} nodes`);
        setViewMode('projects');
      } catch (err: any) {
        toast.error(`Import failed: ${err.message}`);
      }
    };
    input.click();
  };

  const handleSnapshot = async () => {
    if (!currentProject) return;
    try {
      await api.createSnapshot({ project_id: currentProject.id, label: `Snapshot ${new Date().toLocaleString()}` });
      toast.success('Snapshot saved');
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const NavButton = ({ item }: { item: { id: ViewMode; label: string; icon: React.ReactNode } }) => (
    <button
      onClick={() => setViewMode(item.id)}
      className={cn(
        'flex items-center gap-2 px-2.5 py-1.5 rounded-md text-[12px] font-medium transition-all duration-150',
        viewMode === item.id
          ? 'bg-gradient-to-r from-primary/20 to-primary/5 text-primary shadow-[inset_0_0_0_1px] shadow-primary/20'
          : 'hover:bg-white/5 text-muted-foreground hover:text-foreground'
      )}
    >
      {item.icon}
      {item.label}
    </button>
  );

  const handleLogout = () => {
    queryClient.clear();
    logout();
    resetWorkspaceState();
  };

  return (
    <>
      <header className="h-13 border-b border-border/50 bg-card/80 backdrop-blur-md flex items-center px-4 gap-2 shrink-0">
        {/* Logo + Brand */}
        <div
          className={cn(
            'mr-3 flex cursor-pointer select-none items-center gap-2.5 rounded-xl px-2.5 py-1.5 transition-colors',
            viewMode === 'landing' ? 'bg-primary/10' : 'hover:bg-white/5'
          )}
          onClick={() => setViewMode('landing')}
        >
          <img src={ocpLogo} alt="OCP" className="w-7 h-7 rounded-md" />
          <div className="flex flex-col leading-none">
            <span className="text-[13px] font-bold tracking-tight bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-500 bg-clip-text text-transparent">
              OCP
            </span>
            <span className="text-[9px] text-muted-foreground font-medium tracking-widest uppercase">
              Offensive Cyber Planner
            </span>
          </div>
        </div>

        <div className="w-px h-6 bg-border/50 mx-1" />

        {/* Home nav */}
        <nav className="flex items-center gap-0.5">
          {NAV_HOME.map((item) => <NavButton key={item.id} item={item} />)}
        </nav>

        <div className="w-px h-4 bg-border/30 mx-0.5" />

        {/* Tools nav group */}
        <nav className="flex items-center gap-0.5">
          {NAV_TOOLS.map((item) => <NavButton key={item.id} item={item} />)}
        </nav>

        <div className="w-px h-4 bg-border/30 mx-0.5" />

        {/* Utility nav */}
        <nav className="flex items-center gap-0.5">
          {NAV_UTIL.map((item) => <NavButton key={item.id} item={item} />)}
        </nav>

        {/* Right side actions */}
        <div className="ml-auto flex items-center gap-0.5">
          {viewMode === 'tree' && currentProject && (
            <>
              <button onClick={undo} disabled={!canUndo} className="topbar-btn" title="Undo (Ctrl+Z)">
                <Undo2 size={14} />
              </button>
              <button onClick={redo} disabled={!canRedo} className="topbar-btn" title="Redo (Ctrl+Y)">
                <Redo2 size={14} />
              </button>
              <div className="w-px h-4 bg-border/40 mx-1" />
              <button onClick={handleSnapshot} className="topbar-btn" title="Save Snapshot">
                <Save size={14} />
              </button>
              <button onClick={handleExportJson} className="topbar-btn" title="Export JSON">
                <Download size={14} />
              </button>
              <button onClick={handleExportPdf} className="topbar-btn text-[10px] font-bold" title="Export PDF Report">
                PDF
              </button>
              <button onClick={handleExportMarkdown} className="topbar-btn text-[10px] font-bold" title="Export Markdown Report">
                MD
              </button>
            </>
          )}
          <button onClick={handleImport} className="topbar-btn" title="Import JSON">
            <Upload size={14} />
          </button>
          <div className="w-px h-4 bg-border/40 mx-1" />
          {currentProject && (
            <button
              onClick={() => setAdvisorOpen(o => !o)}
              className={cn('topbar-btn', advisorOpen && 'text-orange-400')}
              title="Red Team Advisor"
            >
              <Swords size={14} />
            </button>
          )}
          <button onClick={() => setHelpOpen(true)} className="topbar-btn" title="Help & Guide">
            <HelpCircle size={14} />
          </button>
          <button onClick={() => setShortcutsOpen(true)} className="topbar-btn" title="Keyboard shortcuts (?)">
            <Keyboard size={14} />
          </button>
          <button
            onClick={toggleDarkMode}
            className="topbar-btn"
            title={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {darkMode ? <Sun size={14} /> : <Moon size={14} />}
          </button>
          {user?.role === 'admin' && (
            <button onClick={() => setUserManagementOpen(true)} className="topbar-btn" title="User management">
              <Users size={14} />
            </button>
          )}
          <button onClick={() => setChangePasswordOpen(true)} className="topbar-btn" title="Change password">
            <KeyRound size={14} />
          </button>
          <div className="hidden items-center gap-2 rounded-lg border border-border/50 bg-background/40 px-2.5 py-1 text-xs md:flex">
            <div className="min-w-0">
              <div className="truncate font-semibold">{user?.name || 'User'}</div>
              <div className="truncate text-[10px] text-muted-foreground">
                {user?.username ? `@${user.username}` : user?.email || ''}
              </div>
            </div>
            <span className={cn(
              'rounded-full px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-[0.16em]',
              user?.role === 'admin' ? 'bg-cyan-500/10 text-cyan-400' : 'bg-muted text-muted-foreground'
            )}>
              {user?.role || 'user'}
            </span>
            {user?.password_reset_required && (
              <span className="rounded-full bg-amber-500/10 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-[0.16em] text-amber-400">
                Rotate Password
              </span>
            )}
          </div>
          <button onClick={handleLogout} className="topbar-btn" title="Log out">
            <LogOut size={14} />
          </button>
        </div>
      </header>

      <KeyboardShortcutsDialog open={shortcutsOpen} onOpenChange={setShortcutsOpen} />
      <HelpDialog open={helpOpen} onOpenChange={setHelpOpen} />
      <RedTeamAdvisorPanel open={advisorOpen} onClose={() => setAdvisorOpen(false)} />
      <ChangePasswordDialog open={changePasswordOpen} onClose={() => setChangePasswordOpen(false)} />
      <UserManagementDialog open={userManagementOpen} onClose={() => setUserManagementOpen(false)} />
    </>
  );
}
