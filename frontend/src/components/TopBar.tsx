import { useState, useEffect } from 'react';
import { useStore, type ViewMode } from '@/stores/useStore';
import { cn } from '@/utils/cn';
import { api } from '@/utils/api';
import { KeyboardShortcutsDialog } from '@/components/KeyboardShortcutsDialog';
import toast from 'react-hot-toast';
import {
  FolderOpen, GitBranch, LayoutDashboard, BookOpen, Settings,
  Undo2, Redo2, Save, Download, Upload, Shield, Sun, Moon, Keyboard
} from 'lucide-react';

const NAV_ITEMS: { id: ViewMode; label: string; icon: React.ReactNode }[] = [
  { id: 'projects', label: 'Projects', icon: <FolderOpen size={16} /> },
  { id: 'tree', label: 'Tree Editor', icon: <GitBranch size={16} /> },
  { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={16} /> },
  { id: 'references', label: 'References', icon: <BookOpen size={16} /> },
  { id: 'settings', label: 'Settings', icon: <Settings size={16} /> },
];

export function TopBar() {
  const { viewMode, setViewMode, currentProject, canUndo, canRedo, undo, redo, darkMode, toggleDarkMode } = useStore();
  const [shortcutsOpen, setShortcutsOpen] = useState(false);

  // Global ? key to show shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // Don't trigger inside inputs/textareas
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

  return (
    <>
      <header className="h-12 border-b bg-card flex items-center px-3 gap-1 shrink-0">
        <div className="flex items-center gap-2 mr-4">
          <Shield size={20} className="text-primary" />
          <span className="font-semibold text-sm">AttackTree Builder</span>
        </div>

        <nav className="flex items-center gap-0.5">
          {NAV_ITEMS.map((item) => (
            <button
              key={item.id}
              onClick={() => setViewMode(item.id)}
              className={cn(
                'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors',
                viewMode === item.id
                  ? 'bg-primary text-primary-foreground'
                  : 'hover:bg-accent text-muted-foreground hover:text-foreground'
              )}
            >
              {item.icon}
              {item.label}
            </button>
          ))}
        </nav>

        {currentProject && (
          <div className="ml-4 text-xs text-muted-foreground truncate max-w-[300px]">
            {currentProject.name}
          </div>
        )}

        <div className="ml-auto flex items-center gap-1">
          {viewMode === 'tree' && currentProject && (
            <>
              <button onClick={undo} disabled={!canUndo} className="p-1.5 rounded hover:bg-accent disabled:opacity-30" title="Undo (Ctrl+Z)">
                <Undo2 size={15} />
              </button>
              <button onClick={redo} disabled={!canRedo} className="p-1.5 rounded hover:bg-accent disabled:opacity-30" title="Redo (Ctrl+Y)">
                <Redo2 size={15} />
              </button>
              <div className="w-px h-5 bg-border mx-1" />
              <button onClick={handleSnapshot} className="p-1.5 rounded hover:bg-accent" title="Save Snapshot">
                <Save size={15} />
              </button>
              <button onClick={handleExportJson} className="p-1.5 rounded hover:bg-accent" title="Export JSON">
                <Download size={15} />
              </button>
              <button onClick={handleExportPdf} className="p-1.5 rounded hover:bg-accent text-xs font-medium" title="Export PDF Report">
                PDF
              </button>
              <button onClick={handleExportMarkdown} className="p-1.5 rounded hover:bg-accent text-xs font-medium" title="Export Markdown Report">
                MD
              </button>
            </>
          )}
          <button onClick={handleImport} className="p-1.5 rounded hover:bg-accent" title="Import JSON">
            <Upload size={15} />
          </button>
          <div className="w-px h-5 bg-border mx-1" />
          <button
            onClick={() => setShortcutsOpen(true)}
            className="p-1.5 rounded hover:bg-accent transition-colors"
            title="Keyboard shortcuts (?)"
          >
            <Keyboard size={15} />
          </button>
          <button
            onClick={toggleDarkMode}
            className="p-1.5 rounded hover:bg-accent transition-colors"
            title={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {darkMode ? <Sun size={15} /> : <Moon size={15} />}
          </button>
        </div>
      </header>

      <KeyboardShortcutsDialog open={shortcutsOpen} onOpenChange={setShortcutsOpen} />
    </>
  );
}
