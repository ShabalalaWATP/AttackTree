import { Toaster } from 'react-hot-toast';
import { useStore } from '@/stores/useStore';
import { ProjectsView } from '@/views/ProjectsView';
import { TreeEditorView } from '@/views/TreeEditorView';
import { DashboardView } from '@/views/DashboardView';
import { ReferencesView } from '@/views/ReferencesView';
import { SettingsView } from '@/views/SettingsView';
import { TopBar } from '@/components/TopBar';
import { ErrorBoundary } from '@/components/ErrorBoundary';

export default function App() {
  const viewMode = useStore((s) => s.viewMode);

  return (
    <ErrorBoundary>
      <div className="h-screen flex flex-col bg-background text-foreground">
        <TopBar />
        <main className="flex-1 overflow-hidden">
          <ErrorBoundary>
            {viewMode === 'projects' && <ProjectsView />}
            {viewMode === 'tree' && <TreeEditorView />}
            {viewMode === 'dashboard' && <DashboardView />}
            {viewMode === 'references' && <ReferencesView />}
            {viewMode === 'settings' && <SettingsView />}
          </ErrorBoundary>
        </main>
        <Toaster position="bottom-right" toastOptions={{
          style: { background: 'hsl(var(--card))', color: 'hsl(var(--card-foreground))', border: '1px solid hsl(var(--border))' },
        }} />
      </div>
    </ErrorBoundary>
  );
}
