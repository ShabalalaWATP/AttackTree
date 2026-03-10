import { lazy, Suspense, useEffect } from 'react';
import { Toaster } from 'react-hot-toast';
import { useStore } from '@/stores/useStore';
import { useAuthStore } from '@/stores/useAuthStore';
import { ProjectsView } from '@/views/ProjectsView';
import { AuthView } from '@/views/AuthView';
import { TreeEditorView } from '@/views/TreeEditorView';
import { ProjectHomeView } from '@/views/ProjectHomeView';
import { DashboardView } from '@/views/DashboardView';
import { ReferencesView } from '@/views/ReferencesView';
import { SettingsView } from '@/views/SettingsView';
import { TopBar } from '@/components/TopBar';
import { ProjectToolBar } from '@/components/ProjectToolBar';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import { queryClient } from '@/lib/queryClient';

const ScenarioSimulationView = lazy(() => import('@/views/ScenarioSimulationView').then(m => ({ default: m.ScenarioSimulationView })));
const KillChainView = lazy(() => import('@/views/KillChainView').then(m => ({ default: m.KillChainView })));
const ThreatModelView = lazy(() => import('@/views/ThreatModelView').then(m => ({ default: m.ThreatModelView })));
const BrainstormView = lazy(() => import('@/views/BrainstormView').then(m => ({ default: m.BrainstormView })));
const InfraMapView = lazy(() => import('@/views/InfraMapView'));

export default function App() {
  const viewMode = useStore((s) => s.viewMode);
  const resetWorkspaceState = useStore((s) => s.resetWorkspaceState);
  const { token, user, initializing, restoreSession, logout } = useAuthStore();

  useEffect(() => {
    restoreSession();
  }, [restoreSession]);

  useEffect(() => {
    const handler = () => {
      queryClient.clear();
      logout();
      resetWorkspaceState();
    };
    window.addEventListener('atb-auth-expired', handler);
    return () => window.removeEventListener('atb-auth-expired', handler);
  }, [logout, resetWorkspaceState]);

  if (initializing) {
    return (
      <div className="flex h-screen items-center justify-center bg-background text-sm text-muted-foreground">
        Restoring session...
      </div>
    );
  }

  if (!token || !user) {
    return (
      <ErrorBoundary>
        <AuthView />
        <Toaster position="bottom-right" toastOptions={{
          style: { background: 'hsl(var(--card))', color: 'hsl(var(--card-foreground))', border: '1px solid hsl(var(--border))' },
        }} />
      </ErrorBoundary>
    );
  }

  return (
    <ErrorBoundary>
      <div className="h-screen flex flex-col bg-background text-foreground">
        <TopBar />
        <ProjectToolBar />
        <main className="flex-1 overflow-hidden">
          <ErrorBoundary>
            {viewMode === 'projects' && <ProjectsView />}
            {viewMode === 'project_home' && <ProjectHomeView />}
            {viewMode === 'tree' && <TreeEditorView />}
            {viewMode === 'dashboard' && <DashboardView />}
            {viewMode === 'references' && <ReferencesView />}
            {viewMode === 'settings' && <SettingsView />}
            <Suspense fallback={<div className="h-full flex items-center justify-center text-muted-foreground text-sm">Loading…</div>}>
              {viewMode === 'scenarios' && <ScenarioSimulationView />}
              {viewMode === 'kill_chain' && <KillChainView />}
              {viewMode === 'threat_model' && <ThreatModelView />}
              {viewMode === 'brainstorm' && <BrainstormView />}
              {viewMode === 'infra_map' && <InfraMapView />}
            </Suspense>
          </ErrorBoundary>
        </main>
        <Toaster position="bottom-right" toastOptions={{
          style: { background: 'hsl(var(--card))', color: 'hsl(var(--card-foreground))', border: '1px solid hsl(var(--border))' },
        }} />
      </div>
    </ErrorBoundary>
  );
}
