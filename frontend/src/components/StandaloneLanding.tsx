import { useStore } from '@/stores/useStore';
import { cn } from '@/utils/cn';
import { ArrowRight, FolderOpen } from 'lucide-react';

interface Feature {
  icon: React.ReactNode;
  title: string;
  desc: string;
}

interface Props {
  icon: React.ReactNode;
  title: string;
  description: string;
  features?: Feature[];
}

export function StandaloneLanding({ icon, title, description, features }: Props) {
  const { setViewMode } = useStore();

  return (
    <div className="h-full flex items-center justify-center overflow-auto">
      <div className="max-w-2xl w-full px-6 py-12">
        {/* Tool header */}
        <div className="text-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-primary/15 to-primary/5 border border-primary/20 flex items-center justify-center mx-auto mb-4">
            {icon}
          </div>
          <h2 className="text-xl font-bold mb-2">{title}</h2>
          <p className="text-sm text-muted-foreground max-w-md mx-auto leading-relaxed">{description}</p>
        </div>

        {/* Feature cards */}
        {features && features.length > 0 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-8">
            {features.map((f, i) => (
              <div key={i} className="flex items-start gap-3 p-3 rounded-xl border border-border/50 bg-card/60">
                <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0 mt-0.5">
                  {f.icon}
                </div>
                <div>
                  <div className="text-xs font-semibold">{f.title}</div>
                  <div className="text-[11px] text-muted-foreground mt-0.5">{f.desc}</div>
                </div>
              </div>
            ))}
          </div>
        )}

        <div className="flex justify-center">
          <button
            onClick={() => setViewMode('projects')}
            className="inline-flex items-center gap-2 rounded-xl border border-border/50 bg-card/70 px-4 py-2 text-sm font-medium hover:bg-card transition-colors"
          >
            <FolderOpen size={14} />
            Open Workspaces
            <ArrowRight size={14} className="text-muted-foreground" />
          </button>
        </div>

        <p className="mt-4 text-center text-[11px] text-muted-foreground">
          Create or open a <strong>Standalone Scan</strong> or <strong>Project Scan</strong> workspace from <strong>Workspaces</strong>, then switch tools from the workspace toolbar.
        </p>
      </div>
    </div>
  );
}
