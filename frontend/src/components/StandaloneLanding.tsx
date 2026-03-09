import { cn } from '@/utils/cn';

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

        {/* Hint */}
        <p className="text-center text-[11px] text-muted-foreground">
          Open a project from <strong>Projects</strong> to use this tool with project-specific data, or use the in-project toolbar to switch tools.
        </p>
      </div>
    </div>
  );
}
