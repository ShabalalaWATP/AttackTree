import { ArrowRight, FolderOpen, GitBranch, Route, ShieldCheck } from 'lucide-react';

import ocpLogo from '@/assets/ocp.png';
import { useStore } from '@/stores/useStore';

const CAPABILITIES = [
  {
    icon: <GitBranch size={16} className="text-cyan-400" />,
    title: 'Attack Trees',
    description: 'Model adversary objectives, branches, controls, and evidence in one structured workspace.',
  },
  {
    icon: <Route size={16} className="text-sky-400" />,
    title: 'Scenario Planning',
    description: 'Run scenarios, kill chains, and operational what-if analysis against the same workspace.',
  },
  {
    icon: <ShieldCheck size={16} className="text-emerald-400" />,
    title: 'Threat Analysis',
    description: 'Link threat models, infrastructure maps, and reference mappings without leaving the app.',
  },
];

export function LandingView() {
  const setViewMode = useStore((state) => state.setViewMode);

  return (
    <div className="relative h-full overflow-auto bg-[radial-gradient(circle_at_top_left,_rgba(34,211,238,0.14),_transparent_30%),radial-gradient(circle_at_bottom_right,_rgba(59,130,246,0.16),_transparent_28%),linear-gradient(155deg,_hsl(var(--background)),_hsl(var(--card)))]">
      <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(148,163,184,0.08)_1px,transparent_1px),linear-gradient(to_bottom,rgba(148,163,184,0.08)_1px,transparent_1px)] bg-[size:72px_72px] opacity-20" />
      <div className="absolute inset-x-[8%] top-12 h-40 rounded-full bg-cyan-500/10 blur-3xl" />
      <div className="absolute bottom-8 right-[12%] h-44 w-44 rounded-full bg-blue-500/10 blur-3xl" />

      <div className="relative mx-auto flex min-h-full max-w-6xl items-center px-6 py-10">
        <div className="grid w-full items-center gap-8 lg:grid-cols-[1.05fr_0.95fr]">
          <section className="max-w-2xl">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.2em] text-cyan-400">
              Offensive Planning Workspace
            </div>
            <h1 className="mt-5 text-5xl font-black tracking-tight text-foreground sm:text-6xl">
              Offensive Cyber Planner
            </h1>
            <p className="mt-5 max-w-xl text-base leading-7 text-muted-foreground">
              OCP brings attack trees, scenario planning, kill-chain analysis, threat models, and infrastructure mapping
              into one workspace for authorised offensive security planning.
            </p>

            <div className="mt-8 flex flex-wrap items-center gap-3">
              <button
                onClick={() => setViewMode('projects')}
                className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-5 py-3 text-sm font-semibold text-white shadow-lg shadow-blue-500/25 transition-all hover:-translate-y-0.5 hover:shadow-blue-500/35"
              >
                <FolderOpen size={16} />
                Workspaces
                <ArrowRight size={15} />
              </button>
            </div>

            <p className="mt-4 text-sm text-muted-foreground">
              Open Workspaces when you want to create a new project scan, launch a standalone scan, or continue an
              existing assessment.
            </p>

            <div className="mt-8 grid gap-3 sm:grid-cols-3">
              {CAPABILITIES.map((capability) => (
                <div
                  key={capability.title}
                  className="rounded-2xl border border-border/50 bg-card/65 p-4 shadow-lg shadow-black/5 backdrop-blur"
                >
                  <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-xl border border-white/10 bg-background/70">
                    {capability.icon}
                  </div>
                  <h2 className="text-sm font-semibold">{capability.title}</h2>
                  <p className="mt-2 text-xs leading-5 text-muted-foreground">{capability.description}</p>
                </div>
              ))}
            </div>
          </section>

          <section className="relative overflow-hidden rounded-[32px] border border-border/50 bg-card/75 p-8 shadow-2xl shadow-black/10 backdrop-blur">
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,_rgba(34,211,238,0.16),_transparent_55%)]" />
            <div className="absolute inset-x-12 bottom-6 h-20 rounded-full bg-cyan-400/15 blur-3xl" />
            <div className="relative flex flex-col items-center text-center">
              <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-border/50 bg-background/50 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                OCP
              </div>
              <img
                src={ocpLogo}
                alt="Offensive Cyber Planner logo"
                className="animate-landing-logo-bob w-full max-w-[17rem] drop-shadow-[0_20px_48px_rgba(34,211,238,0.22)]"
              />
              <p className="mt-6 max-w-sm text-sm leading-6 text-muted-foreground">
                Keep attack planning artefacts aligned instead of scattering them across separate notes, diagrams, and
                point-in-time exports.
              </p>

              <div className="mt-8 grid w-full gap-3 text-left">
                <LandingSignal
                  title="Shared workspace context"
                  description="One place for objectives, nodes, references, and analysis runs."
                />
                <LandingSignal
                  title="Built for iterative assessments"
                  description="Move from quick scans into deeper modelling without changing tools."
                />
                <LandingSignal
                  title="Purpose-built for OCP"
                  description="Workspaces stay available when you need to pick up an assessment again."
                />
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function LandingSignal({ title, description }: { title: string; description: string }) {
  return (
    <div className="rounded-2xl border border-border/40 bg-background/55 px-4 py-3">
      <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
        <span className="inline-flex h-2 w-2 rounded-full bg-cyan-400" />
        {title}
      </div>
      <p className="mt-1 text-xs leading-5 text-muted-foreground">{description}</p>
    </div>
  );
}
