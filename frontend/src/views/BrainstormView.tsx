import { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { useStore } from '@/stores/useStore';
import { api } from '@/utils/api';
import { cn } from '@/utils/cn';
import toast from 'react-hot-toast';
import { Brain, Send, Loader2, Trash2, Sparkles, Copy, Crosshair, Network, ShieldCheck, Route, Target } from 'lucide-react';
import { MarkdownContent } from '@/components/MarkdownContent';

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

type FocusMode = 'broad' | 'attack_surface' | 'technical_research' | 'chain_building' | 'defense_pressure' | 'prioritization';
type TechnicalDepth = 'standard' | 'deep_technical';

interface FocusOption {
  id: FocusMode;
  label: string;
  description: string;
  starter: string;
  placeholder: string;
  icon: React.ReactNode;
}

const FOCUS_OPTIONS: FocusOption[] = [
  {
    id: 'broad',
    label: 'Broad Coverage',
    description: 'Sweep the environment, attacker paths, and planning assumptions before narrowing down.',
    starter: 'Start broad. Map the most important attacker objectives, entry points, pivots, and assumptions we should test first.',
    placeholder: 'Ask for attacker paths, key targets, assumptions, and broad planning coverage...',
    icon: <Brain size={16} className="text-violet-300" />,
  },
  {
    id: 'attack_surface',
    label: 'Attack Surface',
    description: 'Focus on reachable entry points, exposed services, trust boundaries, and initial footholds.',
    starter: 'Focus on attack surface analysis. Identify the most realistic entry points, exposed trust boundaries, and first-hop compromises to investigate.',
    placeholder: 'Ask about exposed interfaces, remote access, cloud edges, suppliers, or reachable services...',
    icon: <Network size={16} className="text-cyan-300" />,
  },
  {
    id: 'technical_research',
    label: 'Technical Research',
    description: 'Drive toward software weaknesses, protocol flaws, exploit primitives, and reverse engineering angles.',
    starter: 'Treat this as a deep technical research session. Prioritize software-specific weaknesses, vulnerability classes, exploit primitives, and reverse engineering leads.',
    placeholder: 'Ask about parser flaws, memory corruption, protocol states, firmware internals, or exploit chains...',
    icon: <Crosshair size={16} className="text-amber-300" />,
  },
  {
    id: 'chain_building',
    label: 'Chain Building',
    description: 'Build realistic multi-step operations from foothold to objective with pivots and prerequisites.',
    starter: 'Build realistic chained operations from initial access to objective completion. Highlight prerequisites, pivots, dependencies, and likely choke points.',
    placeholder: 'Ask to build end-to-end intrusion paths, privilege escalation chains, or collection paths...',
    icon: <Route size={16} className="text-emerald-300" />,
  },
  {
    id: 'defense_pressure',
    label: 'Defense Pressure',
    description: 'Stress detections, mitigations, and defender assumptions to find weak points.',
    starter: 'Pressure-test the defense posture. Identify brittle mitigations, weak detections, bypass ideas, and assumptions defenders are relying on.',
    placeholder: 'Ask how controls fail, where detections are blind, and what an operator would exploit...',
    icon: <ShieldCheck size={16} className="text-blue-300" />,
  },
  {
    id: 'prioritization',
    label: 'Prioritization',
    description: 'Sort the research or operation backlog by leverage, feasibility, and intelligence gaps.',
    starter: 'Prioritize the highest-value investigations. Rank attack hypotheses by feasibility, impact, evidence gaps, and operational leverage.',
    placeholder: 'Ask what to investigate first, which branch has the best payoff, or where uncertainty matters most...',
    icon: <Target size={16} className="text-rose-300" />,
  },
];

function recommendedTechnicalDepth(contextPreset?: string): TechnicalDepth {
  if (['software_reverse_engineering', 'vulnerability_research', 'embedded_firmware_research'].includes(contextPreset || '')) {
    return 'deep_technical';
  }
  return 'standard';
}

function buildTreeContext(nodes: ReturnType<typeof useStore.getState>['nodes']): string {
  if (!nodes.length) return '';
  return [...nodes]
    .sort((a, b) => {
      const riskDelta = (b.inherent_risk || 0) - (a.inherent_risk || 0);
      if (riskDelta !== 0) return riskDelta;
      return (b.likelihood || 0) - (a.likelihood || 0);
    })
    .slice(0, 12)
    .map(node => {
      const parts = [
        `[${node.node_type}] ${node.title}`,
        node.inherent_risk != null ? `risk=${node.inherent_risk.toFixed(1)}` : null,
        node.attack_surface ? `surface=${node.attack_surface}` : null,
        node.platform ? `platform=${node.platform}` : null,
        node.status ? `status=${node.status}` : null,
      ].filter(Boolean);
      return `- ${parts.join(' | ')}`;
    })
    .join('\n');
}

function buildContextPackets(
  currentProject: ReturnType<typeof useStore.getState>['currentProject'],
  nodes: ReturnType<typeof useStore.getState>['nodes'],
): string[] {
  const packets: string[] = [];
  if (currentProject?.context_preset) {
    packets.push(`Environment preset: ${currentProject.context_preset}`);
  }
  if (currentProject?.workspace_mode) {
    packets.push(`Workspace mode: ${currentProject.workspace_mode}`);
  }

  const topSurfaces = Array.from(new Set(nodes.map(node => node.attack_surface).filter(Boolean))).slice(0, 5);
  if (topSurfaces.length) {
    packets.push(`Top attack surfaces: ${topSurfaces.join(', ')}`);
  }

  const topPlatforms = Array.from(new Set(nodes.map(node => node.platform).filter(Boolean))).slice(0, 5);
  if (topPlatforms.length) {
    packets.push(`Platforms in scope: ${topPlatforms.join(', ')}`);
  }

  const topRisks = [...nodes]
    .filter(node => node.inherent_risk != null)
    .sort((a, b) => (b.inherent_risk || 0) - (a.inherent_risk || 0))
    .slice(0, 4)
    .map(node => `${node.title} (${(node.inherent_risk || 0).toFixed(1)})`);
  if (topRisks.length) {
    packets.push(`Highest-risk branches: ${topRisks.join(', ')}`);
  }

  const researchCards = nodes.reduce((count, node) => {
    const cards = node.extended_metadata?.vulnerability_cards;
    return count + (Array.isArray(cards) ? cards.length : 0);
  }, 0);
  if (researchCards > 0) {
    packets.push(`Research evidence available: ${researchCards} vulnerability cards from analyst investigations`);
  }

  return packets;
}

function buildQuickPrompts(
  focus: FocusOption,
  currentProject: ReturnType<typeof useStore.getState>['currentProject'],
  nodes: ReturnType<typeof useStore.getState>['nodes'],
): string[] {
  const prompts = [
    focus.starter,
    'Identify the three most promising branches to investigate next and explain why.',
    'What assumptions in the current plan look weakest or most likely to break under real operations?',
  ];

  if (currentProject?.context_preset && recommendedTechnicalDepth(currentProject.context_preset) === 'deep_technical') {
    prompts.push('Take a deeply technical view. Which implementation details, protocol states, or exploit primitives deserve immediate research attention?');
  }

  if (nodes.some(node => node.detections?.length || node.mitigations?.length)) {
    prompts.push('Where do current detections or mitigations appear fragile, and how would an operator pressure-test those weak points?');
  }

  return prompts.slice(0, 4);
}

export function BrainstormView() {
  const { currentProject, nodes } = useStore();
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [providers, setProviders] = useState<any[]>([]);
  const [providerId, setProviderId] = useState('');
  const [focusMode, setFocusMode] = useState<FocusMode>('broad');
  const [technicalDepth, setTechnicalDepth] = useState<TechnicalDepth>(recommendedTechnicalDepth(currentProject?.context_preset));
  const [includeTreeContext, setIncludeTreeContext] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api.listProviders().then(p => {
      setProviders(p);
      if (p.length) setProviderId(existing => existing || p[0].id);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    setMessages([]);
    setInput('');
    setTechnicalDepth(recommendedTechnicalDepth(currentProject?.context_preset));
  }, [currentProject?.id, currentProject?.context_preset]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' });
  }, [messages, loading]);

  const activeFocus = useMemo(
    () => FOCUS_OPTIONS.find(option => option.id === focusMode) || FOCUS_OPTIONS[0],
    [focusMode],
  );
  const treeContext = useMemo(() => buildTreeContext(nodes), [nodes]);
  const contextPackets = useMemo(() => buildContextPackets(currentProject, nodes), [currentProject, nodes]);
  const quickPrompts = useMemo(() => buildQuickPrompts(activeFocus, currentProject, nodes), [activeFocus, currentProject, nodes]);

  const sendMessage = useCallback(async (userMsg?: string, resetConversation = false) => {
    if (!providerId) {
      toast.error('Configure an LLM provider first');
      return;
    }

    const text = userMsg ?? input.trim();
    const baseMessages = resetConversation ? [] : messages;
    if (!text && baseMessages.length > 0) return;

    const newMessages: Message[] = text
      ? [...baseMessages, { role: 'user', content: text }]
      : baseMessages;

    if (text) {
      setMessages(newMessages);
      setInput('');
    }
    setLoading(true);

    try {
      const res = await api.aiBrainstorm({
        provider_id: providerId,
        project_name: currentProject?.name ?? '',
        root_objective: currentProject?.root_objective ?? '',
        context_preset: currentProject?.context_preset ?? '',
        workspace_mode: currentProject?.workspace_mode ?? '',
        focus_mode: focusMode,
        technical_depth: technicalDepth,
        tree_context: includeTreeContext ? treeContext : '',
        context_packets: contextPackets,
        messages: newMessages,
      });

      if (res.status === 'success') {
        setMessages([...newMessages, { role: 'assistant', content: res.content }]);
      } else {
        toast.error(res.content || 'AI request failed');
      }
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setLoading(false);
    }
  }, [providerId, input, messages, currentProject, focusMode, technicalDepth, includeTreeContext, treeContext, contextPackets]);

  const startSession = useCallback((starter?: string) => {
    setMessages([]);
    setInput('');
    sendMessage(starter || activeFocus.starter, true);
  }, [activeFocus.starter, sendMessage]);

  const copyTranscript = useCallback(async () => {
    if (!messages.length) return;
    const transcript = messages.map(message => `${message.role.toUpperCase()}: ${message.content}`).join('\n\n');
    try {
      await navigator.clipboard.writeText(transcript);
      toast.success('Transcript copied');
    } catch {
      toast.error('Clipboard copy failed');
    }
  }, [messages]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const workspaceLabel = currentProject?.workspace_mode === 'standalone_scan' ? 'standalone scan' : 'project scan';

  return (
    <div className="h-full flex flex-col">
      <div className="shrink-0 border-b border-border/50 bg-card/50 backdrop-blur-sm px-6 py-3">
        <div className="max-w-5xl mx-auto space-y-3">
          <div className="flex items-start justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-violet-500 to-fuchsia-500 flex items-center justify-center">
                <Brain size={18} className="text-white" />
              </div>
              <div>
                <h1 className="text-sm font-bold">Brainstorm</h1>
                <p className="text-[11px] text-muted-foreground">
                  Guided offensive planning with workspace-aware context and adjustable technical depth
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <select
                value={providerId}
                onChange={e => setProviderId(e.target.value)}
                className="text-xs bg-background border border-border rounded-md px-2 py-1.5"
              >
                {providers.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
              <select
                value={focusMode}
                onChange={e => setFocusMode(e.target.value as FocusMode)}
                className="text-xs bg-background border border-border rounded-md px-2 py-1.5"
              >
                {FOCUS_OPTIONS.map(option => (
                  <option key={option.id} value={option.id}>{option.label}</option>
                ))}
              </select>
              <select
                value={technicalDepth}
                onChange={e => setTechnicalDepth(e.target.value as TechnicalDepth)}
                className="text-xs bg-background border border-border rounded-md px-2 py-1.5"
              >
                <option value="standard">Standard Depth</option>
                <option value="deep_technical">Deep Technical</option>
              </select>
              <button
                onClick={() => setIncludeTreeContext(value => !value)}
                className={cn(
                  'text-xs px-2.5 py-1.5 rounded-md border transition-colors',
                  includeTreeContext ? 'border-primary/40 bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-accent',
                )}
                title="Include current attack-tree context"
              >
                Tree Context {includeTreeContext ? 'On' : 'Off'}
              </button>
              {messages.length > 0 && (
                <>
                  <button
                    onClick={copyTranscript}
                    className="p-1.5 rounded-md hover:bg-accent text-muted-foreground hover:text-foreground transition-colors"
                    title="Copy transcript"
                  >
                    <Copy size={14} />
                  </button>
                  <button
                    onClick={() => setMessages([])}
                    className="p-1.5 rounded-md hover:bg-destructive/10 text-muted-foreground hover:text-destructive transition-colors"
                    title="Clear conversation"
                  >
                    <Trash2 size={14} />
                  </button>
                </>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <div className="inline-flex items-center gap-2 rounded-full border border-border/50 bg-background/50 px-3 py-1">
              {activeFocus.icon}
              <span className="text-[11px] font-medium">{activeFocus.label}</span>
            </div>
            <span className="text-[11px] text-muted-foreground">{activeFocus.description}</span>
            {currentProject && (
              <span className="text-[11px] text-muted-foreground">
                Using {workspaceLabel} context from <span className="text-foreground font-medium">{currentProject.name}</span>
              </span>
            )}
          </div>
        </div>
      </div>

      <div ref={scrollRef} className="flex-1 overflow-auto px-6 py-4">
        <div className="max-w-5xl mx-auto space-y-4">
          {messages.length === 0 && !loading && (
            <div className="space-y-6 py-10">
              <div className="flex flex-col items-center justify-center text-center">
                <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-violet-500/20 to-fuchsia-500/20 border border-violet-500/20 flex items-center justify-center mb-4">
                  <Sparkles size={28} className="text-violet-400" />
                </div>
                <h2 className="text-lg font-bold mb-1">Start a Focused Brainstorming Session</h2>
                <p className="text-sm text-muted-foreground max-w-2xl leading-relaxed">
                  The assistant will adapt to the chosen focus mode, technical depth, and current workspace context.
                  {currentProject ? (
                    <> This session is grounded in the <span className="text-foreground font-medium">{workspaceLabel}</span> workspace <span className="text-foreground font-medium">{currentProject.name}</span>.</>
                  ) : (
                    <> Open a workspace for saved context, or use this as a standalone strategy session.</>
                  )}
                </p>
              </div>

              <div className="grid grid-cols-3 gap-3">
                {FOCUS_OPTIONS.map(option => (
                  <button
                    key={option.id}
                    onClick={() => {
                      setFocusMode(option.id);
                      startSession(option.starter);
                    }}
                    disabled={!providerId}
                    className={cn(
                      'rounded-xl border p-4 text-left transition-all',
                      focusMode === option.id ? 'border-primary/40 bg-primary/5' : 'border-border/40 bg-card/60 hover:border-primary/20 hover:bg-white/5',
                    )}
                  >
                    <div className="flex items-center gap-2 mb-2">
                      <div className="w-8 h-8 rounded-lg bg-background/70 flex items-center justify-center">{option.icon}</div>
                      <div className="text-sm font-semibold">{option.label}</div>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">{option.description}</p>
                  </button>
                ))}
              </div>

              <div className="rounded-xl border border-border/40 bg-card/60 p-4 space-y-3">
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <div>
                    <div className="text-sm font-semibold">Session Context</div>
                    <div className="text-xs text-muted-foreground mt-1">
                      {includeTreeContext && nodes.length
                        ? `Using ${Math.min(nodes.length, 12)} prioritised tree branches as context`
                        : 'Tree context is disabled for this session'}
                    </div>
                  </div>
                  <button
                    onClick={() => startSession(activeFocus.starter)}
                    disabled={!providerId}
                    className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white text-sm font-medium hover:opacity-90 transition-opacity disabled:opacity-50"
                  >
                    <Brain size={15} className="inline mr-2 -mt-0.5" />
                    Begin Session
                  </button>
                </div>
                <div className="flex flex-wrap gap-2">
                  {contextPackets.length > 0 ? contextPackets.map(packet => (
                    <span key={packet} className="text-[11px] px-2.5 py-1 rounded-full bg-background/70 border border-border/40">
                      {packet}
                    </span>
                  )) : (
                    <span className="text-xs text-muted-foreground">No workspace-derived packets yet.</span>
                  )}
                </div>
              </div>
            </div>
          )}

          {messages.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {quickPrompts.map(prompt => (
                <button
                  key={prompt}
                  onClick={() => sendMessage(prompt)}
                  disabled={loading}
                  className="text-xs px-3 py-1.5 rounded-full border border-border/40 bg-card/60 hover:bg-white/5 disabled:opacity-50"
                >
                  {prompt}
                </button>
              ))}
            </div>
          )}

          {messages.map((msg, i) => (
            <div key={i} className={cn('flex gap-3', msg.role === 'user' ? 'justify-end' : 'justify-start')}>
              {msg.role === 'assistant' && (
                <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-violet-500 to-fuchsia-500 flex items-center justify-center shrink-0 mt-1">
                  <Brain size={14} className="text-white" />
                </div>
              )}
              <div
                className={cn(
                  'max-w-[82%] rounded-xl px-4 py-3 text-sm leading-relaxed',
                  msg.role === 'user'
                    ? 'bg-primary text-primary-foreground rounded-br-sm'
                    : 'bg-card border border-border rounded-bl-sm'
                )}
              >
                {msg.role === 'assistant' ? (
                  <MarkdownContent content={msg.content} size="sm" />
                ) : (
                  <span>{msg.content}</span>
                )}
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex gap-3">
              <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-violet-500 to-fuchsia-500 flex items-center justify-center shrink-0">
                <Brain size={14} className="text-white" />
              </div>
              <div className="bg-card border border-border rounded-xl rounded-bl-sm px-4 py-3">
                <Loader2 size={16} className="animate-spin text-muted-foreground" />
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="shrink-0 border-t border-border/50 bg-card/50 backdrop-blur-sm px-6 py-3">
        <div className="max-w-5xl mx-auto space-y-2">
          <div className="flex items-center justify-between gap-3 flex-wrap text-[11px] text-muted-foreground">
            <span>{activeFocus.description}</span>
            <span>
              Depth: <span className="text-foreground font-medium">{technicalDepth === 'deep_technical' ? 'Deep Technical' : 'Standard'}</span>
              {includeTreeContext && nodes.length > 0 && <> · {Math.min(nodes.length, 12)} tree nodes in context</>}
            </span>
          </div>
          <div className="flex items-end gap-2">
            <textarea
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={activeFocus.placeholder}
              rows={2}
              className="flex-1 resize-none bg-background border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
            />
            <button
              onClick={() => sendMessage()}
              disabled={loading || !input.trim()}
              className="p-2.5 rounded-lg bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white hover:opacity-90 transition-opacity disabled:opacity-50"
            >
              <Send size={16} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
