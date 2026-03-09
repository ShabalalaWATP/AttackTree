import { useState, useEffect } from 'react';
import { api } from '@/utils/api';
import { cn } from '@/utils/cn';
import toast from 'react-hot-toast';
import { Scale, Loader2, X, RotateCcw } from 'lucide-react';
import { MarkdownContent } from '@/components/MarkdownContent';
import type { AttackNodeData } from '@/types';

interface Props {
  node: AttackNodeData;
  open: boolean;
  onClose: () => void;
}

export function RiskChallengerPanel({ node, open, onClose }: Props) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [providers, setProviders] = useState<any[]>([]);
  const [providerId, setProviderId] = useState('');

  useEffect(() => {
    api.listProviders().then(p => {
      setProviders(p);
      if (p.length) setProviderId(p[0].id);
    }).catch(() => {});
  }, []);

  // Reset when node changes
  useEffect(() => {
    setResult(null);
  }, [node.id]);

  const runChallenge = async () => {
    if (!providerId) { toast.error('Configure an LLM provider first'); return; }
    setLoading(true);
    setResult(null);

    const mitigationsSummary = node.mitigations?.length
      ? node.mitigations.map(m => `${m.title} (effectiveness: ${m.effectiveness})`).join('; ')
      : 'None';

    try {
      const res = await api.aiChallengeScores({
        provider_id: providerId,
        node_title: node.title,
        node_description: node.description || '',
        node_type: node.node_type,
        likelihood: node.likelihood ?? undefined,
        impact: node.impact ?? undefined,
        effort: node.effort ?? undefined,
        exploitability: node.exploitability ?? undefined,
        detectability: node.detectability ?? undefined,
        inherent_risk: node.inherent_risk ?? undefined,
        mitigations_summary: mitigationsSummary,
      });

      if (res.status === 'success') {
        setResult(res.content);
      } else {
        toast.error(res.content || 'Challenge request failed');
      }
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setLoading(false);
    }
  };

  if (!open) return null;

  const scores = [
    { label: 'Likelihood', value: node.likelihood, color: 'text-blue-400' },
    { label: 'Impact', value: node.impact, color: 'text-red-400' },
    { label: 'Effort', value: node.effort, color: 'text-amber-400' },
    { label: 'Exploitability', value: node.exploitability, color: 'text-orange-400' },
    { label: 'Detectability', value: node.detectability, color: 'text-green-400' },
  ];

  return (
    <div className="fixed inset-y-0 right-0 w-[460px] z-50 flex flex-col bg-card border-l border-border shadow-2xl">
      {/* Header */}
      <div className="shrink-0 flex items-center justify-between px-4 py-3 border-b border-border/50">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-amber-500 to-red-500 flex items-center justify-center">
            <Scale size={16} className="text-white" />
          </div>
          <div>
            <h2 className="text-sm font-bold">Risk Score Challenger</h2>
            <p className="text-[10px] text-muted-foreground truncate max-w-[200px]">{node.title}</p>
          </div>
        </div>
        <button onClick={onClose} className="p-1 rounded hover:bg-muted text-muted-foreground">
          <X size={15} />
        </button>
      </div>

      {/* Current scores */}
      <div className="shrink-0 px-4 py-3 border-b border-border/30 bg-muted/30">
        <div className="text-[11px] font-medium text-muted-foreground mb-2">Current Scores</div>
        <div className="grid grid-cols-5 gap-2">
          {scores.map(s => (
            <div key={s.label} className="text-center">
              <div className={cn('text-lg font-bold', s.color)}>{s.value ?? '—'}</div>
              <div className="text-[9px] text-muted-foreground">{s.label}</div>
            </div>
          ))}
        </div>
        {node.inherent_risk != null && (
          <div className="mt-2 text-center">
            <span className="text-[10px] text-muted-foreground">Inherent Risk: </span>
            <span className="text-sm font-bold">{node.inherent_risk.toFixed(1)}</span>
          </div>
        )}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto px-4 py-3">
        {!result && !loading && (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <Scale size={32} className="text-muted-foreground/40 mb-3" />
            <p className="text-xs text-muted-foreground mb-4 max-w-[280px]">
              The AI will critically examine your risk scores, identify potential biases,
              and suggest adjustments with evidence-based reasoning.
            </p>
            <div className="flex items-center gap-2 mb-4">
              <select
                value={providerId}
                onChange={e => setProviderId(e.target.value)}
                className="text-xs bg-background border border-border rounded-md px-2 py-1.5"
              >
                {providers.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </div>
            <button
              onClick={runChallenge}
              disabled={!providerId || scores.every(s => s.value == null)}
              className="px-4 py-2 rounded-lg bg-gradient-to-r from-amber-500 to-red-500 text-white text-sm font-medium hover:opacity-90 disabled:opacity-50"
            >
              <Scale size={14} className="inline mr-1.5 -mt-0.5" />
              Challenge My Scores
            </button>
            {scores.every(s => s.value == null) && (
              <p className="text-[10px] text-muted-foreground mt-2">Assign scores first to enable challenges</p>
            )}
          </div>
        )}

        {loading && (
          <div className="flex flex-col items-center justify-center py-16">
            <Loader2 size={24} className="animate-spin text-amber-500 mb-3" />
            <p className="text-xs text-muted-foreground">Analyzing your risk scores...</p>
          </div>
        )}

        {result && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-muted-foreground">AI Analysis</span>
              <button
                onClick={runChallenge}
                disabled={loading}
                className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground"
              >
                <RotateCcw size={12} /> Re-challenge
              </button>
            </div>
            <MarkdownContent content={result} size="xs" />
          </div>
        )}
      </div>
    </div>
  );
}
