import { useState } from 'react';
import { useStore } from '@/stores/useStore';
import { api } from '@/utils/api';
import { NODE_TYPE_CONFIG, type NodeType } from '@/types';
import toast from 'react-hot-toast';
import { Sparkles, Check, X, Loader2, Brain, FileText, Shield, MapPin } from 'lucide-react';
import { cn } from '@/utils/cn';

export function AISuggestionsPanel() {
  const { selectedNodeId, nodes, currentProject, setAiSuggestionsOpen, pushUndo, addNodeLocal } = useStore();
  const selectedNode = nodes.find(n => n.id === selectedNodeId);
  const [suggestions, setSuggestions] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [summaryText, setSummaryText] = useState('');
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [promptUsed, setPromptUsed] = useState('');
  const [suggestionType, setSuggestionType] = useState('branches');

  const handleSuggest = async () => {
    if (!selectedNodeId || !currentProject) {
      toast.error('Select a node first');
      return;
    }
    setLoading(true);
    setSuggestions([]);
    try {
      const result = await api.suggestBranches({
        node_id: selectedNodeId,
        project_id: currentProject.id,
        suggestion_type: suggestionType,
      });
      setSuggestions(result.suggestions);
      setPromptUsed(result.prompt_used || '');
      if (!result.suggestions.length) {
        toast('No suggestions returned. Check LLM configuration.', { icon: '⚠️' });
      }
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setLoading(false);
    }
  };

  const acceptSuggestion = async (suggestion: any) => {
    if (!selectedNodeId || !currentProject) return;
    try {
      pushUndo('Accept AI suggestion');
      const parent = nodes.find(n => n.id === selectedNodeId);
      const newNode = await api.createNode({
        project_id: currentProject.id,
        parent_id: selectedNodeId,
        node_type: suggestion.node_type || 'attack_step',
        title: suggestion.title,
        description: suggestion.description || '',
        logic_type: suggestion.logic_type || 'OR',
        threat_category: suggestion.threat_category || '',
        likelihood: suggestion.likelihood,
        impact: suggestion.impact,
        position_x: (parent?.position_x || 0) + Math.random() * 300 - 150,
        position_y: (parent?.position_y || 0) + 180,
      });
      addNodeLocal(newNode);
      setSuggestions(prev => prev.filter(s => s !== suggestion));
      toast.success(`Added: ${suggestion.title}`);
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const handleSummary = async (type: 'technical' | 'executive') => {
    if (!currentProject) return;
    setSummaryLoading(true);
    setSummaryText('');
    try {
      const result = await api.generateSummary({
        project_id: currentProject.id,
        summary_type: type,
      });
      setSummaryText(result.summary);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setSummaryLoading(false);
    }
  };

  return (
    <div className="w-[340px] border-l bg-card flex flex-col h-full shrink-0">
      <div className="flex items-center justify-between px-4 py-3 border-b">
        <div className="flex items-center gap-2">
          <Sparkles size={16} className="text-primary" />
          <span className="font-semibold text-sm">AI Assistant</span>
        </div>
        <button onClick={() => setAiSuggestionsOpen(false)} className="p-1 rounded hover:bg-accent">
          <X size={14} />
        </button>
      </div>

      <div className="flex-1 overflow-auto p-4 space-y-4">
        {/* Branch suggestions */}
        <div className="space-y-2">
          <h3 className="text-xs font-semibold uppercase text-muted-foreground">Node Suggestions</h3>
          <p className="text-xs text-muted-foreground">
            {selectedNode ? `Selected: ${selectedNode.title}` : 'Select a node on the canvas first'}
          </p>

          <div className="flex gap-1 flex-wrap">
            {[
              { id: 'branches', label: 'Branches', icon: <Brain size={12} /> },
              { id: 'mitigations', label: 'Mitigations', icon: <Shield size={12} /> },
              { id: 'detections', label: 'Detections', icon: <MapPin size={12} /> },
              { id: 'mappings', label: 'Mappings', icon: <FileText size={12} /> },
            ].map(st => (
              <button
                key={st.id}
                onClick={() => setSuggestionType(st.id)}
                className={cn('flex items-center gap-1 px-2 py-1 text-xs rounded', suggestionType === st.id ? 'bg-primary text-primary-foreground' : 'border hover:bg-accent')}
              >
                {st.icon} {st.label}
              </button>
            ))}
          </div>

          <button
            onClick={handleSuggest}
            disabled={!selectedNodeId || loading}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 text-xs rounded-lg bg-primary text-primary-foreground hover:opacity-90 disabled:opacity-50"
          >
            {loading ? <Loader2 size={14} className="animate-spin" /> : <Sparkles size={14} />}
            {loading ? 'Generating...' : `Suggest ${suggestionType}`}
          </button>

          {promptUsed && (
            <details className="text-[10px] text-muted-foreground">
              <summary className="cursor-pointer hover:text-foreground">View prompt context</summary>
              <pre className="mt-1 p-2 bg-muted rounded text-[10px] whitespace-pre-wrap max-h-32 overflow-auto">{promptUsed}</pre>
            </details>
          )}
        </div>

        {/* Suggestions list */}
        {suggestions.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-xs font-medium">Suggestions — review before accepting</h4>
            <div className="space-y-2 p-2 rounded-lg border warning-box">
              <div className="text-[10px] font-medium">⚠️ AI-generated — review carefully</div>
              {suggestions.map((s, i) => (
                <div key={i} className="p-2 rounded border bg-card text-xs space-y-1">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1">
                      <span className="text-[10px] text-muted-foreground">{NODE_TYPE_CONFIG[s.node_type as NodeType]?.icon || '⚔️'} {s.node_type}</span>
                      <div className="font-semibold">{s.title}</div>
                      {s.description && <div className="text-muted-foreground">{s.description}</div>}
                      {(s.likelihood || s.impact) && (
                        <div className="flex gap-2 mt-1 text-[10px]">
                          {s.likelihood && <span>L: {s.likelihood}</span>}
                          {s.impact && <span>I: {s.impact}</span>}
                        </div>
                      )}
                    </div>
                    <div className="flex gap-0.5 shrink-0">
                      <button onClick={() => acceptSuggestion(s)} className="p-1 rounded hover:bg-accent text-success" title="Accept">
                        <Check size={14} />
                      </button>
                      <button onClick={() => setSuggestions(prev => prev.filter((_, j) => j !== i))} className="p-1 rounded hover:bg-accent text-destructive" title="Reject">
                        <X size={14} />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Summary generation */}
        <div className="border-t pt-4 space-y-2">
          <h3 className="text-xs font-semibold uppercase text-muted-foreground">Report Drafts</h3>
          <div className="flex gap-1">
            <button onClick={() => handleSummary('technical')} disabled={summaryLoading} className="flex-1 px-2 py-1.5 text-xs rounded border hover:bg-accent disabled:opacity-50">
              Technical Summary
            </button>
            <button onClick={() => handleSummary('executive')} disabled={summaryLoading} className="flex-1 px-2 py-1.5 text-xs rounded border hover:bg-accent disabled:opacity-50">
              Executive Summary
            </button>
          </div>
          {summaryLoading && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Loader2 size={14} className="animate-spin" /> Generating...
            </div>
          )}
          {summaryText && (
            <div className="p-3 rounded-lg border warning-box space-y-2">
              <div className="text-[10px] font-medium">⚠️ AI-generated draft — review and edit before use</div>
              <div className="text-xs whitespace-pre-wrap">{summaryText}</div>
              <button
                onClick={() => { navigator.clipboard.writeText(summaryText); toast.success('Copied to clipboard'); }}
                className="text-xs text-primary hover:underline"
              >
                Copy to clipboard
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
