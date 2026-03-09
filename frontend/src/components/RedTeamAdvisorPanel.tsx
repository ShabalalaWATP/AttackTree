import { useState, useEffect, useRef } from 'react';
import { api } from '@/utils/api';
import { useStore } from '@/stores/useStore';
import { cn } from '@/utils/cn';
import toast from 'react-hot-toast';
import { Swords, Send, Loader2, X, Trash2 } from 'lucide-react';
import { MarkdownContent } from '@/components/MarkdownContent';

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

interface Props {
  open: boolean;
  onClose: () => void;
}

export function RedTeamAdvisorPanel({ open, onClose }: Props) {
  const { currentProject, nodes } = useStore();
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [providers, setProviders] = useState<any[]>([]);
  const [providerId, setProviderId] = useState('');
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api.listProviders().then(p => {
      setProviders(p);
      if (p.length) setProviderId(p[0].id);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' });
  }, [messages, loading]);

  const buildTreeContext = () => {
    return nodes.slice(0, 30).map(n =>
      `[${n.node_type}] ${n.title} (risk:${n.inherent_risk ?? '?'}, status:${n.status})`
    ).join('\n');
  };

  const askAdvisor = async () => {
    if (!input.trim() || !providerId) return;
    const question = input.trim();
    setMessages(prev => [...prev, { role: 'user', content: question }]);
    setInput('');
    setLoading(true);

    try {
      const res = await api.aiAdvisor({
        provider_id: providerId,
        question,
        project_name: currentProject?.name ?? '',
        root_objective: currentProject?.root_objective ?? '',
        tree_context: buildTreeContext(),
      });

      if (res.status === 'success') {
        setMessages(prev => [...prev, { role: 'assistant', content: res.content }]);
      } else {
        toast.error(res.content || 'Advisor request failed');
      }
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      askAdvisor();
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-y-0 right-0 w-[420px] z-50 flex flex-col bg-card border-l border-border shadow-2xl">
      {/* Header */}
      <div className="shrink-0 flex items-center justify-between px-4 py-3 border-b border-border/50">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-red-500 to-orange-500 flex items-center justify-center">
            <Swords size={16} className="text-white" />
          </div>
          <div>
            <h2 className="text-sm font-bold">Red Team Advisor</h2>
            <p className="text-[10px] text-muted-foreground">Tactical offensive guidance</p>
          </div>
        </div>
        <div className="flex items-center gap-1">
          <select
            value={providerId}
            onChange={e => setProviderId(e.target.value)}
            className="text-[11px] bg-background border border-border rounded px-1.5 py-1 max-w-[120px]"
          >
            {providers.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          {messages.length > 0 && (
            <button onClick={() => setMessages([])} className="p-1 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive">
              <Trash2 size={13} />
            </button>
          )}
          <button onClick={onClose} className="p-1 rounded hover:bg-muted text-muted-foreground">
            <X size={15} />
          </button>
        </div>
      </div>

      {/* Messages */}
      <div ref={scrollRef} className="flex-1 overflow-auto px-4 py-3 space-y-3">
        {messages.length === 0 && (
          <div className="text-center py-10">
            <Swords size={28} className="mx-auto text-muted-foreground/50 mb-3" />
            <p className="text-xs text-muted-foreground mb-2">Ask the Red Team Advisor about:</p>
            <div className="space-y-1.5 text-[11px]">
              {[
                'How would you pivot from initial access to domain admin?',
                'What detection gaps exist for lateral movement?',
                'Suggest OPSEC-safe persistence mechanisms',
                'What ATT&CK techniques apply to cloud environments?',
              ].map(q => (
                <button
                  key={q}
                  onClick={() => { setInput(q); }}
                  className="block w-full text-left px-3 py-2 rounded-lg border border-border/50 hover:border-primary/30 hover:bg-primary/5 text-muted-foreground hover:text-foreground transition-colors"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} className={cn('flex gap-2', msg.role === 'user' ? 'justify-end' : 'justify-start')}>
            {msg.role === 'assistant' && (
              <div className="w-6 h-6 rounded-md bg-gradient-to-br from-red-500 to-orange-500 flex items-center justify-center shrink-0 mt-0.5">
                <Swords size={12} className="text-white" />
              </div>
            )}
            <div
              className={cn(
                'max-w-[85%] rounded-lg px-3 py-2 text-xs leading-relaxed',
                msg.role === 'user'
                  ? 'bg-primary text-primary-foreground rounded-br-sm'
                  : 'bg-muted/50 border border-border/50 rounded-bl-sm'
              )}
            >
              {msg.role === 'assistant' ? (
                <MarkdownContent content={msg.content} size="xs" />
              ) : (
                <span>{msg.content}</span>
              )}
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex gap-2">
            <div className="w-6 h-6 rounded-md bg-gradient-to-br from-red-500 to-orange-500 flex items-center justify-center shrink-0">
              <Swords size={12} className="text-white" />
            </div>
            <div className="bg-muted/50 border border-border/50 rounded-lg rounded-bl-sm px-3 py-2">
              <Loader2 size={14} className="animate-spin text-muted-foreground" />
            </div>
          </div>
        )}
      </div>

      {/* Input */}
      <div className="shrink-0 border-t border-border/50 px-4 py-3">
        <div className="flex items-end gap-2">
          <textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about TTPs, tradecraft, tools..."
            rows={2}
            className="flex-1 resize-none bg-background border border-border rounded-lg px-3 py-2 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
          />
          <button
            onClick={askAdvisor}
            disabled={loading || !input.trim()}
            className="p-2 rounded-lg bg-gradient-to-r from-red-500 to-orange-500 text-white hover:opacity-90 disabled:opacity-50"
          >
            <Send size={14} />
          </button>
        </div>
      </div>
    </div>
  );
}
