import { useState, useRef, useEffect, useCallback } from 'react';
import { useStore } from '@/stores/useStore';
import { api } from '@/utils/api';
import { cn } from '@/utils/cn';
import toast from 'react-hot-toast';
import { Brain, Send, Loader2, Trash2, Sparkles } from 'lucide-react';
import { MarkdownContent } from '@/components/MarkdownContent';

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

export function BrainstormView() {
  const { currentProject } = useStore();
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

  const sendMessage = useCallback(async (userMsg?: string) => {
    if (!providerId) { toast.error('Configure an LLM provider first'); return; }
    const text = userMsg ?? input.trim();
    if (!text && messages.length > 0) return;

    const newMessages: Message[] = text
      ? [...messages, { role: 'user', content: text }]
      : messages;

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
  }, [providerId, input, messages, currentProject]);

  const startSession = () => {
    setMessages([]);
    sendMessage('Start the brainstorming session.');
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="shrink-0 border-b border-border/50 bg-card/50 backdrop-blur-sm px-6 py-3">
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-violet-500 to-fuchsia-500 flex items-center justify-center">
              <Brain size={18} className="text-white" />
            </div>
            <div>
              <h1 className="text-sm font-bold">AI Brainstorming Session</h1>
              <p className="text-[11px] text-muted-foreground">Explore attack surfaces through guided dialogue</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <select
              value={providerId}
              onChange={e => setProviderId(e.target.value)}
              className="text-xs bg-background border border-border rounded-md px-2 py-1.5"
            >
              {providers.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
            {messages.length > 0 && (
              <button
                onClick={() => setMessages([])}
                className="p-1.5 rounded-md hover:bg-destructive/10 text-muted-foreground hover:text-destructive transition-colors"
                title="Clear conversation"
              >
                <Trash2 size={14} />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Messages */}
      <div ref={scrollRef} className="flex-1 overflow-auto px-6 py-4">
        <div className="max-w-4xl mx-auto space-y-4">
          {messages.length === 0 && !loading && (
            <div className="flex flex-col items-center justify-center py-20 text-center">
              <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-violet-500/20 to-fuchsia-500/20 border border-violet-500/20 flex items-center justify-center mb-4">
                <Sparkles size={28} className="text-violet-400" />
              </div>
              <h2 className="text-lg font-bold mb-1">Start a Brainstorming Session</h2>
              <p className="text-sm text-muted-foreground mb-6 max-w-md">
                An AI offensive security strategist will guide you through exploring attack surfaces,
                threat actors, and realistic attack paths{currentProject ? (
                  <> for <span className="text-foreground font-medium">{currentProject.name}</span></>
                ) : (
                  <> — open a project first for project-specific context, or start a general session</>
                )}.
              </p>
              <button
                onClick={startSession}
                disabled={!providerId}
                className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-violet-600 to-fuchsia-600 text-white text-sm font-medium hover:opacity-90 transition-opacity disabled:opacity-50"
              >
                <Brain size={15} className="inline mr-2 -mt-0.5" />
                Begin Session
              </button>
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
                  'max-w-[80%] rounded-xl px-4 py-3 text-sm leading-relaxed',
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

      {/* Input */}
      {messages.length > 0 && (
        <div className="shrink-0 border-t border-border/50 bg-card/50 backdrop-blur-sm px-6 py-3">
          <div className="max-w-4xl mx-auto flex items-end gap-2">
            <textarea
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Describe your target, ask about attack vectors, or explore scenarios..."
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
      )}
    </div>
  );
}
