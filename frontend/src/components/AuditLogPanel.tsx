import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/utils/api';
import type { AuditEventData } from '@/types';
import { cn } from '@/utils/cn';
import { Plus, Trash2, Edit3, MessageSquare, Shield, ChevronDown, Eye, BookOpen } from 'lucide-react';

const EVENT_CONFIG: Record<string, { icon: typeof Plus; color: string; label: string }> = {
  node_created: { icon: Plus, color: 'text-green-400', label: 'Node Created' },
  node_updated: { icon: Edit3, color: 'text-blue-400', label: 'Node Updated' },
  node_deleted: { icon: Trash2, color: 'text-red-400', label: 'Node Deleted' },
  comment_added: { icon: MessageSquare, color: 'text-cyan-400', label: 'Comment Added' },
  comment_deleted: { icon: MessageSquare, color: 'text-red-400', label: 'Comment Deleted' },
  mitigation_added: { icon: Shield, color: 'text-emerald-400', label: 'Mitigation Added' },
  mitigation_updated: { icon: Shield, color: 'text-blue-400', label: 'Mitigation Updated' },
  mitigation_removed: { icon: Shield, color: 'text-red-400', label: 'Mitigation Removed' },
  detection_added: { icon: Eye, color: 'text-emerald-400', label: 'Detection Added' },
  detection_updated: { icon: Eye, color: 'text-blue-400', label: 'Detection Updated' },
  detection_removed: { icon: Eye, color: 'text-red-400', label: 'Detection Removed' },
  mapping_added: { icon: BookOpen, color: 'text-emerald-400', label: 'Mapping Added' },
  mapping_updated: { icon: BookOpen, color: 'text-blue-400', label: 'Mapping Updated' },
  mapping_removed: { icon: BookOpen, color: 'text-red-400', label: 'Mapping Removed' },
};

function formatTime(dateStr: string): string {
  try {
    const d = new Date(dateStr);
    const now = new Date();
    const diff = now.getTime() - d.getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    if (days < 7) return `${days}d ago`;
    return d.toLocaleDateString();
  } catch {
    return dateStr;
  }
}

export function AuditLogPanel({ projectId }: { projectId: string }) {
  const [limit, setLimit] = useState(20);

  const { data: events = [], isLoading } = useQuery({
    queryKey: ['audit-events', projectId, limit],
    queryFn: () => api.listAuditEvents(projectId, limit, 0),
    enabled: !!projectId,
  });

  if (isLoading) {
    return (
      <div className="space-y-2">
        {[1, 2, 3, 4, 5].map(i => <div key={i} className="h-10 skeleton rounded" />)}
      </div>
    );
  }

  if (events.length === 0) {
    return (
      <div className="text-sm text-muted-foreground text-center py-6">
        No activity recorded yet. Actions on nodes, comments, and mitigations will appear here.
      </div>
    );
  }

  return (
    <div className="space-y-1">
      {events.map((event: AuditEventData) => {
        const config = EVENT_CONFIG[event.event_type] || { icon: Edit3, color: 'text-muted-foreground', label: event.event_type };
        const Icon = config.icon;
        const detail = event.detail || {};
        const title = (detail as any).title || '';

        return (
          <div key={event.id} className="flex items-start gap-3 py-2 px-2 rounded hover:bg-muted/30 transition-colors">
            <div className={cn('mt-0.5 shrink-0', config.color)}>
              <Icon size={14} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 text-xs">
                <span className="font-medium">{config.label}</span>
                {title && <span className="text-muted-foreground truncate">{title}</span>}
              </div>
              <div className="text-[10px] text-muted-foreground mt-0.5">
                {event.actor} &middot; {formatTime(event.timestamp)}
              </div>
            </div>
          </div>
        );
      })}

      {events.length >= limit && (
        <button
          onClick={() => setLimit(prev => prev + 20)}
          className="w-full flex items-center justify-center gap-1 py-2 text-xs text-primary hover:underline"
        >
          <ChevronDown size={12} /> Load more
        </button>
      )}
    </div>
  );
}
