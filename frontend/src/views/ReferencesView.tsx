import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/utils/api';
import { useStore } from '@/stores/useStore';
import { cn } from '@/utils/cn';
import { Search, BookOpen, ChevronDown, ChevronRight, Plus, Check } from 'lucide-react';
import toast from 'react-hot-toast';

const FRAMEWORKS = [
  { id: 'attack', name: 'MITRE ATT&CK', description: 'Adversary tactics, techniques, and procedures' },
  { id: 'capec', name: 'CAPEC', description: 'Common attack pattern enumeration and classification' },
  { id: 'cwe', name: 'CWE', description: 'Common weakness enumeration' },
  { id: 'owasp', name: 'OWASP', description: 'Open Web Application Security Project references' },
];

const FILTER_LABELS: Record<string, string> = {
  tactic: 'Tactic',
  severity: 'Severity',
  category: 'Category',
};

export function ReferencesView() {
  const [selectedFw, setSelectedFw] = useState('attack');
  const [query, setQuery] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [filterValue, setFilterValue] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [addingRefId, setAddingRefId] = useState<string | null>(null);

  const selectedNodeId = useStore((s) => s.selectedNodeId);
  const selectedNode = useStore((s) => s.selectedNode);
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ['references', selectedFw, searchTerm, filterValue],
    queryFn: () => api.browseReferences(selectedFw, searchTerm, filterValue),
  });

  // Fetch counts for sidebar badges
  const { data: attackData } = useQuery({ queryKey: ['references', 'attack', '', ''], queryFn: () => api.browseReferences('attack', '', ''), staleTime: 60_000 });
  const { data: capecData } = useQuery({ queryKey: ['references', 'capec', '', ''], queryFn: () => api.browseReferences('capec', '', ''), staleTime: 60_000 });
  const { data: cweData } = useQuery({ queryKey: ['references', 'cwe', '', ''], queryFn: () => api.browseReferences('cwe', '', ''), staleTime: 60_000 });
  const { data: owaspData } = useQuery({ queryKey: ['references', 'owasp', '', ''], queryFn: () => api.browseReferences('owasp', '', ''), staleTime: 60_000 });
  const badgeCounts: Record<string, number> = {
    attack: attackData?.total ?? 0,
    capec: capecData?.total ?? 0,
    cwe: cweData?.total ?? 0,
    owasp: owaspData?.total ?? 0,
  };

  const doSearch = () => setSearchTerm(query);

  const handleAddToNode = async (item: any) => {
    if (!selectedNodeId) return;
    setAddingRefId(item.id);
    try {
      await api.createMapping({
        node_id: selectedNodeId,
        framework: selectedFw,
        ref_id: item.id,
        ref_name: item.name,
      });
      toast.success(`Mapped ${item.id} to node`);
      queryClient.invalidateQueries({ queryKey: ['mappings'] });
    } catch (e: any) {
      toast.error(e.message || 'Failed to add mapping');
    } finally {
      setAddingRefId(null);
    }
  };

  return (
    <div className="h-full flex">
      {/* Framework selector */}
      <div className="w-64 border-r bg-card p-4 space-y-2 shrink-0">
        <h2 className="font-semibold text-sm mb-3 flex items-center gap-2">
          <BookOpen size={16} /> Reference Browser
        </h2>
        {FRAMEWORKS.map(fw => (
          <button
            key={fw.id}
            onClick={() => { setSelectedFw(fw.id); setSearchTerm(''); setQuery(''); setFilterValue(''); setExpandedId(null); }}
            className={cn(
              'w-full text-left p-3 rounded-lg text-sm transition-colors',
              selectedFw === fw.id ? 'bg-primary text-primary-foreground' : 'hover:bg-accent'
            )}
          >
            <div className="flex items-center justify-between">
              <span className="font-medium">{fw.name}</span>
              {badgeCounts[fw.id] > 0 && (
                <span className={cn(
                  'text-[10px] font-bold rounded-full px-1.5 py-0.5 min-w-[22px] text-center',
                  selectedFw === fw.id ? 'bg-primary-foreground/20 text-primary-foreground' : 'bg-muted text-muted-foreground'
                )}>
                  {badgeCounts[fw.id]}
                </span>
              )}
            </div>
            <div className={cn('text-xs mt-0.5', selectedFw === fw.id ? 'text-primary-foreground/70' : 'text-muted-foreground')}>{fw.description}</div>
          </button>
        ))}

        {/* Node context */}
        <div className="pt-4 border-t mt-4">
          {selectedNodeId ? (
            <div className="p-2 rounded-lg bg-green-500/10 border border-green-500/20">
              <p className="text-[10px] font-medium text-green-600 dark:text-green-400">Selected Node</p>
              <p className="text-xs truncate mt-0.5">{selectedNode?.title || selectedNodeId}</p>
              <p className="text-[10px] text-muted-foreground mt-0.5">Click "Add to Node" on any reference to map it</p>
            </div>
          ) : (
            <p className="text-[10px] text-muted-foreground">
              Select a node in the Tree Editor first to use "Add to Node".
            </p>
          )}
        </div>
      </div>

      {/* Results */}
      <div className="flex-1 overflow-auto p-6">
        <div className="max-w-4xl">
          <div className="flex items-center gap-3 mb-4">
            <h2 className="text-lg font-bold">{FRAMEWORKS.find(f => f.id === selectedFw)?.name}</h2>
            <span className="text-sm text-muted-foreground">
              {data?.count ?? 0}{data && data.count !== data.total ? ` / ${data.total}` : ''} items
            </span>
          </div>

          {/* Search + filter row */}
          <div className="flex gap-2 mb-4">
            <div className="relative flex-1">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && doSearch()}
                placeholder="Search by ID, name, or keyword..."
                className="w-full pl-9 pr-3 py-2 rounded-lg border bg-background text-sm"
              />
            </div>
            {data?.filter_field && data.filter_options.length > 0 && (
              <select
                value={filterValue}
                onChange={(e) => setFilterValue(e.target.value)}
                className="px-3 py-2 rounded-lg border bg-background text-sm min-w-[150px]"
              >
                <option value="">All {FILTER_LABELS[data.filter_field] || data.filter_field}s</option>
                {data.filter_options.map((opt) => (
                  <option key={opt} value={opt}>{opt}</option>
                ))}
              </select>
            )}
            <button onClick={doSearch} className="px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm hover:opacity-90">
              Search
            </button>
          </div>

          {isLoading ? (
            <div className="text-center py-8 text-muted-foreground">Loading...</div>
          ) : (
            <div className="space-y-2">
              {data?.items.map((item: any) => {
                const isExpanded = expandedId === item.id;
                return (
                  <div key={item.id} className={cn('rounded-lg border transition-colors', isExpanded ? 'border-primary/40 bg-primary/5' : 'hover:border-primary/30')}>
                    {/* Header row */}
                    <button
                      onClick={() => setExpandedId(isExpanded ? null : item.id)}
                      className="w-full text-left p-3 flex items-start gap-3"
                    >
                      <span className="mt-0.5 shrink-0 text-muted-foreground">
                        {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                      </span>
                      <span className="font-mono text-xs font-bold text-primary bg-primary/10 px-2 py-0.5 rounded shrink-0">
                        {item.id}
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="font-medium text-sm">{item.name}</div>
                        {!isExpanded && item.description && (
                          <div className="text-xs text-muted-foreground mt-1 line-clamp-1">{item.description}</div>
                        )}
                        <div className="flex gap-3 mt-1 text-[10px] text-muted-foreground">
                          {item.tactic && <span className="bg-muted px-1.5 py-0.5 rounded">Tactic: {item.tactic}</span>}
                          {item.severity && (
                            <span className={cn(
                              'px-1.5 py-0.5 rounded',
                              item.severity === 'Critical' ? 'bg-red-500/10 text-red-600 dark:text-red-400' :
                              item.severity === 'High' ? 'bg-orange-500/10 text-orange-600 dark:text-orange-400' :
                              item.severity === 'Medium' ? 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400' :
                              'bg-muted'
                            )}>
                              {item.severity}
                            </span>
                          )}
                          {item.category && <span className="bg-muted px-1.5 py-0.5 rounded">{item.category}</span>}
                        </div>
                      </div>
                    </button>

                    {/* Expanded detail */}
                    {isExpanded && (
                      <div className="px-3 pb-3 pl-12 space-y-3 border-t mx-3 pt-3">
                        {item.description && (
                          <div>
                            <div className="text-[10px] font-semibold uppercase text-muted-foreground mb-1">Description</div>
                            <div className="text-sm whitespace-pre-wrap">{item.description}</div>
                          </div>
                        )}
                        {/* Show all extra fields */}
                        {Object.entries(item as Record<string, unknown>)
                          .filter(([k]) => !['id', 'name', 'description'].includes(k))
                          .map(([key, value]) => (
                            <div key={key}>
                              <div className="text-[10px] font-semibold uppercase text-muted-foreground mb-0.5">
                                {key.replace(/_/g, ' ')}
                              </div>
                              <div className="text-xs">
                                {Array.isArray(value)
                                  ? (value as string[]).join(', ')
                                  : String(value)}
                              </div>
                            </div>
                          ))
                        }
                        {/* Add to Node button */}
                        {selectedNodeId && (
                          <button
                            onClick={() => handleAddToNode(item)}
                            disabled={addingRefId === item.id}
                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-primary text-primary-foreground text-xs font-medium hover:opacity-90 disabled:opacity-50 mt-2"
                          >
                            {addingRefId === item.id ? (
                              <><Check size={12} /> Adding...</>
                            ) : (
                              <><Plus size={12} /> Add to Node</>
                            )}
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
              {data?.items.length === 0 && (
                <div className="text-center py-8 text-muted-foreground">No results found</div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
