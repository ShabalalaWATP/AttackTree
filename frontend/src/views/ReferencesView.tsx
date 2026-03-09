import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/utils/api';
import { cn } from '@/utils/cn';
import { Search, BookOpen } from 'lucide-react';

const FRAMEWORKS = [
  { id: 'attack', name: 'MITRE ATT&CK', description: 'Adversary tactics, techniques, and procedures' },
  { id: 'capec', name: 'CAPEC', description: 'Common attack pattern enumeration and classification' },
  { id: 'cwe', name: 'CWE', description: 'Common weakness enumeration' },
  { id: 'owasp', name: 'OWASP', description: 'Open Web Application Security Project references' },
];

export function ReferencesView() {
  const [selectedFw, setSelectedFw] = useState('attack');
  const [query, setQuery] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  const { data, isLoading } = useQuery({
    queryKey: ['references', selectedFw, searchTerm],
    queryFn: () => api.browseReferences(selectedFw, searchTerm),
  });

  const doSearch = () => setSearchTerm(query);

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
            onClick={() => { setSelectedFw(fw.id); setSearchTerm(''); setQuery(''); }}
            className={cn(
              'w-full text-left p-3 rounded-lg text-sm transition-colors',
              selectedFw === fw.id ? 'bg-primary text-primary-foreground' : 'hover:bg-accent'
            )}
          >
            <div className="font-medium">{fw.name}</div>
            <div className={cn('text-xs mt-0.5', selectedFw === fw.id ? 'text-primary-foreground/70' : 'text-muted-foreground')}>{fw.description}</div>
          </button>
        ))}
        <div className="pt-4 border-t mt-4">
          <p className="text-[10px] text-muted-foreground">
            Reference data is bundled locally for offline use. Updates can be imported via reference pack files.
          </p>
        </div>
      </div>

      {/* Results */}
      <div className="flex-1 overflow-auto p-6">
        <div className="max-w-4xl">
          <div className="flex items-center gap-3 mb-4">
            <h2 className="text-lg font-bold">{FRAMEWORKS.find(f => f.id === selectedFw)?.name}</h2>
            <span className="text-sm text-muted-foreground">{data?.count || 0} items</span>
          </div>

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
            <button onClick={doSearch} className="px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm hover:opacity-90">
              Search
            </button>
          </div>

          {isLoading ? (
            <div className="text-center py-8 text-muted-foreground">Loading...</div>
          ) : (
            <div className="space-y-2">
              {data?.items.map((item: any, i: number) => (
                <div key={i} className="p-3 rounded-lg border hover:border-primary/30 transition-colors">
                  <div className="flex items-start gap-3">
                    <span className="font-mono text-xs font-bold text-primary bg-primary/10 px-2 py-0.5 rounded shrink-0">
                      {item.id}
                    </span>
                    <div className="min-w-0">
                      <div className="font-medium text-sm">{item.name}</div>
                      {item.description && (
                        <div className="text-xs text-muted-foreground mt-1 line-clamp-2">{item.description}</div>
                      )}
                      <div className="flex gap-3 mt-1 text-[10px] text-muted-foreground">
                        {item.tactic && <span>Tactic: {item.tactic}</span>}
                        {item.severity && <span>Severity: {item.severity}</span>}
                        {item.category && <span>Category: {item.category}</span>}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
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
