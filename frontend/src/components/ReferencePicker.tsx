import { useMemo, useState } from 'react';
import type { ReferenceSearchItem } from '@/types';
import { api } from '@/utils/api';
import { Search, Plus } from 'lucide-react';
import toast from 'react-hot-toast';

const FRAMEWORK_LABELS: Record<string, string> = {
  attack: 'ATT&CK',
  capec: 'CAPEC',
  cwe: 'CWE',
  owasp: 'OWASP',
  infra_attack_patterns: 'Infrastructure Patterns',
  software_research_patterns: 'Software Research',
  environment_catalog: 'Environment Catalog',
};

interface ReferencePickerProps {
  artifactType: string;
  contextPreset?: string;
  objective?: string;
  scope?: string;
  targetKind?: string;
  targetSummary?: string;
  allowedFrameworks?: string[];
  limit?: number;
  placeholder?: string;
  onAdd: (item: ReferenceSearchItem) => void;
}

export function ReferencePicker({
  artifactType,
  contextPreset = '',
  objective = '',
  scope = '',
  targetKind = '',
  targetSummary = '',
  allowedFrameworks,
  limit = 10,
  placeholder = 'Search references...',
  onAdd,
}: ReferencePickerProps) {
  const [query, setQuery] = useState('');
  const [frameworkFilter, setFrameworkFilter] = useState('all');
  const [results, setResults] = useState<ReferenceSearchItem[]>([]);
  const [loading, setLoading] = useState(false);

  const frameworkOptions = useMemo(() => {
    const values = allowedFrameworks?.length
      ? allowedFrameworks
      : ['attack', 'capec', 'cwe', 'owasp', 'infra_attack_patterns', 'software_research_patterns', 'environment_catalog'];
    return values;
  }, [allowedFrameworks]);

  const handleSearch = async () => {
    if (!query.trim()) {
      setResults([]);
      return;
    }
    setLoading(true);
    try {
      const response = await api.searchReferences({
        query: query.trim(),
        artifact_type: artifactType,
        context_preset: contextPreset,
        objective,
        scope,
        target_kind: targetKind,
        target_summary: targetSummary,
        allowed_frameworks: frameworkFilter === 'all' ? frameworkOptions : [frameworkFilter],
        limit,
      });
      setResults(response.items as ReferenceSearchItem[]);
    } catch (error: any) {
      setResults([]);
      toast.error(error.message || 'Unable to search references');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-2">
      <div className="flex gap-1">
        <select
          value={frameworkFilter}
          onChange={(e) => {
            setFrameworkFilter(e.target.value);
            setResults([]);
          }}
          className="input-field !w-auto !py-1"
        >
          <option value="all">All</option>
          {frameworkOptions.map((framework) => (
            <option key={framework} value={framework}>
              {FRAMEWORK_LABELS[framework] || framework}
            </option>
          ))}
        </select>
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
          placeholder={placeholder}
          className="input-field !py-1"
        />
        <button
          onClick={handleSearch}
          disabled={loading}
          className="px-2 py-1 text-xs rounded bg-primary text-primary-foreground shrink-0 disabled:opacity-60"
        >
          <Search size={13} />
        </button>
      </div>

      {results.map((item) => (
        <button
          key={`${item.framework}:${item.ref_id}`}
          onClick={() => {
            onAdd(item);
            setResults([]);
            setQuery('');
          }}
          className="w-full text-left rounded border p-2 hover:bg-accent text-xs space-y-1"
        >
          <div className="flex items-center gap-2">
            <span className="font-mono font-bold">{item.ref_id}</span>
            <span className="text-[10px] uppercase text-muted-foreground">{FRAMEWORK_LABELS[item.framework] || item.framework}</span>
            <span className="ml-auto text-primary"><Plus size={12} /></span>
          </div>
          <div>{item.ref_name}</div>
          {item.reasons?.length > 0 && (
            <div className="text-[10px] text-muted-foreground">
              {item.reasons.slice(0, 3).join(', ')}
            </div>
          )}
        </button>
      ))}
    </div>
  );
}
