import { useEffect, useMemo, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/utils/api';
import { useStore } from '@/stores/useStore';
import { cn } from '@/utils/cn';
import { formatContextPreset } from '@/utils/contextPresets';
import type { EnvironmentCatalogData, EnvironmentCatalogNode } from '@/types';
import {
  BookOpen,
  ChevronDown,
  ChevronRight,
  Check,
  Layers3,
  Network,
  Plus,
  Search,
} from 'lucide-react';
import toast from 'react-hot-toast';

type LibraryId = 'attack' | 'infra_attack_patterns' | 'software_research_patterns' | 'capec' | 'cwe' | 'owasp' | 'environment_catalog';

const LIBRARIES: Array<{ id: LibraryId; name: string; description: string; icon: React.ReactNode }> = [
  { id: 'attack', name: 'MITRE ATT&CK', description: 'Adversary tactics, techniques, and procedures', icon: <BookOpen size={14} /> },
  {
    id: 'infra_attack_patterns',
    name: 'Infrastructure Attack Patterns',
    description: 'Curated cross-domain attack types against management planes, OT, timing, physical systems, remote access, and facility technology',
    icon: <Network size={14} />,
  },
  {
    id: 'software_research_patterns',
    name: 'Software Security Research Patterns',
    description: 'Defensive reverse-engineering, adversarial test-theme, and vulnerability-triage patterns for mapping software attack surfaces, trust boundaries, and hardening priorities',
    icon: <BookOpen size={14} />,
  },
  { id: 'capec', name: 'CAPEC', description: 'Common attack pattern enumeration and classification', icon: <BookOpen size={14} /> },
  { id: 'cwe', name: 'CWE', description: 'Common weakness enumeration', icon: <BookOpen size={14} /> },
  { id: 'owasp', name: 'OWASP', description: 'OWASP Top 10 and adjacent security project references across web, API, mobile, AI, infrastructure, and machine identity risk domains', icon: <BookOpen size={14} /> },
  { id: 'environment_catalog', name: 'Environment Catalog', description: 'Hierarchical planning models for industrial, telecoms, transport, defence, energy, and facility environments', icon: <Layers3 size={14} /> },
];

const FILTER_LABELS: Record<string, string> = {
  tactic: 'Tactic',
  severity: 'Severity',
  category: 'Category',
};

function stringifyCatalogNode(node: EnvironmentCatalogNode): string {
  return [
    node.label,
    node.description,
    node.category,
    ...(node.shared_concepts || []).map((concept) => concept.label),
    ...(node.related_catalogs || []).map((catalog) => catalog.name),
    ...(node.attack_surfaces || []),
    ...(node.telemetry || []),
    ...(node.management_interfaces || []),
    ...(node.dependencies || []),
    ...(node.common_protocols || []),
    ...(node.example_technologies || []),
  ]
    .join(' ')
    .toLowerCase();
}

function joinValue(value?: string[]): string {
  return value?.length ? value.join(', ') : '';
}

function CatalogNodeCard({
  node,
  catalog,
  depth,
  childMap,
  visibleIds,
  expandedIds,
  onToggle,
  onAdd,
  selectedNodeId,
  addingRefId,
}: {
  node: EnvironmentCatalogNode;
  catalog: EnvironmentCatalogData;
  depth: number;
  childMap: Map<string, EnvironmentCatalogNode[]>;
  visibleIds: Set<string> | null;
  expandedIds: Set<string>;
  onToggle: (id: string) => void;
  onAdd: (node: EnvironmentCatalogNode) => void;
  selectedNodeId: string | null;
  addingRefId: string | null;
}) {
  const children = (childMap.get(node.id) || []).filter((child) => !visibleIds || visibleIds.has(child.id));
  const isExpanded = expandedIds.has(node.id);
  const paddingLeft = depth * 18;
  const refId = `${catalog.id}:${node.id}`;

  return (
    <div className="space-y-2">
      <div
        className={cn(
          'rounded-2xl border border-border/40 bg-card/70 p-3 transition-colors',
          depth === 0 && 'border-primary/20 bg-primary/5',
        )}
        style={{ marginLeft: paddingLeft }}
      >
        <div className="flex items-start gap-3">
          <button
            onClick={() => children.length && onToggle(node.id)}
            className={cn(
              'mt-0.5 shrink-0 rounded-md p-1 text-muted-foreground',
              children.length ? 'hover:bg-accent' : 'opacity-30 cursor-default',
            )}
          >
            {children.length ? (isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />) : <Network size={14} />}
          </button>
          <div className="min-w-0 flex-1 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <div className="font-medium text-sm">{node.label}</div>
              <span className="rounded-full bg-muted px-2 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">
                {node.category}
              </span>
              {children.length > 0 && (
                <span className="rounded-full bg-background px-2 py-0.5 text-[10px] text-muted-foreground">
                  {children.length} children
                </span>
              )}
            </div>
            {node.shared_concepts?.length ? (
              <div className="flex flex-wrap gap-1.5">
                {node.shared_concepts.map((concept) => (
                  <span key={concept.id} className="rounded-full border border-primary/20 bg-primary/5 px-2 py-0.5 text-[10px] text-primary">
                    {concept.label}
                  </span>
                ))}
              </div>
            ) : null}
            <p className="text-xs leading-relaxed text-muted-foreground">{node.description}</p>
            <div className="grid gap-2 sm:grid-cols-2">
              {node.common_protocols?.length ? (
                <div>
                  <div className="text-[10px] font-semibold uppercase text-muted-foreground">Protocols</div>
                  <div className="text-xs">{joinValue(node.common_protocols)}</div>
                </div>
              ) : null}
              {node.management_interfaces?.length ? (
                <div>
                  <div className="text-[10px] font-semibold uppercase text-muted-foreground">Management Interfaces</div>
                  <div className="text-xs">{joinValue(node.management_interfaces)}</div>
                </div>
              ) : null}
              {node.attack_surfaces?.length ? (
                <div>
                  <div className="text-[10px] font-semibold uppercase text-muted-foreground">Attack Surfaces</div>
                  <div className="text-xs">{joinValue(node.attack_surfaces)}</div>
                </div>
              ) : null}
              {node.dependencies?.length ? (
                <div>
                  <div className="text-[10px] font-semibold uppercase text-muted-foreground">Dependencies</div>
                  <div className="text-xs">{joinValue(node.dependencies)}</div>
                </div>
              ) : null}
              {node.telemetry?.length ? (
                <div>
                  <div className="text-[10px] font-semibold uppercase text-muted-foreground">Telemetry</div>
                  <div className="text-xs">{joinValue(node.telemetry)}</div>
                </div>
              ) : null}
              {node.example_technologies?.length ? (
                <div>
                  <div className="text-[10px] font-semibold uppercase text-muted-foreground">Example Technologies</div>
                  <div className="text-xs">{joinValue(node.example_technologies)}</div>
                </div>
              ) : null}
            </div>
            {node.related_catalogs?.length ? (
              <div>
                <div className="text-[10px] font-semibold uppercase text-muted-foreground">Also Seen In</div>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {node.related_catalogs.map((catalog) => (
                    <span key={catalog.id} className="rounded-full bg-background px-2 py-0.5 text-[10px] text-muted-foreground">
                      {catalog.name}
                    </span>
                  ))}
                </div>
              </div>
            ) : null}
            {selectedNodeId && (
              <button
                onClick={() => onAdd(node)}
                disabled={addingRefId === refId}
                className="flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50"
              >
                {addingRefId === refId ? (
                  <>
                    <Check size={12} />
                    Adding...
                  </>
                ) : (
                  <>
                    <Plus size={12} />
                    Add to Node
                  </>
                )}
              </button>
            )}
          </div>
        </div>
      </div>
      {children.length > 0 && isExpanded && (
        <div className="space-y-2">
          {children.map((child) => (
            <CatalogNodeCard
              key={child.id}
              node={child}
              catalog={catalog}
              depth={depth + 1}
              childMap={childMap}
              visibleIds={visibleIds}
              expandedIds={expandedIds}
              onToggle={onToggle}
              onAdd={onAdd}
              selectedNodeId={selectedNodeId}
              addingRefId={addingRefId}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export function ReferencesView() {
  const [selectedLibrary, setSelectedLibrary] = useState<LibraryId>('attack');
  const [selectedCatalogId, setSelectedCatalogId] = useState('');
  const [query, setQuery] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [filterValue, setFilterValue] = useState('');
  const [catalogCategory, setCatalogCategory] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [expandedCatalogIds, setExpandedCatalogIds] = useState<Set<string>>(new Set());
  const [addingRefId, setAddingRefId] = useState<string | null>(null);

  const selectedNodeId = useStore((s) => s.selectedNodeId);
  const selectedNode = useStore((s) => s.selectedNode);
  const queryClient = useQueryClient();

  const { data: threatData, isLoading: referencesLoading } = useQuery({
    queryKey: ['references', selectedLibrary, searchTerm, filterValue],
    queryFn: () => api.browseReferences(selectedLibrary, searchTerm, filterValue),
    enabled: selectedLibrary !== 'environment_catalog',
  });

  const { data: attackData } = useQuery({ queryKey: ['references', 'attack', '', ''], queryFn: () => api.browseReferences('attack', '', ''), staleTime: 60_000 });
  const { data: infraAttackPatternsData } = useQuery({
    queryKey: ['references', 'infra_attack_patterns', '', ''],
    queryFn: () => api.browseReferences('infra_attack_patterns', '', ''),
    staleTime: 60_000,
  });
  const { data: softwareResearchPatternsData } = useQuery({
    queryKey: ['references', 'software_research_patterns', '', ''],
    queryFn: () => api.browseReferences('software_research_patterns', '', ''),
    staleTime: 60_000,
  });
  const { data: capecData } = useQuery({ queryKey: ['references', 'capec', '', ''], queryFn: () => api.browseReferences('capec', '', ''), staleTime: 60_000 });
  const { data: cweData } = useQuery({ queryKey: ['references', 'cwe', '', ''], queryFn: () => api.browseReferences('cwe', '', ''), staleTime: 60_000 });
  const { data: owaspData } = useQuery({ queryKey: ['references', 'owasp', '', ''], queryFn: () => api.browseReferences('owasp', '', ''), staleTime: 60_000 });
  const { data: environmentCatalogsData, isLoading: catalogsLoading } = useQuery({
    queryKey: ['environment-catalogs'],
    queryFn: () => api.listEnvironmentCatalogs(),
    staleTime: 60_000,
  });
  const { data: selectedCatalog, isLoading: catalogDetailLoading } = useQuery({
    queryKey: ['environment-catalog', selectedCatalogId],
    queryFn: () => api.getEnvironmentCatalog(selectedCatalogId),
    enabled: selectedLibrary === 'environment_catalog' && !!selectedCatalogId,
  });

  useEffect(() => {
    if (selectedLibrary !== 'environment_catalog') return;
    if (!selectedCatalogId && environmentCatalogsData?.catalogs?.length) {
      setSelectedCatalogId(environmentCatalogsData.catalogs[0].id);
    }
  }, [selectedLibrary, selectedCatalogId, environmentCatalogsData]);

  useEffect(() => {
    if (!selectedCatalog) return;
    const topLevelIds = selectedCatalog.nodes.filter((node) => !node.parent_id).map((node) => node.id);
    setExpandedCatalogIds(new Set(topLevelIds));
  }, [selectedCatalog?.id]);

  const badgeCounts: Record<string, number> = {
    attack: attackData?.total ?? 0,
    infra_attack_patterns: infraAttackPatternsData?.total ?? 0,
    software_research_patterns: softwareResearchPatternsData?.total ?? 0,
    capec: capecData?.total ?? 0,
    cwe: cweData?.total ?? 0,
    owasp: owaspData?.total ?? 0,
    environment_catalog: environmentCatalogsData?.total ?? 0,
  };

  const catalogChildren = useMemo(() => {
    const map = new Map<string, EnvironmentCatalogNode[]>();
    if (!selectedCatalog) return map;
    for (const node of selectedCatalog.nodes) {
      if (!node.parent_id) continue;
      const group = map.get(node.parent_id) || [];
      group.push(node);
      map.set(node.parent_id, group);
    }
    return map;
  }, [selectedCatalog]);

  const visibleCatalogIds = useMemo(() => {
    if (!selectedCatalog) return null;
    const loweredSearch = searchTerm.trim().toLowerCase();
    if (!loweredSearch && !catalogCategory) return null;

    const nodeMap = new Map(selectedCatalog.nodes.map((node) => [node.id, node]));
    const visible = new Set<string>();

    const includeAncestors = (nodeId: string | null) => {
      let currentId = nodeId;
      const seen = new Set<string>();
      while (currentId && !seen.has(currentId)) {
        seen.add(currentId);
        const current = nodeMap.get(currentId);
        if (!current) break;
        visible.add(current.id);
        currentId = current.parent_id;
      }
    };

    const includeDescendants = (nodeId: string) => {
      const stack = [...(catalogChildren.get(nodeId) || [])];
      while (stack.length) {
        const current = stack.pop();
        if (!current || visible.has(current.id)) continue;
        visible.add(current.id);
        stack.push(...(catalogChildren.get(current.id) || []));
      }
    };

    for (const node of selectedCatalog.nodes) {
      const matchesSearch = !loweredSearch || stringifyCatalogNode(node).includes(loweredSearch);
      const matchesCategory = !catalogCategory || node.category === catalogCategory;
      if (!matchesSearch || !matchesCategory) continue;
      visible.add(node.id);
      includeAncestors(node.parent_id);
      includeDescendants(node.id);
    }

    return visible;
  }, [catalogChildren, catalogCategory, searchTerm, selectedCatalog]);

  const selectedCatalogSummary = environmentCatalogsData?.catalogs.find((catalog) => catalog.id === selectedCatalogId) || null;
  const topLevelCatalogNodes = selectedCatalog?.nodes.filter((node) => !node.parent_id && (!visibleCatalogIds || visibleCatalogIds.has(node.id))) || [];

  const doSearch = () => setSearchTerm(query);

  const handleLibraryChange = (libraryId: LibraryId) => {
    setSelectedLibrary(libraryId);
    setSearchTerm('');
    setQuery('');
    setFilterValue('');
    setCatalogCategory('');
    setExpandedId(null);
  };

  const handleAddThreatReferenceToNode = async (item: any) => {
    if (!selectedNodeId) return;
    setAddingRefId(item.id);
    try {
      await api.createMapping({
        node_id: selectedNodeId,
        framework: selectedLibrary,
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

  const handleAddCatalogNodeToNode = async (node: EnvironmentCatalogNode) => {
    if (!selectedNodeId || !selectedCatalog) return;
    const refId = `${selectedCatalog.id}:${node.id}`;
    setAddingRefId(refId);
    try {
      await api.createMapping({
        node_id: selectedNodeId,
        framework: 'environment_catalog',
        ref_id: refId,
        ref_name: `${selectedCatalog.name} / ${node.label}`,
      });
      toast.success(`Mapped ${node.label} to node`);
      queryClient.invalidateQueries({ queryKey: ['mappings'] });
    } catch (e: any) {
      toast.error(e.message || 'Failed to add mapping');
    } finally {
      setAddingRefId(null);
    }
  };

  const toggleCatalogNode = (nodeId: string) => {
    setExpandedCatalogIds((current) => {
      const next = new Set(current);
      if (next.has(nodeId)) next.delete(nodeId);
      else next.add(nodeId);
      return next;
    });
  };

  const isEnvironmentMode = selectedLibrary === 'environment_catalog';

  return (
    <div className="h-full flex">
      <div className="w-72 shrink-0 border-r bg-card p-4 space-y-2">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold">
          <BookOpen size={16} />
          References
        </h2>
        {LIBRARIES.map((library) => (
          <button
            key={library.id}
            onClick={() => handleLibraryChange(library.id)}
            className={cn(
              'w-full rounded-xl p-3 text-left text-sm transition-colors',
              selectedLibrary === library.id ? 'bg-primary text-primary-foreground' : 'hover:bg-accent',
            )}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="flex items-center gap-2 font-medium">
                {library.icon}
                {library.name}
              </span>
              {badgeCounts[library.id] > 0 && (
                <span
                  className={cn(
                    'min-w-[22px] rounded-full px-1.5 py-0.5 text-center text-[10px] font-bold',
                    selectedLibrary === library.id ? 'bg-primary-foreground/20 text-primary-foreground' : 'bg-muted text-muted-foreground',
                  )}
                >
                  {badgeCounts[library.id]}
                </span>
              )}
            </div>
            <div className={cn('mt-1 text-xs', selectedLibrary === library.id ? 'text-primary-foreground/70' : 'text-muted-foreground')}>
              {library.description}
            </div>
          </button>
        ))}

        {isEnvironmentMode && environmentCatalogsData?.catalogs?.length ? (
          <div className="mt-4 border-t pt-4">
            <div className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Environment Types</div>
            <div className="space-y-1">
              {environmentCatalogsData.catalogs.map((catalog) => (
                <button
                  key={catalog.id}
                  onClick={() => setSelectedCatalogId(catalog.id)}
                  className={cn(
                    'w-full rounded-lg border px-3 py-2 text-left text-xs transition-colors',
                    selectedCatalogId === catalog.id ? 'border-primary/40 bg-primary/10 text-foreground' : 'border-border/40 hover:bg-accent',
                  )}
                >
                  <div className="font-medium">{catalog.name}</div>
                  <div className="mt-1 text-[10px] text-muted-foreground">{catalog.sector}</div>
                </button>
              ))}
            </div>
          </div>
        ) : null}

        <div className="mt-4 border-t pt-4">
          {selectedNodeId ? (
            <div className="rounded-lg border border-green-500/20 bg-green-500/10 p-2">
              <p className="text-[10px] font-medium text-green-600 dark:text-green-400">Selected Node</p>
              <p className="mt-0.5 truncate text-xs">{selectedNode?.title || selectedNodeId}</p>
              <p className="mt-0.5 text-[10px] text-muted-foreground">
                {isEnvironmentMode ? 'Map environment nodes or systems into the selected attack-tree node.' : 'Click "Add to Node" on any reference to map it.'}
              </p>
            </div>
          ) : (
            <p className="text-[10px] text-muted-foreground">Select a node in the Tree Editor first to use "Add to Node".</p>
          )}
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="max-w-5xl space-y-4">
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-bold">{LIBRARIES.find((library) => library.id === selectedLibrary)?.name}</h2>
            <span className="text-sm text-muted-foreground">
              {isEnvironmentMode
                ? selectedCatalog
                  ? `${selectedCatalog.node_count} nodes across ${selectedCatalog.top_level_count} top-level domains`
                  : `${environmentCatalogsData?.total ?? 0} catalog types`
                : `${threatData?.count ?? 0}${threatData && threatData.count !== threatData.total ? ` / ${threatData.total}` : ''} items`}
            </span>
          </div>

          <div className="flex flex-wrap gap-2">
            <div className="relative min-w-[260px] flex-1">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                onKeyDown={(event) => event.key === 'Enter' && doSearch()}
                placeholder={
                  isEnvironmentMode
                    ? 'Search environment nodes, protocols, technologies, telemetry, or dependencies...'
                    : 'Search by ID, name, or keyword...'
                }
                className="w-full rounded-lg border bg-background py-2 pl-9 pr-3 text-sm"
              />
            </div>
            {isEnvironmentMode ? (
              selectedCatalog?.categories?.length ? (
                <select
                  value={catalogCategory}
                  onChange={(event) => setCatalogCategory(event.target.value)}
                  className="min-w-[180px] rounded-lg border bg-background px-3 py-2 text-sm"
                >
                  <option value="">All categories</option>
                  {selectedCatalog.categories.map((category) => (
                    <option key={category} value={category}>
                      {category}
                    </option>
                  ))}
                </select>
              ) : null
            ) : threatData?.filter_field && threatData.filter_options.length > 0 ? (
              <select
                value={filterValue}
                onChange={(event) => setFilterValue(event.target.value)}
                className="min-w-[160px] rounded-lg border bg-background px-3 py-2 text-sm"
              >
                <option value="">All {FILTER_LABELS[threatData.filter_field] || threatData.filter_field}s</option>
                {threatData.filter_options.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            ) : null}
            <button onClick={doSearch} className="rounded-lg bg-primary px-4 py-2 text-sm text-primary-foreground hover:opacity-90">
              Search
            </button>
          </div>

          {isEnvironmentMode ? (
            catalogsLoading || catalogDetailLoading ? (
              <div className="py-8 text-center text-muted-foreground">Loading environment catalog...</div>
            ) : selectedCatalog ? (
              <div className="space-y-4">
                <div className="rounded-2xl border border-border/40 bg-card/70 p-4">
                  <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                    <div className="space-y-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="rounded-full bg-primary/10 px-2.5 py-1 text-[11px] font-medium text-primary">{selectedCatalog.name}</span>
                        <span className="rounded-full bg-muted px-2.5 py-1 text-[11px] text-muted-foreground">{selectedCatalog.sector}</span>
                      </div>
                      <p className="max-w-3xl text-sm text-muted-foreground">{selectedCatalog.description}</p>
                      <div className="flex flex-wrap gap-2 text-[11px] text-muted-foreground">
                        {selectedCatalog.context_presets.map((preset) => (
                          <span key={preset} className="rounded-full border border-border/40 bg-background px-2 py-0.5">
                            preset: {formatContextPreset(preset)}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div className="grid grid-cols-3 gap-2 text-center">
                      <div className="rounded-xl border border-border/40 bg-background/70 px-3 py-2">
                        <div className="text-lg font-semibold">{selectedCatalog.top_level_count}</div>
                        <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Domains</div>
                      </div>
                      <div className="rounded-xl border border-border/40 bg-background/70 px-3 py-2">
                        <div className="text-lg font-semibold">{selectedCatalog.node_count}</div>
                        <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Nodes</div>
                      </div>
                      <div className="rounded-xl border border-border/40 bg-background/70 px-3 py-2">
                        <div className="text-lg font-semibold">{selectedCatalog.categories.length}</div>
                        <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Categories</div>
                      </div>
                    </div>
                  </div>
                  <div className="mt-4 flex flex-wrap gap-2">
                    {selectedCatalog.categories.map((category) => (
                      <span key={category} className="rounded-full bg-muted px-2 py-0.5 text-[10px] text-muted-foreground">
                        {category}
                      </span>
                    ))}
                  </div>
                  {selectedCatalog.shared_concepts?.length ? (
                    <div className="mt-3">
                      <div className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Cross-Environment Concepts</div>
                      <div className="flex flex-wrap gap-2">
                        {selectedCatalog.shared_concepts.map((concept) => (
                          <span key={concept.id} className="rounded-full border border-primary/20 bg-primary/5 px-2.5 py-1 text-[11px] text-primary">
                            {concept.label}
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>

                {selectedCatalogSummary ? (
                  <div className="text-xs text-muted-foreground">
                    Showing {visibleCatalogIds ? visibleCatalogIds.size : selectedCatalogSummary.node_count} of {selectedCatalogSummary.node_count} catalog nodes.
                  </div>
                ) : null}

                {topLevelCatalogNodes.length ? (
                  <div className="space-y-3">
                    {topLevelCatalogNodes.map((node) => (
                      <CatalogNodeCard
                        key={node.id}
                        node={node}
                        catalog={selectedCatalog}
                        depth={0}
                        childMap={catalogChildren}
                        visibleIds={visibleCatalogIds}
                        expandedIds={expandedCatalogIds}
                        onToggle={toggleCatalogNode}
                        onAdd={handleAddCatalogNodeToNode}
                        selectedNodeId={selectedNodeId}
                        addingRefId={addingRefId}
                      />
                    ))}
                  </div>
                ) : (
                  <div className="py-8 text-center text-muted-foreground">No catalog nodes match the current filters.</div>
                )}
              </div>
            ) : (
              <div className="py-8 text-center text-muted-foreground">Select an environment catalog to begin browsing.</div>
            )
          ) : referencesLoading ? (
            <div className="py-8 text-center text-muted-foreground">Loading...</div>
          ) : (
            <div className="space-y-2">
              {threatData?.items.map((item: any) => {
                const isExpanded = expandedId === item.id;
                return (
                  <div
                    key={item.id}
                    className={cn(
                      'rounded-lg border transition-colors',
                      isExpanded ? 'border-primary/40 bg-primary/5' : 'hover:border-primary/30',
                    )}
                  >
                    <button onClick={() => setExpandedId(isExpanded ? null : item.id)} className="flex w-full items-start gap-3 p-3 text-left">
                      <span className="mt-0.5 shrink-0 text-muted-foreground">
                        {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                      </span>
                      <span className="shrink-0 rounded bg-primary/10 px-2 py-0.5 font-mono text-xs font-bold text-primary">
                        {item.id}
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-medium">{item.name}</div>
                        {!isExpanded && item.description && (
                          <div className="mt-1 line-clamp-1 text-xs text-muted-foreground">{item.description}</div>
                        )}
                        <div className="mt-1 flex gap-3 text-[10px] text-muted-foreground">
                          {item.tactic && <span className="rounded bg-muted px-1.5 py-0.5">Tactic: {item.tactic}</span>}
                          {item.severity && (
                            <span
                              className={cn(
                                'rounded px-1.5 py-0.5',
                                item.severity === 'Critical'
                                  ? 'bg-red-500/10 text-red-600 dark:text-red-400'
                                  : item.severity === 'High'
                                    ? 'bg-orange-500/10 text-orange-600 dark:text-orange-400'
                                    : item.severity === 'Medium'
                                      ? 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400'
                                      : 'bg-muted',
                              )}
                            >
                              {item.severity}
                            </span>
                          )}
                          {item.category && <span className="rounded bg-muted px-1.5 py-0.5">{item.category}</span>}
                        </div>
                      </div>
                    </button>

                    {isExpanded && (
                      <div className="mx-3 space-y-3 border-t px-3 pb-3 pt-3">
                        {item.description && (
                          <div>
                            <div className="mb-1 text-[10px] font-semibold uppercase text-muted-foreground">Description</div>
                            <div className="whitespace-pre-wrap text-sm">{item.description}</div>
                          </div>
                        )}
                        {Object.entries(item as Record<string, unknown>)
                          .filter(([key]) => !['id', 'name', 'description'].includes(key))
                          .map(([key, value]) => (
                            <div key={key}>
                              <div className="mb-0.5 text-[10px] font-semibold uppercase text-muted-foreground">
                                {key.replace(/_/g, ' ')}
                              </div>
                              <div className="text-xs">{Array.isArray(value) ? value.join(', ') : String(value)}</div>
                            </div>
                          ))}
                        {selectedNodeId && (
                          <button
                            onClick={() => handleAddThreatReferenceToNode(item)}
                            disabled={addingRefId === item.id}
                            className="mt-2 flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50"
                          >
                            {addingRefId === item.id ? (
                              <>
                                <Check size={12} />
                                Adding...
                              </>
                            ) : (
                              <>
                                <Plus size={12} />
                                Add to Node
                              </>
                            )}
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
              {threatData?.items.length === 0 && <div className="py-8 text-center text-muted-foreground">No results found</div>}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
