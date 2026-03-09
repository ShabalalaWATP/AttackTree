import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ReactFlow, Background, Controls, MiniMap, Panel,
  useNodesState, useEdgesState, addEdge,
  type Node, type Edge, type Connection, type NodeTypes,
  BackgroundVariant, MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useStore } from '@/stores/useStore';
import { api } from '@/utils/api';
import { AttackNodeData, NODE_TYPE_CONFIG, type NodeType, type LogicType } from '@/types';
import { NodeInspector } from '@/components/NodeInspector';
import { AISuggestionsPanel } from '@/components/AISuggestionsPanel';
import { AttackTreeNode } from '@/components/AttackTreeNode';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import toast from 'react-hot-toast';
import { cn } from '@/utils/cn';
import { Search, Filter, Plus, Sparkles, ChevronRight, RefreshCw, Tag, X } from 'lucide-react';
import { toPng, toSvg } from 'html-to-image';
import { useQuery } from '@tanstack/react-query';
import type { TagData } from '@/types';

const nodeTypes: NodeTypes = { attackNode: AttackTreeNode };

export function TreeEditorView() {
  const {
    currentProject, nodes: storeNodes, setNodes: setStoreNodes,
    selectedNodeId, setSelectedNodeId, inspectorOpen, setInspectorOpen,
    pushUndo, searchQuery, setSearchQuery, filterNodeType, setFilterNodeType,
    aiSuggestionsOpen, setAiSuggestionsOpen, darkMode,
    filterTags, setFilterTags,
  } = useStore();

  const flowRef = useRef<HTMLDivElement>(null);
  const [pendingDeleteId, setPendingDeleteId] = useState<string | null>(null);
  const pendingDeleteNode = storeNodes.find(n => n.id === pendingDeleteId);

  const { data: allTags = [] } = useQuery({
    queryKey: ['tags'],
    queryFn: api.listTags,
  });

  // Convert store nodes to React Flow nodes and edges, applying all filters
  const { rfNodes, rfEdges } = useMemo(() => {
    let filtered = storeNodes;

    // Search query filter
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter(n =>
        n.title.toLowerCase().includes(q) ||
        n.description?.toLowerCase().includes(q) ||
        n.threat_category?.toLowerCase().includes(q) ||
        n.attack_surface?.toLowerCase().includes(q)
      );
    }

    // Node type filter
    if (filterNodeType) {
      filtered = filtered.filter(n => n.node_type === filterNodeType);
    }

    // Tag filter
    if (filterTags.length > 0) {
      const tagSet = new Set(filterTags);
      filtered = filtered.filter(n =>
        n.tags?.some(t => tagSet.has(t.id))
      );
    }
    const filteredIds = new Set(filtered.map(n => n.id));

    const rfNodes = filtered.map((n) => ({
      id: n.id,
      type: 'attackNode' as const,
      position: { x: n.position_x, y: n.position_y },
      data: n as unknown as Record<string, unknown>,
      selected: n.id === selectedNodeId,
    }));

    const rfEdges: Edge[] = filtered
      .filter((n) => n.parent_id && filteredIds.has(n.parent_id))
      .map((n) => ({
        id: `e-${n.parent_id}-${n.id}`,
        source: n.parent_id!,
        target: n.id,
        type: 'smoothstep',
        animated: false,
        style: { stroke: 'hsl(var(--muted-foreground))', strokeWidth: 1.5 },
        markerEnd: { type: MarkerType.ArrowClosed, width: 12, height: 12, color: 'hsl(var(--muted-foreground))' },
      }));

    return { rfNodes, rfEdges };
  }, [storeNodes, selectedNodeId, filterTags, searchQuery, filterNodeType]);

  const [flowNodes, setFlowNodes, onNodesChange] = useNodesState(rfNodes);
  const [flowEdges, setFlowEdges, onEdgesChange] = useEdgesState(rfEdges);

  useEffect(() => { setFlowNodes(rfNodes); }, [rfNodes, setFlowNodes]);
  useEffect(() => { setFlowEdges(rfEdges); }, [rfEdges, setFlowEdges]);

  const onNodeClick = useCallback((_: any, node: Node) => {
    setSelectedNodeId(node.id);
  }, [setSelectedNodeId]);

  const onPaneClick = useCallback(() => {
    setSelectedNodeId(null);
  }, [setSelectedNodeId]);

  const onNodeDragStop = useCallback(async (_: any, node: Node) => {
    const prevNode = useStore.getState().nodes.find(n => n.id === node.id);
    try {
      await api.updateNode(node.id, { position_x: node.position.x, position_y: node.position.y });
      useStore.getState().updateNodeLocal(node.id, { position_x: node.position.x, position_y: node.position.y });
    } catch (e) {
      // Revert to old position on failure
      if (prevNode) {
        useStore.getState().updateNodeLocal(node.id, { position_x: prevNode.position_x, position_y: prevNode.position_y });
      }
    }
  }, []);

  const onConnect = useCallback(async (connection: Connection) => {
    if (!connection.source || !connection.target) return;
    try {
      pushUndo('Re-parent node');
      await api.updateNode(connection.target, { parent_id: connection.source });
      useStore.getState().updateNodeLocal(connection.target, { parent_id: connection.source });
      toast.success('Node re-parented');
    } catch (e: any) {
      toast.error(e.message);
    }
  }, [pushUndo]);

  const addNode = useCallback(async (parentId: string | null, nodeType: NodeType = 'attack_step') => {
    const project = useStore.getState().currentProject;
    if (!project) return;
    const parent = useStore.getState().nodes.find(n => n.id === parentId);
    try {
      pushUndo('Add node');
      const newNode = await api.createNode({
        project_id: project.id,
        parent_id: parentId,
        node_type: nodeType,
        title: 'New ' + (NODE_TYPE_CONFIG[nodeType]?.label || 'Node'),
        position_x: parent ? parent.position_x + 200 : 400,
        position_y: parent ? parent.position_y + 150 : 0,
      });
      useStore.getState().addNodeLocal(newNode);
      setSelectedNodeId(newNode.id);
    } catch (e: any) {
      toast.error(e.message);
    }
  }, [pushUndo, setSelectedNodeId]);

  const addRootNode = () => addNode(null, 'goal');

  const handleRecalculate = async () => {
    if (!currentProject) return;
    try {
      await api.recalculateRisk(currentProject.id);
      const nodes = await api.listNodes(currentProject.id);
      setStoreNodes(nodes);
      toast.success('Risk scores recalculated');
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const handleExportPng = async () => {
    if (!flowRef.current) return;
    try {
      const viewport = flowRef.current.querySelector('.react-flow__viewport') as HTMLElement;
      if (!viewport) return;
      const isDark = useStore.getState().darkMode;
      const dataUrl = await toPng(viewport, { backgroundColor: isDark ? '#0a1128' : '#ffffff', pixelRatio: 2 });
      const a = document.createElement('a');
      a.href = dataUrl;
      a.download = `${currentProject?.name || 'tree'}.png`;
      a.click();
      toast.success('Exported PNG');
    } catch (e: any) {
      toast.error('PNG export failed');
    }
  };

  const handleExportSvg = async () => {
    if (!flowRef.current) return;
    try {
      const viewport = flowRef.current.querySelector('.react-flow__viewport') as HTMLElement;
      if (!viewport) return;
      const isDark = useStore.getState().darkMode;
      const dataUrl = await toSvg(viewport, { backgroundColor: isDark ? '#0a1128' : '#ffffff' });
      const a = document.createElement('a');
      a.href = dataUrl;
      a.download = `${currentProject?.name || 'tree'}.svg`;
      a.click();
      toast.success('Exported SVG');
    } catch (e: any) {
      toast.error('SVG export failed');
    }
  };

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === 'z') { e.preventDefault(); useStore.getState().undo(); }
      if (e.ctrlKey && e.key === 'y') { e.preventDefault(); useStore.getState().redo(); }
      if (e.key === 'Delete' && selectedNodeId && !(e.target as any)?.closest?.('input,textarea,select')) {
        e.preventDefault();
        setPendingDeleteId(selectedNodeId);
      }
      if (e.key === 'Enter' && e.ctrlKey && selectedNodeId) {
        e.preventDefault();
        addNode(selectedNodeId);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [selectedNodeId, pushUndo, setSelectedNodeId, addNode]);

  const confirmDelete = async () => {
    if (!pendingDeleteId) return;
    try {
      pushUndo('Delete node');
      await api.deleteNode(pendingDeleteId);
      useStore.getState().removeNodeLocal(pendingDeleteId);
      setSelectedNodeId(null);
      toast.success('Node deleted');
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setPendingDeleteId(null);
    }
  };

  if (!currentProject) {
    return (
      <div className="h-full flex items-center justify-center text-muted-foreground">
        <div className="text-center">
          <p className="text-lg mb-2">No project selected</p>
          <button onClick={() => useStore.getState().setViewMode('projects')} className="text-primary text-sm hover:underline">
            Open a project →
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex">
      {/* Main canvas */}
      <div className="flex-1 relative" ref={flowRef}>
        <ReactFlow
          nodes={flowNodes}
          edges={flowEdges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={onNodeClick}
          onPaneClick={onPaneClick}
          onNodeDragStop={onNodeDragStop}
          onConnect={onConnect}
          nodeTypes={nodeTypes}
          fitView
          minZoom={0.1}
          maxZoom={2}
          snapToGrid
          snapGrid={[10, 10]}
          deleteKeyCode={null}
        >
          <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="hsl(var(--border))" />
          <Controls showInteractive={false} />
          <MiniMap
            nodeColor={(n) => {
              const data = n.data as unknown as AttackNodeData;
              return NODE_TYPE_CONFIG[data?.node_type as NodeType]?.color || '#888';
            }}
            maskColor={darkMode ? 'rgba(0,0,0,0.4)' : 'rgba(0,0,0,0.08)'}
            style={{ border: '1px solid hsl(var(--border))' }}
          />

          {/* Top toolbar panel */}
          <Panel position="top-left" className="flex items-center gap-2">
            <div className="flex items-center gap-1 bg-card border rounded-lg p-1 shadow-sm">
              <div className="relative">
                <Search size={14} className="absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground" />
                <input
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search nodes..."
                  className="pl-7 pr-2 py-1 text-xs rounded bg-background border w-40"
                />
              </div>
              <select
                value={filterNodeType}
                onChange={(e) => setFilterNodeType(e.target.value)}
                className="text-xs px-2 py-1 rounded bg-background border"
              >
                <option value="">All types</option>
                {Object.entries(NODE_TYPE_CONFIG).map(([k, v]) => (
                  <option key={k} value={k}>{v.label}</option>
                ))}
              </select>
              {allTags.length > 0 && (
                <select
                  value=""
                  onChange={(e) => {
                    if (e.target.value && !filterTags.includes(e.target.value)) {
                      setFilterTags([...filterTags, e.target.value]);
                    }
                    e.target.value = '';
                  }}
                  className="text-xs px-2 py-1 rounded bg-background border"
                >
                  <option value="">Filter by tag...</option>
                  {allTags.filter((t: TagData) => !filterTags.includes(t.id)).map((t: TagData) => (
                    <option key={t.id} value={t.id}>{t.name}</option>
                  ))}
                </select>
              )}
            </div>
            {filterTags.length > 0 && (
              <div className="flex items-center gap-1 bg-card border rounded-lg p-1 shadow-sm">
                {filterTags.map(tagId => {
                  const tag = allTags.find((t: TagData) => t.id === tagId);
                  return tag ? (
                    <span key={tagId} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-primary/20 text-primary">
                      <Tag size={10} />
                      {tag.name}
                      <button onClick={() => setFilterTags(filterTags.filter(id => id !== tagId))} className="hover:opacity-70">
                        <X size={10} />
                      </button>
                    </span>
                  ) : null;
                })}
                <button onClick={() => setFilterTags([])} className="text-[10px] text-muted-foreground hover:text-foreground px-1">
                  Clear
                </button>
              </div>
            )}
          </Panel>

          {/* Action buttons panel */}
          <Panel position="top-right" className="flex items-center gap-1">
            <div className="flex items-center gap-1 bg-card border rounded-lg p-1 shadow-sm">
              {storeNodes.length === 0 && (
                <button onClick={addRootNode} className="flex items-center gap-1 px-2 py-1 text-xs rounded bg-primary text-primary-foreground hover:opacity-90">
                  <Plus size={13} /> Add Root Goal
                </button>
              )}
              {selectedNodeId && (
                <button onClick={() => addNode(selectedNodeId)} className="flex items-center gap-1 px-2 py-1 text-xs rounded hover:bg-accent">
                  <Plus size={13} /> Add Child
                </button>
              )}
              <button onClick={handleRecalculate} className="flex items-center gap-1 px-2 py-1 text-xs rounded hover:bg-accent" title="Recalculate all risk scores">
                <RefreshCw size={13} /> Recalc
              </button>
              <button onClick={() => setAiSuggestionsOpen(!aiSuggestionsOpen)} className={cn("flex items-center gap-1 px-2 py-1 text-xs rounded", aiSuggestionsOpen ? 'bg-primary text-primary-foreground' : 'hover:bg-accent')}>
                <Sparkles size={13} /> AI Assist
              </button>
              <button onClick={handleExportPng} className="px-2 py-1 text-xs rounded hover:bg-accent">PNG</button>
              <button onClick={handleExportSvg} className="px-2 py-1 text-xs rounded hover:bg-accent">SVG</button>
            </div>
          </Panel>
        </ReactFlow>
      </div>

      {/* AI Suggestions Panel */}
      {aiSuggestionsOpen && (
        <AISuggestionsPanel />
      )}

      {/* Inspector sidebar */}
      {inspectorOpen && selectedNodeId && (
        <NodeInspector />
      )}

      {/* Confirm delete dialog */}
      <ConfirmDialog
        open={!!pendingDeleteId}
        onOpenChange={(open) => { if (!open) setPendingDeleteId(null); }}
        onConfirm={confirmDelete}
        title="Delete Node"
        description={`Are you sure you want to delete "${pendingDeleteNode?.title || 'this node'}"? This action cannot be undone.`}
        confirmLabel="Delete"
        destructive
      />
    </div>
  );
}
