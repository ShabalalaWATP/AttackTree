import { create } from 'zustand';
import type { AttackNodeData, ProjectData } from '@/types';

export type ViewMode = 'projects' | 'project_home' | 'tree' | 'dashboard' | 'references' | 'settings' | 'scenarios' | 'kill_chain' | 'threat_model' | 'brainstorm';

interface UndoEntry {
  nodes: AttackNodeData[];
  label: string;
}

interface AppState {
  // Theme
  darkMode: boolean;
  toggleDarkMode: () => void;

  // Navigation
  viewMode: ViewMode;
  setViewMode: (mode: ViewMode) => void;

  // Project
  currentProject: ProjectData | null;
  setCurrentProject: (project: ProjectData | null) => void;

  // Nodes
  nodes: AttackNodeData[];
  setNodes: (nodes: AttackNodeData[]) => void;
  updateNodeLocal: (id: string, updates: Partial<AttackNodeData>) => void;
  addNodeLocal: (node: AttackNodeData) => void;
  removeNodeLocal: (id: string) => void;

  // Selection
  selectedNodeId: string | null;
  setSelectedNodeId: (id: string | null) => void;
  selectedNode: AttackNodeData | null;
  selectedNodeIds: Set<string>;
  toggleNodeSelection: (id: string) => void;
  clearMultiSelect: () => void;

  // Inspector
  inspectorOpen: boolean;
  setInspectorOpen: (open: boolean) => void;

  // Search / Filter
  searchQuery: string;
  setSearchQuery: (q: string) => void;
  filterNodeType: string;
  setFilterNodeType: (t: string) => void;
  filterStatus: string;
  setFilterStatus: (s: string) => void;
  filterTags: string[];
  setFilterTags: (tags: string[]) => void;

  // Undo/Redo
  undoStack: UndoEntry[];
  redoStack: UndoEntry[];
  pushUndo: (label: string) => void;
  undo: () => void;
  redo: () => void;
  canUndo: boolean;
  canRedo: boolean;

  // AI Suggestions panel
  aiSuggestionsOpen: boolean;
  setAiSuggestionsOpen: (open: boolean) => void;
  aiSuggestions: any[];
  setAiSuggestions: (suggestions: any[]) => void;
}

function getInitialDarkMode(): boolean {
  try {
    const stored = localStorage.getItem('atb-dark-mode');
    if (stored !== null) return stored !== 'false';
  } catch {}
  return true; // default dark
}

export const useStore = create<AppState>((set, get) => ({
  darkMode: getInitialDarkMode(),
  toggleDarkMode: () => {
    const next = !get().darkMode;
    set({ darkMode: next });
    try { localStorage.setItem('atb-dark-mode', String(next)); } catch {}
    if (next) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  },

  viewMode: 'projects',
  setViewMode: (mode) => set({ viewMode: mode }),

  currentProject: null,
  setCurrentProject: (project) => set({ currentProject: project }),

  nodes: [],
  setNodes: (nodes) => set((state) => ({
    nodes,
    selectedNode: state.selectedNodeId ? nodes.find(n => n.id === state.selectedNodeId) || null : null,
  })),
  updateNodeLocal: (id, updates) => set((state) => {
    const newNodes = state.nodes.map((n) => n.id === id ? { ...n, ...updates } : n);
    return {
      nodes: newNodes,
      // Keep selectedNode in sync when the selected node is updated
      selectedNode: state.selectedNodeId === id
        ? { ...(state.nodes.find(n => n.id === id) || {}), ...updates } as AttackNodeData
        : state.selectedNode,
    };
  }),
  addNodeLocal: (node) => set((state) => ({ nodes: [...state.nodes, node] })),
  removeNodeLocal: (id) => set((state) => ({
    nodes: state.nodes.filter((n) => n.id !== id),
    selectedNodeId: state.selectedNodeId === id ? null : state.selectedNodeId,
    selectedNode: state.selectedNodeId === id ? null : state.selectedNode,
  })),

  selectedNodeId: null,
  setSelectedNodeId: (id) => set((state) => ({
    selectedNodeId: id,
    selectedNode: id ? state.nodes.find(n => n.id === id) || null : null,
    inspectorOpen: id ? true : state.inspectorOpen,
    selectedNodeIds: new Set<string>(),
  })),
  selectedNode: null,
  selectedNodeIds: new Set<string>(),
  toggleNodeSelection: (id) => set((state) => {
    const next = new Set(state.selectedNodeIds);
    if (next.has(id)) { next.delete(id); } else { next.add(id); }
    return { selectedNodeIds: next };
  }),
  clearMultiSelect: () => set({ selectedNodeIds: new Set<string>() }),

  inspectorOpen: false,
  setInspectorOpen: (open) => set({ inspectorOpen: open }),

  searchQuery: '',
  setSearchQuery: (q) => set({ searchQuery: q }),
  filterNodeType: '',
  setFilterNodeType: (t) => set({ filterNodeType: t }),
  filterStatus: '',
  setFilterStatus: (s) => set({ filterStatus: s }),
  filterTags: [],
  setFilterTags: (tags) => set({ filterTags: tags }),

  undoStack: [],
  redoStack: [],
  pushUndo: (label) => {
    const { nodes, undoStack } = get();
    set({
      undoStack: [...undoStack.slice(-49), { nodes: JSON.parse(JSON.stringify(nodes)), label }],
      redoStack: [],
      canUndo: true,
      canRedo: false,
    });
  },
  undo: () => {
    const { undoStack, nodes } = get();
    if (undoStack.length === 0) return;
    const prev = undoStack[undoStack.length - 1];
    const newUndoStack = undoStack.slice(0, -1);
    const newRedoStack = [...get().redoStack, { nodes: JSON.parse(JSON.stringify(nodes)), label: prev.label }];
    set({
      nodes: prev.nodes,
      undoStack: newUndoStack,
      redoStack: newRedoStack,
      canUndo: newUndoStack.length > 0,
      canRedo: true,
    });
  },
  redo: () => {
    const { redoStack, nodes } = get();
    if (redoStack.length === 0) return;
    const next = redoStack[redoStack.length - 1];
    const newRedoStack = redoStack.slice(0, -1);
    const newUndoStack = [...get().undoStack, { nodes: JSON.parse(JSON.stringify(nodes)), label: next.label }];
    set({
      nodes: next.nodes,
      redoStack: newRedoStack,
      undoStack: newUndoStack,
      canUndo: true,
      canRedo: newRedoStack.length > 0,
    });
  },
  canUndo: false,
  canRedo: false,

  aiSuggestionsOpen: false,
  setAiSuggestionsOpen: (open) => set({ aiSuggestionsOpen: open }),
  aiSuggestions: [],
  setAiSuggestions: (suggestions) => set({ aiSuggestions: suggestions }),
}));
