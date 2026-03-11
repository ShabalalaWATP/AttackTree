import { CONTEXT_PRESETS, type ContextPresetOption } from '@/types';

function normalizePresetKey(value: string): string {
  return value.trim().toLowerCase().replace(/[-/\s]+/g, '_');
}

const CONTEXT_PRESET_MAP = new Map(
  CONTEXT_PRESETS.flatMap((preset) => [
    [preset.id, preset] as const,
    [normalizePresetKey(preset.id), preset] as const,
  ]),
);

function prettifyIdentifier(value: string): string {
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export function getContextPresetOption(id?: string | null): ContextPresetOption | null {
  if (!id) return null;
  return CONTEXT_PRESET_MAP.get(id) || CONTEXT_PRESET_MAP.get(normalizePresetKey(id)) || null;
}

export function formatContextPreset(id?: string | null): string {
  if (!id) return 'Unspecified';
  return getContextPresetOption(id)?.name || prettifyIdentifier(id);
}

export function getGroupedContextPresets(): Array<{ category: string; presets: ContextPresetOption[] }> {
  const grouped = new Map<string, ContextPresetOption[]>();
  CONTEXT_PRESETS.forEach((preset) => {
    const group = grouped.get(preset.category) || [];
    group.push(preset);
    grouped.set(preset.category, group);
  });
  return Array.from(grouped.entries()).map(([category, presets]) => ({ category, presets }));
}

export function getEnvironmentContextPresets(): ContextPresetOption[] {
  return CONTEXT_PRESETS.filter((preset) => preset.isEnvironment);
}
