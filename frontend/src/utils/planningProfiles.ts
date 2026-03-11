import type { PlanningProfile } from '@/types';

export interface PlanningProfileOption {
  value: PlanningProfile;
  label: string;
  description: string;
}

export const PLANNING_PROFILE_OPTIONS: PlanningProfileOption[] = [
  {
    value: 'planning_first',
    label: 'Planning-first',
    description: 'Start with major domains, actors, trust boundaries, and operating layers before detailed references.',
  },
  {
    value: 'balanced',
    label: 'Balanced',
    description: 'Open with conceptual structure, then deepen branches with concrete technical paths and references.',
  },
  {
    value: 'reference_heavy',
    label: 'Reference-heavy',
    description: 'Keep the structure usable, but attach ATT&CK, CWE, CAPEC, and vulnerability detail earlier.',
  },
];

export function getPlanningProfileOption(value?: PlanningProfile): PlanningProfileOption {
  return PLANNING_PROFILE_OPTIONS.find((option) => option.value === value) ?? PLANNING_PROFILE_OPTIONS[1];
}
