import type { ReferenceLink, ReferenceSearchItem } from '@/types';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function normalizeText(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function normalizeConfidence(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.max(0, Math.min(1, value));
  }
  return null;
}

export function referenceLinkKey(link: Pick<ReferenceLink, 'framework' | 'ref_id'>): string {
  return `${normalizeText(link.framework).toLowerCase()}:${normalizeText(link.ref_id).toUpperCase()}`;
}

export function normalizeReferenceLinks(value: unknown): ReferenceLink[] {
  if (!Array.isArray(value)) {
    return [];
  }

  const deduped = new Map<string, ReferenceLink>();
  value.forEach((item) => {
    if (!isRecord(item)) {
      return;
    }
    const framework = normalizeText(item.framework);
    const refId = normalizeText(item.ref_id);
    const refName = normalizeText(item.ref_name);
    if (!framework || !refId) {
      return;
    }
    const normalized: ReferenceLink = {
      framework,
      ref_id: refId,
      ref_name: refName || refId,
      confidence: normalizeConfidence(item.confidence),
      rationale: normalizeText(item.rationale),
      source: normalizeText(item.source) || undefined,
    };
    const key = referenceLinkKey(normalized);
    const existing = deduped.get(key);
    if (!existing) {
      deduped.set(key, normalized);
      return;
    }
    const existingConfidence = typeof existing.confidence === 'number' ? existing.confidence : 0;
    const newConfidence = typeof normalized.confidence === 'number' ? normalized.confidence : 0;
    if (newConfidence > existingConfidence) {
      deduped.set(key, { ...existing, ...normalized });
      return;
    }
    if (!existing.rationale && normalized.rationale) {
      existing.rationale = normalized.rationale;
    }
    if (!existing.source && normalized.source) {
      existing.source = normalized.source;
    }
  });

  return Array.from(deduped.values());
}

export function buildReferenceLinkFromSearchItem(
  item: ReferenceSearchItem,
  source = 'manual',
): ReferenceLink {
  return {
    framework: item.framework,
    ref_id: item.ref_id,
    ref_name: item.ref_name,
    confidence: Math.max(0.1, Math.min(1, item.score / 1000)),
    rationale: item.reasons?.slice(0, 3).join(', ') || '',
    source,
  };
}

export function mergeReferenceLinks(
  existing: ReferenceLink[],
  additions: Array<ReferenceLink | ReferenceSearchItem>,
  source = 'manual',
): ReferenceLink[] {
  const normalizedExisting = normalizeReferenceLinks(existing);
  const normalizedAdditions = additions.map((item) => (
    'score' in item
      ? buildReferenceLinkFromSearchItem(item, source)
      : item
  ));
  return normalizeReferenceLinks([...normalizedExisting, ...normalizedAdditions]);
}

export function removeReferenceLink(
  links: ReferenceLink[],
  framework: string,
  refId: string,
): ReferenceLink[] {
  const targetKey = referenceLinkKey({ framework, ref_id: refId });
  return normalizeReferenceLinks(links).filter((link) => referenceLinkKey(link) !== targetKey);
}
