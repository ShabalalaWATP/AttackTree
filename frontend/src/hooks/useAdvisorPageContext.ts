import { useEffect, useMemo } from 'react';

import { useStore, type AdvisorPageContext } from '@/stores/useStore';

export function useAdvisorPageContext(context: AdvisorPageContext | null) {
  const setAdvisorPageContext = useStore((state) => state.setAdvisorPageContext);
  const clearAdvisorPageContext = useStore((state) => state.clearAdvisorPageContext);

  const signature = context
    ? JSON.stringify({
        view: context.view,
        title: context.title,
        summary: context.summary,
        packets: context.packets,
      })
    : '';

  const normalizedContext = useMemo<AdvisorPageContext | null>(() => {
    if (!context) return null;
    return {
      view: context.view,
      title: context.title.trim(),
      summary: context.summary.trim(),
      packets: (context.packets || []).map((item) => item.trim()).filter(Boolean),
    };
  }, [signature]);

  useEffect(() => {
    if (!normalizedContext) {
      clearAdvisorPageContext();
      return;
    }

    setAdvisorPageContext(normalizedContext);
    return () => {
      clearAdvisorPageContext();
    };
  }, [clearAdvisorPageContext, normalizedContext, setAdvisorPageContext]);
}
