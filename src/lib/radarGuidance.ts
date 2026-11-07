export const RADAR_URL = 'https://radar-de-golpes-hub.xadoondias.workers.dev/#categorias';

export function radarGuidance(result: { verdict: string; risk_score?: number; coverage?: string }) {
  const score = result.risk_score;
  const highRisk = (typeof score === 'number' && Number.isFinite(score) && score >= 50)
    || result.verdict === 'DANGEROUS' || result.verdict === 'SUSPICIOUS';
  const limited = result.verdict === 'INCONCLUSIVE' || result.coverage !== 'complete';
  if (highRisk) return {
    variant: 'attention',
    title: 'Antes de abrir, conheça os sinais de golpe',
    description: 'A análise merece atenção. No HUB — Radar de Golpes, confira modalidades de golpes, sinais de alerta e orientações para decidir com mais cuidado.',
  };
  if (limited) return {
    variant: 'limited',
    title: 'O resultado tem limitações. Continue se informando.',
    description: 'Não foi possível concluir todas as verificações. Conheça modalidades de golpes e formas de se proteger no HUB — Radar de Golpes.',
  };
  return {
    variant: 'educational',
    title: 'Mesmo com baixo risco aparente, vale conferir',
    description: 'Nenhuma análise garante que um link seja seguro. Conheça modalidades de golpes e sinais de alerta no HUB — Radar de Golpes.',
  };
}
