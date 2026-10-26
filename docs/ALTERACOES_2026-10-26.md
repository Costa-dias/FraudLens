# Alterações e validação — 26/10/2026

## Mudanças

- API: resultado INCONCLUSIVE para cobertura insuficiente sem sinais relevantes. Pontuação de risco e cobertura são campos diferentes.
- Data da análise do VirusTotal exposta; relatórios sem data ou com mais de sete dias não completam a cobertura.
- Removida pontuação automática por palavras usuais como login, pix e nomes de bancos. Domínios de teste exigem hostname exato, sem marcar URLs legítimas que só mencionam esses nomes no caminho/query.
- Frontend aceita os estados novos e o payload anterior, informa datas/limitações e mostra Preparar relato em vez de prometer envio de denúncia.
- Scanner ajustado para não ultrapassar a largura do celular.
- README corrigido para refletir backend, QR local e ausência de inspeção própria de certificados.

## Verificação

`python -m pytest server/test_api.py -q`: 24 testes passaram. DNS e bases externas são simulados, sem envio de alvos reais. Também passaram typecheck, lint e build do frontend. No navegador local, resposta simulada inconclusiva e layout de 390 px foram verificados.

## Publicação

Frontend e API têm deploys separados: ambos precisam receber esta revisão. Testes simulados não confirmam chaves, cotas ou disponibilidade dos provedores em produção. Nenhuma chave foi criada, substituída ou publicada.
