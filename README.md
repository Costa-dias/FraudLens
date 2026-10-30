# FraudLens — segurança antes do clique

**Versão 1.3.1 · atualizado em 30/10/2026**

Evolução incremental da linha 1.x: cobertura e risco separados, resultado inconclusivo, sinais explicados, cancelamento e tratamento de indisponibilidade da API.

[Histórico e critérios da versão](RELEASES.md).

Verificador de URLs com sinais explicados, API FastAPI e interface React/TypeScript. Imagens e vídeos são usados apenas para extração local de QR Codes; não são enviados ao servidor e não passam por análise completa da mensagem.

- [Aplicação](https://fraudlens-code.onrender.com/)
- [API](https://fraudlens-i54g.onrender.com/)

## O que a análise faz

Analisa a estrutura do endereço e, quando configuradas, consulta Google Safe Browsing e o relatório existente do VirusTotal. Não navega no site de destino nem realiza uma inspeção própria do certificado TLS. HTTPS é apenas um dos sinais estruturais.

A resposta separa `risk_score` (0–100, sinais heurísticos; não é uma probabilidade estatística) de `coverage` (complete/partial). `confidence_score` permanece como alias de risco para clientes antigos. Os estados são SAFE (baixo risco aparente), SUSPICIOUS (sinais suspeitos), DANGEROUS (alto risco) e INCONCLUSIVE (informação insuficiente sem sinais locais relevantes).

Relatórios do VirusTotal com mais de sete dias ou sem data têm cobertura parcial. A data externa e a data da consulta são exibidas. Uma classificação limpa não garante segurança. Palavras usuais como login e pix não somam risco por si só.

## Privacidade e limites

- Histórico no navegador, com opção de apagar; URLs são enviadas à API e às bases externas consultadas. Não use links com tokens ou dados sensíveis.
- Chaves somente no servidor; logs omitem alvos e credenciais.
- Limite por IP em memória, CORS restrito, timeouts e validação de URLs.
- “Preparar relato” copia um texto para revisão; não envia denúncia a nenhum órgão e não garante anonimato após compartilhamento.
- Sem consulta ao destino final de links encurtados. Não é antivírus ou garantia de segurança.

## Executar e validar

Node.js 24 para o frontend:

```bash
npm ci
npm run dev
npm run typecheck
npm run lint
npm run build
```

Backend (a partir da raiz):

```bash
python -m pip install -r requirements.txt pytest
python -m uvicorn server.main:app --host 127.0.0.1 --port 8000
python -m pytest server/test_api.py -q
```

Configure `VITE_API_URL` no frontend e `GOOGLE_SAFE_BROWSING_API_KEY`, `VIRUSTOTAL_API_KEY`, `CORS_ORIGINS` no ambiente do servidor. Nunca coloque chaves em variáveis VITE. Sem bases disponíveis, resultados sem sinais críticos ficam inconclusivos.

## Estrutura

`src/` contém interface, QR local e histórico. `server/main.py` contém a API; `server/test_api.py` testa com DNS e serviços externos simulados, sem consultar URLs reais.

## Publicação

Frontend e API precisam ser atualizados juntos para o novo estado INCONCLUSIVE e os metadados de cobertura. O frontend também aceita o formato anterior. Validar build não comprova o estado das chaves ou das cotas em produção.


[Relatório detalhado da manutenção](docs/ATUALIZACOES_2026-10-30.md).
