# Versão do produto

**Versão 1.4.0 · atualizado em 05/11/2026**

## Versão 1.4.0 — 05/11/2026 (branch de validação)

- Relatório visual explica domínio base provável, subdomínios, caminho e presença de parâmetros sem exibir valores sensíveis.
- Campo opcional compara localmente a marca alegada com o domínio; sinaliza quando ela aparece somente em subdomínio.
- Aviso de privacidade aparece antes da consulta e esclarece que a URL segue para a API e bases externas configuradas.
- Não abre o destino, não consulta logs/certificados e não altera a pontuação automática. A API não mudou; o contrato continua 1.2.0.

Esta versão está em branch separada para validação e não substitui a produção até ser aprovada.

## Versão publicada anterior: 1.3.2 — 31/10/2026

## Marco atual

Evolução incremental da linha 1.x: cobertura e risco separados, resultado inconclusivo, sinais explicados, cancelamento e tratamento de indisponibilidade da API.

Esta numeração consolida o estado atual após revisão do código e do histórico. Não é uma alegação de que todas as versões intermediárias tenham sido publicadas formalmente. A identificação por calendário adicionada anteriormente foi substituída por versão do produto e data separadas.

## Evidências no histórico

- `6638ad510`
- `55afa8314`
- `355371c52`

Os marcos acima foram conferidos com os arquivos alterados e a implementação atual; quantidade de commits, versões de React/Vite e o campo genérico 0.0.0 não determinam a versão do produto.

## Política daqui em diante

- MAJOR: nova geração do produto, com reformulação substancial dos fluxos ou da arquitetura, ou incompatibilidades.
- MINOR: funcionalidades adicionais na mesma geração.
- PATCH: correções sem nova funcionalidade relevante.
- A versão do produto é independente do formato de backup, banco de dados e contrato da API. Este marco não modifica esses formatos.

Em cada publicação, manter alinhados `package.json`, o lockfile quando aplicável, a fonte usada pelo rodapé, este documento e o README. Atualizar a data somente quando houver publicação.

A fonte do rodapé é `src/release.ts`. Ela é incorporada ao build; uma aba antiga continua mostrando a versão do código carregado, sem consultar uma versão mais recente pela rede.

A API FastAPI mantém sua versão de contrato 1.2.0; o produto completo passa a 1.3.0. Não houve mudança do contrato nesta publicação.

## Manutenção 1.3.1 — 30/10/2026

Axios, CSS e backend FastAPI/Starlette/Pydantic atualizados com dependências Python fixadas.

Detalhes técnicos e validação em `docs/ATUALIZACOES_2026-10-30.md`.

## Manutenção 1.3.2 — 31/10/2026

Minimatch 10.2.6 → 11.0.1 apenas na cadeia de @typescript-eslint/typescript-estree. A versão 3.1.5 das ferramentas de lint permanece para preservar sua API. Veja docs/SECURITY_REVIEW_2026-10-31.md para validação e pendências.
