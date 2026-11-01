# Conferência de segurança — 31/10/2026

## Alteração aplicada

Minimatch 10.2.6 → 11.0.1 na cadeia de `@typescript-eslint/typescript-estree`, por override restrito ao consumidor. Lockfile regenerado pelo gerenciador do projeto. A API utilizada pelo consumidor (`minimatch` com `dot: true`) foi inspecionada. Não há uso de `makeRe` nesse consumidor.

A troca global não foi aplicada: minimatch 3.1.5 permanece na cadeia ESLint, que usa a API antiga. O aviso GHSA-g3hv-75wg-m249 marca versões <11.0.1. Portanto esta manutenção é parcial e não zera os avisos moderados. A exploração descrita exige padrões controlados por terceiros e `optimizationLevel >= 2`; não foi identificado esse uso no código da aplicação. A versão 3.1.5 não possui essa opção, introduzida na série 7. Não foi declarada uma exceção no auditor nem desabilitado o controle.

## Validação

Instalação pelo lockfile; testes disponíveis; lint e build aprovados. Nos projetos npm, typecheck também aprovado.

Auditoria npm completa após atualização: 0 críticas, 0 altas, 11 moderadas (incluindo consumidores transitivos do mesmo aviso). Auditoria `npm audit --omit=dev`: zero avisos.

## Outras verificações

Não foram encontrados pypdf, pyasn1, node-forge, @sigstore/oci ou pypa/gh-action-pypi-publish nos manifests, lockfiles e workflows examinados. FraudLens mantém follow-redirects 1.16.2. Os requirements Python completos e fixados de FraudLens e Corretor foram consultados com pip-audit --no-deps --disable-pip: zero vulnerabilidades conhecidas. Essa auditoria confere os pins e não o ambiente de produção.

Sete páginas públicas responderam HTTP 200. A raiz da API FraudLens respondeu `{"status":"ok","service":"FraudLens API"}`; `/health` não é uma rota implementada. Não foram testados login, dados pessoais ou alterações em produção.

As cópias de Corretor-de-imoveis-vitrine e projeto-web-ti-apresentacao contêm somente documentação, sem código executável ou dependências para atualizar. ULTRON ficou fora do escopo dos sites.

## Pendência

Migrar a cadeia de lint para versões upstream compatíveis com minimatch 11 quando disponíveis, ou realizar uma migração separada de ESLint com análise de plugins. Os checks que exigem auditoria sem nenhum aviso ainda podem falhar devido ao aviso moderado remanescente. Conferir o deploy do commit; resposta HTTP 200 anterior não comprova publicação da nova versão.

## Fontes

- https://github.com/advisories/GHSA-g3hv-75wg-m249
- https://github.com/advisories/GHSA-mrwp-f3q8-3g9p
- https://github.com/advisories/GHSA-5xjx-3w67-w9x9
- https://github.com/isaacs/minimatch/blob/main/changelog.md
