# Auditoria de segurança — 27/10/2026

## Atualização: integração e implantação autorizadas em 27/10/2026

Após a auditoria inicial, o proprietário autorizou integrar as correções e realizar o deploy, mantendo o Supabase sem testes enquanto estiver hibernando. Esta seção registra o estado posterior e substitui as pendências de merge/deploy mencionadas no registro inicial abaixo. Os limites de auditoria e de testes não executados continuam válidos.

Commit auditado integrado à `main`: `65ebc7fcf3a893ec0667eb2e28a6b0bf29f13829`.

- FraudLens frontend: deploy **live**, concluído em 2026-10-27T13:25:21.804856Z (UTC), no commit auditado.
- FraudLens API: deploy **live**, concluído em 2026-10-27T13:26:35.907319Z (UTC), no commit auditado.

Página pública, JavaScript e CSS responderam HTTP 200. Smoke test do código servido em produção passou em Chromium móvel e desktop, sem erros de JavaScript. O teste usou requisições Playwright com o CA do proxy da plataforma para validar TLS; a verificação TLS não foi desativada. Chamadas de origens externas foram bloqueadas no navegador de teste.

A variável não secreta `PYTHON_VERSION` do serviço existente foi atualizada para **3.11.18**, preservando todas as demais variáveis. Os logs do build ativo confirmam Python 3.11.18 e certifi 2026.10.23. `/`, `/docs` e `/openapi.json` responderam HTTP 200; o endpoint raiz confirmou a identidade da API. Consulta de logs recentes após a publicação não retornou erros. A pendência de atualização do runtime em produção está **CORRIGIDA**. Nenhuma credencial foi alterada.

Nenhuma tabela, política RLS, configuração Supabase, credencial ou dado de usuário foi alterado. O registro abaixo descreve a etapa inicial, anterior à autorização de deploy. Esta atualização é somente documental e usa `[skip render]` para não provocar outro deploy.

---


Repositório: `Costa-dias/FraudLens`. Responsável: Codex. Base auditada: `63dbdb9ee6ada5e94466da3f757e0a57d97b799d`.
Branch de trabalho: `security/audit-2026-10-27`. Este relatório acompanha o commit de correção/documentação desta branch; consulte seu SHA no histórico do arquivo.

## Escopo e critérios

Somente conteúdo deste repositório público e histórico alcançável pelas referências obtidas no clone. Nenhum repositório privado foi modificado. Avisos e versões foram consultados em 27/10/2026. Versão antiga, isoladamente, não confirma explorabilidade. Ausência de alerta não garante ausência de vulnerabilidade.

- **CORRIGIDO**: problema confirmado corrigido nesta branch; não implica implantação.
- **SEM IMPACTO**: aviso específico não alcança a versão ou funcionalidade verificada.
- **PENDENTE**: medida necessária ainda não aplicada no ambiente indicado.
- **NÃO VERIFICADO**: faltam código, credenciais, ambiente ou evidência suficiente.

## Histórico e segredos

Gitleaks 8.30.1, regras padrão, `git --log-opts=--all --redact`, sem exceções do repositório na varredura independente: código de saída 0, 0 achados. Escopo: 92 commits alcançáveis (o contador do scanner pode excluir merges/commits sem conteúdo examinável). Não foram detectadas credenciais pelas regras executadas. Objetos apagados, referências não obtidas e segredos sem padrão reconhecível não são cobertos.

## Dependências, runtime e código

Gerenciador original: npm, com `package-lock.json` preservado (blob `16d17867fa38d6de7822d5149ff73f72d70b63ac`). `npm ci --no-fund` concluiu. A auditoria examinou dependências diretas e transitivas de produção e desenvolvimento: 243 entradas contabilizadas pelo npm; **zero alertas** em todas as gravidades. Versões e integridades vêm do lockfile, não apenas dos intervalos do manifesto.

| Tecnologia | Versão efetiva no lockfile/configuração | Decisão |
|---|---|---|
| Node.js | 24.22.1 em `.node-version` e CI | Manter LTS de segurança; testes locais executados com 24.22.1 |
| React / React DOM | 18.3.1 / 18.3.1 | Manter |
| Vite | 8.3.5 | Manter |
| TypeScript | 5.9.3 | Manter |

Consultas adicionais ao [GitHub Advisory Database](https://github.com/advisories) para as versões de React, Vite e TypeScript retornaram listas vazias. Isso significa ausência de avisos retornados para essas versões, não ausência universal de falhas. O [boletim oficial Node de outubro](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) e a [release 24.22.1](https://nodejs.org/en/blog/release/v24.22.1) justificam preservar a versão já corrigida. Não houve atualização de pacotes npm nem alteração de lockfile.

Não foram encontrados `dangerouslySetInnerHTML`, `innerHTML`, `eval` ou `new Function` no código da aplicação revisado. As configurações Vite não habilitam exposição geral de hosts nem `allowedHosts: true`; mantenha o servidor de desenvolvimento fora da produção. Não foram identificados manifestos/lockfiles Bun no HEAD: Bun não se aplica a este repositório.

## GitHub Actions

Revisados todos os workflows versionados: permissões de conteúdo somente leitura, sem `pull_request_target`, sem checkout de código não confiável com token de escrita e sem interpolação direta de título/corpo de PR em scripts shell. Actions oficiais já estavam em tags atuais; foram fixadas nos SHAs resolvidos das mesmas tags. Checkout agora usa `persist-credentials: false`. A Action Gitleaks já estava fixada e foi preservada. Isto é endurecimento da cadeia de fornecimento, sem CVE confirmado nas Actions presentes. Nenhum workflow de deploy foi acrescentado.

`actionlint 1.7.12 -shellcheck= -pyflakes=` passou; valida sintaxe e expressões, sem análise ShellCheck/Pyflakes. As execuções remotas de CI não substituem os resultados locais e não são presumidas concluídas.

## Validação local

| Verificação | Resultado |
|---|---|
| Instalação com lockfile | Passou |
| `npm run typecheck` | Passou |
| `npm run lint` | Passou |
| `npm run build` | Passou |
| `npm test` | Não executado: script não definido pelo projeto |
| `npm audit --json` | Zero alertas conhecidos |
| `git diff --check` | Passou |
| Inicialização em navegador Chromium | Passou com preview local; viewport móvel 390×844 e desktop 1440×900 |
| Manifest e ícones PWA | Arquivo JSON e respostas dos ícones verificados |
| Service Worker | Registrado e controlando a página local |

Navegação de teste não usou dados reais. Não foram alterados layout, funcionalidades, armazenamento ou autenticação. Instalação efetiva em Android/iOS, diálogos nativos de instalação e todos os dispositivos físicos: **NÃO VERIFICADO**.

O Service Worker é somente de ciclo de vida, sem cache de navegação/dados offline. Foi preservado. Smoke test confirma inicialização e estrutura da rota principal, não todos os fluxos de negócio.

## FraudLens: Python, HTTPX e certificados

`requirements.txt` confirma FastAPI 0.161.1, Starlette 1.9.0, HTTPX 0.28.1, Uvicorn 0.54.0 e Pydantic 2.14.1. As dependências foram instaladas e `pip-audit` examinou as 23 dependências resolvidas; zero vulnerabilidades no grafo da aplicação. FastAPI e HTTPX também foram consultados por versão na base GitHub. Nenhuma justificativa de segurança foi encontrada para atualizar essas bibliotecas. O aviso de depreciação do TestClient/HTTPX não é vulnerabilidade e não impediu os testes.

### GHSA-6q48-6c7w-9gw2 — certifi

- Fonte: [aviso oficial](https://github.com/advisories/GHSA-6q48-6c7w-9gw2), publicado **20/10/2026**, atualizado 26/10/2026.
- Gravidade crítica, CVSS 4.0 **9,1**. **Sem CVE conhecido no aviso**; não confundir com o CVE separado do Python.
- Faixa afetada: `>=2019.03.09,<2026.10.18`; primeira correção `2026.10.18`; recomendação do aviso: `>=2026.10.19`.
- Instalação limpa original e último build ativo do Render (26/10) usam **2026.10.23**. Resultado: **SEM IMPACTO para o bundle observado**. O alerta existe, mas a versão instalada não está afetada.
- HTTPX depende diretamente de certifi; `httpcore`, `anyio`, `idna` e `h11` fazem parte do grafo transitivo. Os clientes externos não passam contexto próprio: usam certifi por padrão, salvo override `SSL_CERT_FILE`/`SSL_CERT_DIR`. Overrides efetivos no servidor não foram inspecionados, para evitar leitura de segredos.
- Medida preventiva: `certifi==2026.10.23` explícito no manifesto. Antes: transitive sem pin, já resolvendo 2026.10.23; depois: mesma versão fixada. Não se trata de atualização de um pacote comprovadamente vulnerável.
- Exploração: chaves intermediárias comprometidas são fato do aviso; exploração contra este projeto não foi demonstrada. A fonte não estabelece exploração ativa no projeto. A consulta ao catálogo CISA KEV foi bloqueada (403): exploração conhecida global permanece **NÃO VERIFICADO**.

### Runtime Python — CVE-2026-115557 / GHSA-x547-2835-q547

Fonte: [release oficial 3.11.18](https://www.python.org/downloads/release/python-31118/) de **25/10/2026** e [registro GHSA](https://github.com/advisories/GHSA-x547-2835-q547) publicado em **24/10/2026**. O GHSA é não revisado, classifica como crítico/CVSS 4.0 9,4; a PSF confirma a correção no módulo SSL. Python 3.11 anterior ao patch não tem a nova denylist; versão corrigida na série: **3.11.18**.

`runtime.txt` original e logs do último build ativo confirmam **3.11.9**; o Render seleciona essa versão por `PYTHON_VERSION`. A produção não foi alterada. O caminho HTTPX observado já é mitigado pelo certifi corrigido; isso não demonstra que todo consumidor SSL do runtime tenha a mesma proteção. Exploração efetiva não demonstrada. A versão real de desenvolvimento anterior não está fixada em outro arquivo; o executor iniciou com 3.12.14, não é evidência da máquina do proprietário.

**CORRIGIDO na branch**: `runtime.txt`, novo `.python-version` e CI alinhados em **3.11.18**, sem mudança da série 3.11. A versão segue recebendo segurança até outubro/2027. Source tarball oficial verificado por SHA-256, compilado localmente e usado na suíte.

**PENDENTE em produção**: após revisão e autorização separada, alterar o override Render `PYTHON_VERSION` para 3.11.18 (ou remover o override para respeitar `.python-version`), aprovar merge e realizar deploy controlado. [Precedência oficial do Render](https://render.com/docs/python-version). Não foi criada mudança de ambiente ou deploy. Não existe Dockerfile no HEAD auditado.

Outras correções incorporadas à release: [CVE-2026-77214](https://github.com/advisories/GHSA-8xfx-9m5m-pgcp), alta, publicada 07/10/2026; [CVE-2026-102633](https://github.com/advisories/GHSA-533f-rf84-jgcc), alta; ambas Expat, corrigidas no Expat 2.9.0 incluído no Python 3.11.18. A aplicação recebe JSON e não utiliza parser XML/Expat no código revisado. A versão Expat da imagem em produção não foi inspecionada: **NÃO VERIFICADO** para o componente instalado, sem caminho de impacto identificado. [CVE-2026-114583](https://github.com/advisories/GHSA-mw29-5qxh-rr87), média, também é corrigida pela release; a aplicação não extrai tarfiles. Não são apresentadas como explorações confirmadas deste projeto.

### Testes backend e TLS

- 27 testes passaram em Python **3.11.18**; os mesmos 27 passaram no executor 3.12.14. Testes existentes usam DNS/integrações simulados; três testes novos verificam TLS.
- `pip check` e `compileall server`: passaram. Bandit com confiança/gravidade média ou alta: nenhum achado; avisos de comentários/depreciações documentados, não ignorados como falhas.
- Uvicorn iniciou em loopback com chaves externas vazias; `/`, `/openapi.json` e `/docs` responderam 200.
- TLS local: certificado não confiável rejeitado; certificado de CA de teste explicitamente confiada aceito com hostname verificado; bundle padrão HTTPX sem a raiz emSign ECC G3 comprometida. Nenhum `verify=False` foi inserido.
- HTTPS externo sem credenciais: Google Safe Browsing respondeu 404 e VirusTotal 302, com validação TLS ativa. O executor usa proxy e trust store configurado pela plataforma (`SSL_CERT_FILE`/`SSL_CERT_DIR`); estes testes não equivalem à inspeção do certificado remoto a partir da produção.
- APIs autenticadas, cotas e chaves em produção: **NÃO VERIFICADO**, sem chamadas autenticadas reais.
- `pip-audit` do ambiente 3.11 recém-criado identificou ferramentas de bootstrap antigas (`pip 24.0`, `setuptools 79.0.1`); atualizadas **apenas no ambiente de teste** para pip 26.2.2 / setuptools 84.2.1. Auditoria completa do ambiente instalado voltou a zero alertas. Isso não prova a versão dessas ferramentas no servidor nem adiciona dependências à aplicação.

### Scanner de segredos

**CORRIGIDO**: `.gitleaks.toml` original usava `fingerprints` em allowlist, formato rejeitado pelo Gitleaks 8.30.1. Regras padrão habilitadas explicitamente e única exceção histórica de credencial fictícia transferida para `.gitleaksignore` no formato de fingerprint exato. Tanto a varredura independente sem exceção quanto a configuração corrigida terminaram sem achados. `.gitignore` agora exclui ambientes virtuais e cache pytest locais.

Arquivos alterados: `requirements.txt`, `runtime.txt`, `.python-version`, `server/test_tls.py`, `.gitleaks.toml`, `.gitleaksignore`, `.gitignore`, os dois workflows e este relatório. Nenhum código de negócio foi alterado.

## Resultado e integridade operacional

As mudanças desta branch são locais/de revisão. **Nenhum merge, deploy, alteração de credencial, escrita no banco/RLS/autenticação, exclusão ou modificação de produção foi realizado.** Verificações do Render, quando realizadas para FraudLens, foram somente leitura. Produção pode divergir do repositório; não foi declarada integralmente validada.

O diff foi revisado e `git diff --check` passou. Commits são separados por repositório. Para reproduzir a identificação: `git log -1 --format=%H -- SECURITY_AUDIT_2026-10-27.md`.
