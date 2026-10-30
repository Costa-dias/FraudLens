# Manutenção — 30/10/2026

## FraudLens — 1.3.0 → 1.3.1

Axios e ferramentas de CSS/TypeScript receberam manutenção. O backend foi atualizado dentro das APIs testadas. As respostas de risco, cobertura e estado inconclusivo continuam com o mesmo contrato; a numeração do produto não é a versão do contrato FastAPI. A extração de QR Codes continua local e os testes não enviam links reais às bases externas.

### Bibliotecas diretas alteradas

| Biblioteca | Antes | Depois | Para que serve |
|---|---|---|---|
| `axios` | 1.20.0 | 1.21.0 | Cliente HTTP: envia e recebe requisições das APIs. |
| `autoprefixer` | 10.6.1 | 10.6.2 | Ajusta CSS para compatibilidade entre navegadores. |
| `postcss` | 8.5.31 | 8.5.32 | Processamento do CSS no build. |
| `typescript-eslint` | 8.72.0 | 8.72.1 | Verifica código TypeScript e regras de qualidade. |

### Backend Python

| Biblioteca | Antes | Depois | Para que serve |
|---|---|---|---|
| `fastapi` | 0.161.1 | 0.162.0 | Define endpoints, validação e documentação da API. |
| `starlette` | 1.9.0 | 1.10.0 | Camada HTTP/ASGI sobre a qual o FastAPI funciona. |
| `uvicorn[standard]` | 0.54.0 | 0.54.0 | Servidor que executa a API no Render. |
| `httpx` | 0.28.1 | 0.28.1 | Cliente HTTP usado pelas integrações e testes. |
| `pydantic` | 2.14.1 | 2.14.2 | Validação e serialização dos modelos de dados. |
| `certifi` | 2026.10.23 | 2026.10.23 | Certificados públicos para validação TLS. |

`requirements.in` registra as bibliotecas diretas; `requirements.txt` passa a fixar também as dependências transitivas. O Render continua instalando `requirements.txt`. Isso torna builds futuros mais reproduzíveis. A auditoria Python não apontou vulnerabilidades conhecidas na resolução fixada. Os metadados dos pacotes aceitam Python 3.11.18.

### Verificações

Teste de prontidão/cancelamento da API, TypeScript, lint, build e 37 testes Python.

Auditoria das dependências JavaScript: nenhuma vulnerabilidade conhecida reportada após as mudanças. Isso não substitui revisão de código nem significa risco zero.
