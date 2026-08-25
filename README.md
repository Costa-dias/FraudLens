# FraudLens

Verificação de segurança antes do clique — analise URLs, prints e vídeos com sinais claros de fraude, mantendo a privacidade primeiro.

## Estrutura

```
.
├── src/                # Frontend React + Vite + TypeScript
├── server/             # Backend FastAPI (Python)
├── requirements.txt    # Dependências Python
└── package.json        # Dependências Node
```

## Backend (FastAPI)

```bash
pip install -r requirements.txt
export GOOGLE_SAFE_BROWSING_API_KEY="sua-chave"
export CORS_ORIGINS="http://localhost:5173"
uvicorn server.main:app --reload --port 8000
```

## Frontend (React)

```bash
npm install
npm run dev
```

O Vite encaminha `/api/*` para `http://localhost:8000` automaticamente.

## Segurança

- API key somente no servidor (nunca no navegador)
- Rate limiting por IP (30 req/min)
- Validação de assinatura de arquivos (magic bytes)
- Limite de upload 25 MB
- Timeout nas requisições externas (8s Safe Browsing, 15s upload)
- CORS configurável via `CORS_ORIGINS`
- Sanitização de entradas (XSS / injection)
- Proteção contra SSRF (bloqueio de hosts privados)
- Não armazena dados além do necessário
- Logs sem API keys, tokens ou dados pessoais
- Nunca retorna a API key na resposta
- Rotação da chave se houver suspeita de vazamento

## Recursos

- Leitura de QR: exibe o endereço encontrado e envia ao scanner de URL
- Histórico privado: salvo apenas no aparelho (localStorage)
- Denúncia rápida: gera relato sem dados pessoais para compartilhar
