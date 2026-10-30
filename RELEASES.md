# Versão pública

A versão exibida no rodapé é **2026.10.30.1**, publicada em 30/10/2026.

O projeto usa data e revisão (`AAAA.MM.DD.revisão`). Esta identificação não representa uma avaliação de maturidade nem uma reconstrução de releases passadas.

Estado incluído nesta publicação:

- Análise de links e leitura local de QR Codes com cobertura e limitações explícitas.
- Identificação discreta da versão no rodapé.

A fonte da versão é `src/release.ts`. Ela é incorporada ao bundle no build, sem buscar a versão mais recente por rede. Assim, uma aba ou PWA antigo continua mostrando a identificação do código que está realmente executando.

Em cada publicação, atualize a fonte da versão, a data e estas notas, execute as verificações e publique o build. Versões do formato de backup, banco de dados e dependências são independentes.
