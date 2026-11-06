# Validação da 1.4.0 — 06/11/2026

Typecheck, lint, testes frontend e build passaram. Backend: 42 de 43 testes passaram; falhou `test_httpx_default_bundle_and_verification`, que exige a ausência de emSign ECC Root CA - G3 no contexto TLS padrão.

A instalação nova de certifi 2026.10.23 foi conferida: o wheel baixado tem SHA-256 e9b54de76e530bb6cf0ccd036787103acb58fd42ba930ea8bf948ddbaa2f61d1, igual ao publicado no PyPI. Neste executor, um SSLContext(PROTOCOL_TLS_CLIENT) recém-criado já reporta um certificado CA e esse certificado corresponde ao fingerprint 86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b. Portanto, este resultado envolve também o contexto TLS do executor e não comprova por si só o bundle ou comportamento da produção.

A tentativa local de contexto isolado foi descartada. O código TLS e o teste original permanecem intactos. Não houve desativação de verificação de certificados/hostname, mudança no armazenamento de confiança do sistema ou alteração dos requisitos para forçar aprovação.

Antes de integrar: repetir os 43 testes em executor limpo independente e conferir o bundle usado pelo serviço. A documentação da vulnerabilidade aponta correção a partir de certifi 2026.10.18: https://github.com/advisories/GHSA-6q48-6c7w-9gw2 . Release conferida: https://pypi.org/project/certifi/2026.10.23/ .

Nenhum deploy ou merge realizado por esta validação.
