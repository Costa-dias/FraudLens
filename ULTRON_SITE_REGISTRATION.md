# Registro público para ULTRON

Domínio exato: https://fraudlens-code.onrender.com

O arquivo `public/.well-known/ultron-site.json` deve ser servido em
`https://fraudlens-code.onrender.com/.well-known/ultron-site.json`, sem redirecionamento.
É um identificador público, não uma senha nem credencial.

O ULTRON compara este registro com seu catálogo antes de cada consulta
manual de TLS/certificado/cabeçalhos (GET deste arquivo e HEAD da raiz).
Nenhum script, monitor, dependência, login ou serviço é instalado no site.
Não autoriza exploração, escrita, correções automáticas nem testes ativos.
Remover ou mudar o arquivo impede novas consultas pelo catálogo atual.

Esta alteração é preparada para revisão; não foi implantada. Depois da
publicação autorizada, verificar que o endpoint entrega JSON, não o HTML
da aplicação SPA. O build deve preservar o arquivo oculto `.well-known`.
O resultado de cabeçalhos não comprova ausência de vulnerabilidades.
