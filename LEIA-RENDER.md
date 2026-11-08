# Correção para o Render

O servidor verificava o cabeçalho Host antes de processar a página. Sem SITE_SEGURO_ORIGIN, aceitava apenas o endereço local e a porta interna, por isso o domínio público era rejeitado. A rota inicial também havia sido substituída por uma mensagem de teste.

A correção configura https://site-seguro.onrender.com como origem padrão quando PORT está definido e volta a servir a página do projeto. A validação de Host e Origin permanece ativa. Se SITE_SEGURO_ORIGIN já estiver definida no Render, ela tem prioridade: confira se seu valor é exatamente https://site-seguro.onrender.com, sem barra ao final. Para outro domínio, configure essa variável com a origem HTTPS desse domínio.

## Atualizar o serviço

1. No repositório usado pelo Render, substitua backend/app.py pelo arquivo backend/app.py deste pacote. O arquivo tests/test_render.py pode ser copiado para manter os testes.
2. Envie a alteração ao repositório e aguarde o deploy automático do Render; se não houver deploy automático, inicie um deploy pelo painel.
3. Confira no serviço do Render que o Start Command é `python3 backend/app.py` e que o Root Directory está na raiz do projeto (ou ajuste o comando se usar outro diretório). A variável PORT é fornecida pelo Render.
4. Abra https://site-seguro.onrender.com/ e teste uma análise. Se o mesmo erro persistir, confira a variável SITE_SEGURO_ORIGIN e os logs do deploy.

Configure SAFE_BROWSING_KEY, VIRUSTOTAL_KEY e URLHAUS_AUTH_KEY como variáveis de ambiente no painel do Render se quiser usar essas consultas; elas não devem ser colocadas no código.

Para preservar seus dados, o banco local de avaliações e a pasta .git do ZIP original não foram incluídos nesta entrega: eles permanecem no seu ZIP original e no seu repositório. Não substitua ou apague seu banco de dados ao copiar a correção. O sistema de arquivos do Render pode ser temporário; avaliações em SQLite podem ser perdidas em reinícios ou deploys se não houver armazenamento persistente apropriado.

A extensão continua usando o servidor local para analisar páginas; o endereço configurado em extensao/config.js abre o site publicado.
