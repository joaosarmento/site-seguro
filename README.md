# Site Seguro — extensão 1.3.2 e site web 0.10.1

Nesta versão, o painel e seus controles ganharam cantos mais suaves e o ícone foi alinhado à marca “S” verde do projeto. O cálculo permanece igual.

Este pacote inclui a extensão Chrome, o site e o mesmo motor local para ambos. Requisitos: Python 3.9 ou superior e Chrome 120 ou superior. Não é necessário instalar bibliotecas adicionais.

## Atualizar a versão anterior

1. Extraia o ZIP em uma pasta nova.
2. Encerre o servidor antigo com Control+C no Terminal.
3. Na nova pasta, abra `INICIAR-MAC.command` e mantenha o Terminal aberto. O banner deve mostrar extensão 1.3.2 e motor web 0.10.1.
4. Copie o conteúdo da nova pasta `extensao` para a pasta `extensao` já carregada no Chrome, substituindo os arquivos antigos.
5. Abra `chrome://extensions`, clique em **Recarregar** no cartão Site Seguro e confira a versão 1.3.2. Feche e reabra o popup em um site público.

A extensão 1.3.2 é compatível com os servidores das versões 1.3.0 e 1.3.1. Para atualizar também a página web, inicie o servidor deste pacote conforme as etapas acima.

Se você configurou as chaves por `export` no Terminal integrado do VS Code, inicie o novo servidor no mesmo terminal, abrindo a nova pasta no VS Code e executando:

```bash
python3 backend/app.py
```

Ao fechar esse terminal, será necessário definir novamente as variáveis. Abrir `INICIAR-MAC.command` pelo Finder não herda automaticamente as variáveis definidas no terminal do VS Code.

## Primeira instalação

1. Extraia o ZIP e execute `INICIAR-MAC.command`. Se o Mac restringir a abertura, no Terminal da pasta extraída execute `python3 backend/app.py`.
2. No Chrome, abra `chrome://extensions`, ative **Modo do desenvolvedor** e clique em **Carregar sem compactação**.
3. Selecione a subpasta `extensao`, onde está `manifest.json`. Fixe Site Seguro no menu de quebra-cabeça.
4. Abra um site público, clique na extensão e depois em **Analisar site**.

A versão web está em http://127.0.0.1:8765/. O rodapé da extensão abre essa página. Para mudar o link quando o site estiver publicado, configure `PUBLIC_SITE_URL` com o endereço HTTPS real em `extensao/config.js` e recarregue a extensão. Isso muda o link; a análise continua usando o servidor local.

## Como interpretar

A pontuação do link considera controles técnicos e evidências de risco. Verde indica 80–100, amarelo 50–79 e vermelho 0–49. A classificação e os motivos aparecem em texto. Uma detecção relevante de uma fonte de reputação limita a nota; HTTPS válido não elimina o alerta. A pontuação é heurística, não é probabilidade estatística nem confirmação de identidade oficial.

A extensão mostra a classificação, a pontuação e até duas razões, com largura mínima de 420 pixels. O site mantém cobertura técnica, cobertura de dados e tópicos verificados; detalhes adicionais das fontes aparecem quando há evidência relevante. Cobertura mede o alcance das consultas, não a precisão estatística.

## Política inicial para fontes

- Google Safe Browsing: correspondência de ameaça limita a nota a 10.
- URLhaus: URL exata com registro ativo limita a 10. Um registro somente no domínio ou histórico recebe tratamento contextual.
- VirusTotal: 3 ou mais motores maliciosos em análise recente limitam a 10; 1 ou 2 maliciosos limitam a 39; somente classificações suspeitas limitam a 69.
- Registro histórico, sem data de análise confirmada ou relacionado somente ao hostname gera atenção contextual, com limite de 79, salvo outro sinal mais grave.
- Domínio recente e sinais fracos geram atenção; combinações relevantes e falhas de conexão podem limitar mais a nota.

A política de recência do VirusTotal usa 90 dias. As contagens são sinais heurísticos, não uma prova infalível de fraude; os mecanismos podem compartilhar dados. Quando há vários alertas, prevalece o limite mais restritivo. A ausência de detecção em uma lista não comprova segurança.

A classificação indica a fonte, a categoria quando informada, o escopo e a orientação apropriada. Data da consulta e data da análise de uma fonte são informações diferentes. Se a fonte não informar a categoria ou data, a ferramenta não inventa esses dados.

## Fontes de reputação e privacidade

Para ativar as consultas, defina as variáveis `SAFE_BROWSING_KEY`, `VIRUSTOTAL_KEY` e `URLHAUS_AUTH_KEY` no ambiente antes de iniciar o servidor. Cada chave é obtida com seu respectivo provedor. Sem as chaves, as outras verificações continuam funcionando, mas essas fontes ficam desconhecidas. A ferramenta não envia URLs para iniciar novas varreduras automaticamente.

A análise só começa quando o usuário clica. A extensão usa `activeTab` e `storage`, sem acesso ao histórico ou injeção de scripts; guarda apenas o último resultado na sessão do Chrome por até 5 minutos.

URLs com query, parâmetros de caminho ou padrões comuns de dados privados têm consultas externas restringidas; para algumas delas pode ser consultado apenas o hostname no URLhaus. Esse filtro não reconhece todos os possíveis dados sensíveis: evite analisar links pessoais, com senhas ou tokens. Não há histórico de URLs em disco. A base de avaliações armazena apenas feedback sobre a ferramenta.

São preservados TLS, bloqueio de destinos privados/reservados, validação e conexão ao IP público em cada requisição/redirecionamento, prazos, limites de bytes e saltos. O projeto não executa JavaScript nem envia formulários ao destino. Navegador isolado e calibração estatística com amostra representativa são etapas futuras. Antes de uso comercial, confira termos, cotas e custos dos provedores.

A Public Suffix List está em `backend/data/public_suffix_list.dat`, obtida de https://publicsuffix.org/list/public_suffix_list.dat, snapshot 2026-11-06; a licença MPL 2.0 permanece no arquivo. O catálogo de marcas é limitado e não confirma identidade.

## Testes

Na pasta principal:

```bash
python3 -m unittest discover -s tests -v
node --test tests/test_common.cjs tests/test_worker.cjs tests/test_popup.cjs
```

Na pasta `backend`:

```bash
python3 -m unittest discover -s tests -v
node --test tests/test_frontend.cjs
```

Consulte `VALIDACAO.txt`. A pasta `evidencias` contém registros da validação anterior da versão 1.3.0. Os testes de reputação usam respostas simuladas quando não há chaves; a prévia do popup usa uma API Chrome simulada. A extensão não foi instalada no seu perfil durante esta entrega.

## Solução de problemas

- **Servidor antigo/incompatível ou porta 8765 ocupada:** encerre a cópia antiga e execute o `backend/app.py` deste pacote.
- **Página não compatível:** use um site público HTTP/HTTPS; `chrome://`, `file://` e destinos internos são bloqueados.
- **Certificados do Python:** execute `python3 backend/server.py --diagnostico`; não desative a validação TLS.

O ID de desenvolvimento permanece `bgiddmnnjlokenfldakmgookikhfmmfa`. O `key` no manifesto é público e mantém essa identidade; não é uma credencial.
