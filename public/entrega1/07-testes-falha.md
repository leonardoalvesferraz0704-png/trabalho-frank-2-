# Testes de falha

Todos os testes foram executados na implantação de produção, em `https://trabalho-frank-2.leonardoalvesferraz0704.workers.dev`. Valores sensíveis (cookies, `code`, `state`, `code_challenge`, URLs de retorno com valores transitórios) foram omitidos e substituídos por [REMOVIDO] quando necessário.

## Caso 1: retorno sem cookie temporário

- **Preparação:** em uma janela comum, iniciei o login com GitHub e parei na tela de autorização do provedor, sem clicar em nada. Copiei a URL de autorização e abri uma janela privativa, que não possuía o cookie `__Host-oauth-tx`.
- **Pedido enviado:** na janela privativa, colei a URL de autorização e concluí a autorização no GitHub. O navegador enviou `GET /oauth/callback/github?code=[REMOVIDO]&state=[REMOVIDO]` sem o cookie temporário.
- **Resultado esperado:** a rota de retorno recusa a resposta e não cria sessão.
- **Resultado observado:** a rota respondeu com a mensagem `Cookie de transacao ausente.`. Em seguida, consultei `/api/me` na mesma janela privativa e recebi `{"error":"sem sessao"}`. Nenhuma sessão foi criada.

## Caso 2: state alterado

- **Preparação:** em uma janela comum, iniciei outro login com GitHub e parei na tela de autorização, antes de autorizar. Na barra de endereço, troquei um único caractere do valor do parâmetro `state`.
- **Pedido enviado:** com a URL modificada, autorizei o acesso no GitHub. O navegador enviou `GET /oauth/callback/github?code=[REMOVIDO]&state=[REMOVIDO]` com o `state` diferente do original. A URL modificada não foi guardada, pois contém valores transitórios.
- **Resultado esperado:** a rota de retorno recusa a resposta antes de trocar o código.
- **Resultado observado:** a rota respondeu com a mensagem `state invalido.` e o login não foi concluído.

## Caso 3: reutilização da transação

- **Preparação:** com o painel Network aberto e Keep log ativado, concluí um login com GitHub com sucesso. Depois, localizei a requisição `github?code=...` da rota de retorno e usei Copy URL.
- **Pedido enviado:** abri a URL copiada em uma nova aba, repetindo `GET /oauth/callback/github?code=[REMOVIDO]&state=[REMOVIDO]`.
- **Resultado esperado:** a transação já foi removida e a repetição falha.
- **Resultado observado:** a rota respondeu com a mensagem `Cookie de transacao ausente.`. A mensagem indica que o cookie temporário já havia sido limpo quando o primeiro retorno terminou, e por isso a repetição foi recusada logo na verificação do cookie. Nenhuma nova sessão foi criada.

## Caso 4: sessão expirada

- **Preparação:** com uma sessão ativa no navegador, abri o console do banco D1 `oauth-sessions-frank`.
- **Pedido enviado:** executei no console `UPDATE sessions SET expires_at = 0;`. Depois, recarreguei a página e consultei `GET /api/me`.
- **Resultado esperado:** `/api/me` responde 401.
- **Resultado observado:** o console D1 informou `This query successfully executed.`. Em seguida, `GET /api/me` respondeu `401 Unauthorized` com o corpo `{"error":"sem sessao"}` e `Cache-Control: no-store`.

## Caso 5: origem inválida na saída

- **Preparação:** com uma sessão válida aberta na URL do projeto, abri uma aba com `https://example.com` e, no console do navegador dessa aba, preparei uma chamada de logout entre origens.
- **Pedido enviado:** executei `fetch("https://trabalho-frank-2.leonardoalvesferraz0704.workers.dev/oauth/logout", { method: "POST", credentials: "include" });` a partir de `https://example.com`. Esse comando foi executado mais de uma vez, e todas as tentativas tiveram o mesmo resultado.
- **Resultado esperado:** a rota recusa a operação e a sessão original permanece válida.
- **Resultado observado:** o console mostrou `POST .../oauth/logout` com `403 (Forbidden)`, acompanhado de um erro de CORS emitido pelo navegador. Ao voltar para a aba do projeto e recarregá-la, a página continuou exibindo a sessão ativa.

## Caso 6: reutilização do cookie revogado

- **Preparação:** em uma sessão exclusiva do laboratório, copiei temporariamente o valor do cookie `__Host-session` pelas ferramentas de desenvolvimento e guardei-o em um arquivo de texto temporário. Depois, executei o logout, que respondeu `{"ok":true}`. Tentei recriar o cookie manualmente na tabela de cookies do navegador, mas o Chrome não o manteve, porque cookies com prefixo `__Host-` não são aceitos quando criados dessa forma. Por isso, enviei o valor antigo diretamente no cabeçalho `Cookie` com o `curl`.
- **Pedido enviado:** `curl -i https://trabalho-frank-2.leonardoalvesferraz0704.workers.dev/api/me -H "Cookie: __Host-session=[REMOVIDO]"`.
- **Resultado esperado:** como a linha da sessão foi removida do D1 no logout, a resposta é 401.
- **Resultado observado:** a resposta foi `HTTP/1.1 401 Unauthorized`, com `Cache-Control: no-store` e o corpo `{"error":"sessao invalida"}`. Essa mensagem é diferente de `sem sessao`, que aparece quando não há cookie, e indica que o cookie chegou ao servidor e foi recusado. A cópia do valor do cookie foi apagada depois do teste.
