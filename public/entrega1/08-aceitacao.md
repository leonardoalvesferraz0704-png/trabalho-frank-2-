# Critérios de aceitação

- [x] o site é servido pelo endereço atribuído à equipe.
  Observação: a conta Cloudflare usada não tem mais acesso ao Pages clássico (Cloudflare unificou Pages dentro de Workers). O projeto foi adaptado para Cloudflare Workers, publicado em `https://trabalho-frank-2.leonardoalvesferraz0704.workers.dev`, em vez de um endereço `.pages.dev`. O professor foi avisado dessa adaptação. O contrato de segurança do roteiro (PKCE S256, state, nonce, sessões opacas no D1, revogação do GitHub, validação do id_token do Google) foi mantido integralmente, implementado em `src/worker.js`.
- [x] os arquivos estáticos e as Functions compartilham a mesma origem.
  Confirmado: a pasta `public` e a lógica dinâmica (`src/worker.js`) são servidas pelo mesmo domínio `workers.dev`, sem CORS entre elas.
- [x] o projeto foi publicado por integração com GitHub.
  O projeto Cloudflare Workers está conectado ao repositório GitHub, com deploy automático a cada commit em `main`.
- [x] a equipe não instalou nem executou Node.js, npm, npx ou Wrangler.
  Todo o trabalho foi feito pelo navegador, incluindo a criação e edição de arquivos no GitHub.
- [x] cada provedor usa uma URL de retorno própria e exata.
  `/oauth/callback/google` e `/oauth/callback/github`, cadastradas exatamente assim no Google Cloud Console e na OAuth App do GitHub.
- [x] os pedidos de autorização usam código e PKCE S256.
  Confirmado no código (`response_type=code`, `code_challenge_method=S256`) e nas evidências 05 e 06 (cabeçalhos do início do login).
- [x] a Function apresenta o Client Secret correto somente na troca de tokens.
  No código, `GOOGLE_CLIENT_SECRET` e `GITHUB_CLIENT_SECRET` só aparecem em `handleCallback`, na troca do código por token e, no caso do GitHub, na revogação da autorização. Não aparecem na URL de início do login nem em nenhuma resposta ao navegador.
- [x] o retorno recusa uma transação ausente, expirada, alterada ou reutilizada.
  Testado nos casos 1, 2 e 3 do arquivo `07-testes-falha.md`: cookie de transação ausente, `state` alterado e reutilização da transação foram todos recusados.
- [x] o id_token do Google só produz uma sessão depois da validação criptográfica e semântica.
  Confirmado no código (`validateGoogleIdToken`): verifica assinatura RS256 via JWKS, `iss`, `aud`, `exp`, `iat` e `nonce` antes de criar a sessão.
- [x] o access_token do GitHub é usado somente para consultar /user e a autorização é revogada antes da criação da sessão.
  Confirmado no código: o access_token é usado só na chamada a `https://api.github.com/user` e depois revogado com `DELETE .../grant` antes de qualquer `INSERT` na tabela `sessions`.
- [x] o cookie de sessão é opaco, Secure, HttpOnly, SameSite=Strict e não possui Domain.
  Confirmado no código (`setCookieHeader` com `sameSite: "Strict"`, sem `Domain`) e nas evidências de sessão.
- [x] o D1 guarda o resumo do cookie, não seu valor bruto.
  Confirmado no código: `sha256Hex(sessionId)` é calculado antes de qualquer gravação ou consulta na tabela `sessions`.
- [x] /api/me devolve somente o perfil necessário.
  Confirmado no código (`handleMe`): devolve apenas `issuer`, `subject`, `email` e `displayName`.
- [x] o logout confere Origin, remove a sessão e expira o cookie.
  Confirmado no código (`handleLogout`) e no caso 5 do arquivo `07-testes-falha.md`: uma chamada de outra origem foi recusada com 403.
- [x] um cookie revogado não restaura a sessão.
  Testado no caso 6 do arquivo `07-testes-falha.md`: o valor do cookie de uma sessão já encerrada foi reenviado ao servidor e a resposta foi 401 com `{"error":"sessao invalida"}`.
- [x] tokens e segredos não aparecem no HTML, nas URLs salvas, no armazenamento Web ou nos registros.
  Confirmado: Local Storage e Session Storage do site estão vazios (nenhuma chave salva). O código não grava tokens, códigos, cookies, state ou nonce em nenhum registro. Os Client Secrets só existem como segredos criptografados no painel da Cloudflare.
- [x] a dupla consegue explicar por que os arquivos estáticos permanecem públicos.
  Confirmado pela dupla: o roteiro não torna privados os arquivos da pasta `public`; qualquer arquivo estático publicado continua acessível por sua URL. A sessão protege somente as rotas dinâmicas (`/api/*`), que checam o cookie antes de responder. Ocultar um link no HTML depois de consultar `/api/me` não torna o arquivo de destino privado.
- [ ] as sessões administrativas foram encerradas no computador compartilhado.
  Não se aplica: o trabalho foi feito em computador de uso pessoal, não compartilhado.

## Assinatura da dupla

- Leonardo Alves Ferraz
- Guilherme Cracco Lichtenfels

Data: 20/09/2026
