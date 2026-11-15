# LocaObra multiempresa — servidor (Cloudflare)

Várias locadoras usam o mesmo sistema. Cada linha do banco tem `empresa_id`,
e o Worker só devolve os dados da empresa de quem está logado.

- App: `app.html` (na raiz do repositório)
- Servidor: `worker/worker.js`
- Banco: `worker/schema.sql`, já aplicado no D1 **locaobra-db**
  (id `7f777e52-7045-4db2-a8db-22356dcbf160`)

## Publicar o Worker (uma vez, pelo painel da Cloudflare)

1. Entre em dash.cloudflare.com → **Workers e Pages** → **Criar** → **Criar Worker**.
2. Nome: `locaobra-worker` → **Implantar**.
3. **Editar código**: apague tudo, cole o conteúdo de `worker/worker.js` e clique em **Implantar**.
4. Volte ao Worker → **Configurações** → **Vinculações** (Bindings) → **Adicionar** → **Banco de dados D1**:
   - Nome da variável: `DB`
   - Banco: `locaobra-db`
5. Salve. O endereço fica `https://locaobra-worker.fosterconstrutora.workers.dev`,
   que é o que o `app.html` já usa.

## Testar

Abra `https://fosterfcs.github.io/Locaobra/app.html` → **Criar conta da minha locadora**.

## O que o servidor garante

- Uma locadora nunca vê, edita ou apaga dados de outra.
- Senhas com PBKDF2 (100 mil iterações), mínimo de 8 caracteres.
- Papéis: **admin** (gerencia usuários e dados da empresa) e **operador**.
- Número do contrato sequencial por empresa, sem repetição.
- Ao gravar um item da locação, o estoque baixa junto; se faltar quantidade, nada é gravado.
- A devolução (status, estoque e multa) é feita de uma vez só.
- Conta nova ganha 14 dias de teste (`plano = 'teste'`). Empresa com `plano = 'suspenso'`
  consegue consultar, mas não gravar.

## Rotas novas

| Rota | Para quê |
| --- | --- |
| `POST /api/cadastro` | cria locadora + usuário admin |
| `GET/PATCH /api/empresa` | dados, cor e logo da locadora |
| `POST /api/senha` | troca a própria senha |
| `POST /api/locacoes/:id/devolver` | devolução completa |

As rotas antigas (`/api/clientes`, `/api/ferramentas` etc.) continuam iguais para o app.
