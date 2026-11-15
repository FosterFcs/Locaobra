/* ==========================================================
   LocaObra — servidor multiempresa (Cloudflare Worker + D1)
   Várias locadoras no mesmo banco. Cada linha tem empresa_id e
   toda consulta é filtrada pela empresa de quem está logado.
   Binding obrigatório: DB (banco D1 "locaobra-db").
   ========================================================== */

// Colunas que o app pode gravar em cada tabela. empresa_id e id
// nunca vêm do navegador: o servidor é quem define.
const TABELAS = {
  clientes: ['tipo_pessoa','nome','documento','telefone','email','endereco','cidade','observacoes','status'],
  ferramentas: ['codigo','nome','categoria','foto_url','valor_diaria','valor_semanal','valor_mensal','valor_reposicao','quantidade_total','quantidade_disponivel','status','observacoes'],
  locacoes: ['cliente_id','data_retirada','data_devolucao_prevista','data_devolucao_real','tipo_cobranca','valor_total','valor_caucao','valor_multa','status','observacoes'],
  itens_locacao: ['locacao_id','ferramenta_id','quantidade','valor_unitario','subtotal'],
  pagamentos: ['locacao_id','tipo','valor','forma_pagamento','data_pagamento','observacoes']
};

// Referências que precisam pertencer à mesma empresa
const REFERENCIAS = {
  locacoes: { cliente_id: 'clientes' },
  itens_locacao: { locacao_id: 'locacoes', ferramenta_id: 'ferramentas' },
  pagamentos: { locacao_id: 'locacoes' }
};

const CAMPOS_EMPRESA = ['nome','cnpj','telefone','email','endereco','cidade','cor_primaria','logo'];
const CAMPOS_EMPRESA_PUBLICOS = 'id, nome, cnpj, telefone, email, endereco, cidade, cor_primaria, logo, plano, teste_ate';
const DIAS_TESTE = 14;
const SESSAO_DIAS = 30;
const PBKDF2_ITERACOES = 100000; // máximo aceito pelo Workers

/* ---------------- utilidades ---------------- */
function corsHeaders(origin){
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}
function json(data, status, origin){
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) }
  });
}
class Erro extends Error { constructor(status, msg){ super(msg); this.status = status; } }
const uuid = () => crypto.randomUUID();
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,'0')).join('');
const emailValido = e => typeof e === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 160;
const normEmail = e => String(e || '').trim().toLowerCase();

async function pbkdf2(senha, saltHex, iteracoes){
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(senha), 'PBKDF2', false, ['deriveBits']);
  const salt = new Uint8Array(saltHex.match(/../g).map(h => parseInt(h, 16)));
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: iteracoes, hash: 'SHA-256' }, key, 256);
  return hex(bits);
}
async function gerarHashSenha(senha){
  const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
  const h = await pbkdf2(senha, salt, PBKDF2_ITERACOES);
  return `pbkdf2$${PBKDF2_ITERACOES}$${salt}$${h}`;
}
function iguais(a, b){
  if(a.length !== b.length) return false;
  let dif = 0;
  for(let i = 0; i < a.length; i++) dif |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return dif === 0;
}
async function conferirSenha(senha, armazenado){
  const partes = String(armazenado).split('$');
  if(partes[0] === 'pbkdf2'){
    const [, it, salt, h] = partes;
    if(!salt || !h) return false;
    return iguais(await pbkdf2(senha, salt, Number(it)), h);
  }
  if(partes[0] === 'sha256'){
    // formato antigo (sistemas migrados): SHA-256(salt + senha). Trocado por PBKDF2 no login.
    const [, salt, h] = partes;
    if(!salt || !h) return false;
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(salt + senha));
    return iguais(hex(buf), h);
  }
  return false;
}
function validarSenha(s){
  if(typeof s !== 'string' || s.length < 8) throw new Erro(400, 'A senha deve ter ao menos 8 caracteres');
}

async function criarSessao(env, usuarioId, empresaId){
  const token = hex(crypto.getRandomValues(new Uint8Array(32)));
  const expira = new Date(Date.now() + SESSAO_DIAS * 86400000).toISOString();
  await env.DB.prepare('INSERT INTO sessions (token, usuario_id, empresa_id, expira_em) VALUES (?1,?2,?3,?4)')
    .bind(token, usuarioId, empresaId, expira).run();
  return token;
}

async function sessao(request, env){
  const token = (request.headers.get('Authorization') || '').replace('Bearer ', '').trim();
  if(!token) throw new Erro(401, 'Não autenticado');
  const s = await env.DB.prepare(
    `SELECT s.expira_em, u.id AS usuario_id, u.email, u.nome, u.papel, u.empresa_id, e.plano
       FROM sessions s JOIN usuarios u ON u.id = s.usuario_id JOIN empresas e ON e.id = u.empresa_id
      WHERE s.token = ?1`
  ).bind(token).first();
  if(!s) throw new Erro(401, 'Não autenticado');
  if(new Date(s.expira_em) < new Date()){
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?1').bind(token).run();
    throw new Erro(401, 'Sessão expirada');
  }
  return { ...s, token };
}
function exigirAdmin(s){ if(s.papel !== 'admin') throw new Erro(403, 'Apenas administradores podem fazer isso'); }
function exigirAtiva(s){ if(s.plano === 'suspenso') throw new Erro(402, 'Conta suspensa. Fale com o suporte para reativar.'); }

async function empresaPublica(env, empresaId){
  return env.DB.prepare(`SELECT ${CAMPOS_EMPRESA_PUBLICOS} FROM empresas WHERE id = ?1`).bind(empresaId).first();
}

async function conferirReferencias(env, tabela, item, empresaId){
  const refs = REFERENCIAS[tabela] || {};
  for(const [col, alvo] of Object.entries(refs)){
    if(item[col] === undefined) continue;
    const ok = await env.DB.prepare(`SELECT 1 AS ok FROM ${alvo} WHERE id = ?1 AND empresa_id = ?2`).bind(item[col], empresaId).first();
    if(!ok) throw new Erro(400, `Referência inválida: ${col}`);
  }
}

function traduzErroSQL(e){
  const m = String(e && e.message || e);
  if(m.includes('UNIQUE') && m.includes('ferramentas')) return new Erro(409, 'Já existe uma ferramenta com esse código');
  if(m.includes('UNIQUE') && m.includes('usuarios')) return new Erro(409, 'Já existe um usuário com esse e-mail');
  if(m.includes('FOREIGN KEY')) return new Erro(409, 'Não é possível excluir: o registro está ligado a locações ou pagamentos');
  if(m.includes('CHECK')) return new Erro(409, 'Estoque insuficiente');
  return e;
}

/* ---------------- rotas ---------------- */
async function rotear(request, env, url){
  const path = url.pathname.replace(/\/+$/, '');
  const method = request.method;
  const corpo = async () => { try { return await request.json(); } catch { throw new Erro(400, 'Corpo inválido'); } };

  // ----- CADASTRO DE NOVA LOCADORA -----
  if(path === '/api/cadastro' && method === 'POST'){
    const b = await corpo();
    const nomeEmpresa = String(b.empresa_nome || '').trim();
    const email = normEmail(b.email);
    if(nomeEmpresa.length < 2) throw new Erro(400, 'Informe o nome da locadora');
    if(!emailValido(email)) throw new Erro(400, 'E-mail inválido');
    validarSenha(b.password);
    const existe = await env.DB.prepare('SELECT 1 FROM usuarios WHERE email = ?1').bind(email).first();
    if(existe) throw new Erro(409, 'Já existe uma conta com esse e-mail');

    const empresaId = uuid(), usuarioId = uuid();
    const testeAte = new Date(Date.now() + DIAS_TESTE * 86400000).toISOString().slice(0,10);
    const hash = await gerarHashSenha(b.password);
    await env.DB.batch([
      env.DB.prepare('INSERT INTO empresas (id, nome, telefone, email, cidade, teste_ate) VALUES (?1,?2,?3,?4,?5,?6)')
        .bind(empresaId, nomeEmpresa, b.telefone || null, email, b.cidade || null, testeAte),
      env.DB.prepare('INSERT INTO usuarios (id, empresa_id, email, nome, papel, senha_hash) VALUES (?1,?2,?3,?4,?5,?6)')
        .bind(usuarioId, empresaId, email, b.nome || null, 'admin', hash)
    ]);
    const token = await criarSessao(env, usuarioId, empresaId);
    return [201, { token, user: { email, nome: b.nome || null, papel: 'admin' }, empresa: await empresaPublica(env, empresaId) }];
  }

  // ----- LOGIN / LOGOUT / SESSÃO -----
  if(path === '/api/login' && method === 'POST'){
    const b = await corpo();
    const email = normEmail(b.email);
    if(!email || !b.password) throw new Erro(400, 'E-mail e senha obrigatórios');
    const u = await env.DB.prepare('SELECT * FROM usuarios WHERE email = ?1').bind(email).first();
    if(!u || !(await conferirSenha(b.password, u.senha_hash))) throw new Erro(401, 'E-mail ou senha inválidos');
    if(!String(u.senha_hash).startsWith('pbkdf2$')){
      // senha veio de um sistema antigo: regrava no formato seguro
      await env.DB.prepare('UPDATE usuarios SET senha_hash = ?1 WHERE id = ?2').bind(await gerarHashSenha(b.password), u.id).run();
    }
    await env.DB.prepare('DELETE FROM sessions WHERE expira_em < ?1').bind(new Date().toISOString()).run();
    const token = await criarSessao(env, u.id, u.empresa_id);
    return [200, { token, user: { email: u.email, nome: u.nome, papel: u.papel }, empresa: await empresaPublica(env, u.empresa_id) }];
  }
  if(path === '/api/logout' && method === 'POST'){
    const token = (request.headers.get('Authorization') || '').replace('Bearer ', '').trim();
    if(token) await env.DB.prepare('DELETE FROM sessions WHERE token = ?1').bind(token).run();
    return [200, { ok: true }];
  }

  const s = await sessao(request, env); // daqui para baixo, só logado

  if(path === '/api/me' && method === 'GET'){
    return [200, { email: s.email, nome: s.nome, papel: s.papel, empresa: await empresaPublica(env, s.empresa_id) }];
  }

  if(path === '/api/senha' && method === 'POST'){
    const b = await corpo();
    const u = await env.DB.prepare('SELECT senha_hash FROM usuarios WHERE id = ?1').bind(s.usuario_id).first();
    if(!(await conferirSenha(b.atual || '', u.senha_hash))) throw new Erro(400, 'Senha atual incorreta');
    validarSenha(b.nova);
    await env.DB.batch([
      env.DB.prepare('UPDATE usuarios SET senha_hash = ?1 WHERE id = ?2').bind(await gerarHashSenha(b.nova), s.usuario_id),
      env.DB.prepare('DELETE FROM sessions WHERE usuario_id = ?1 AND token <> ?2').bind(s.usuario_id, s.token)
    ]);
    return [200, { ok: true }];
  }

  // ----- DADOS DA EMPRESA (marca, contato) -----
  if(path === '/api/empresa'){
    if(method === 'GET') return [200, await empresaPublica(env, s.empresa_id)];
    if(method === 'PATCH'){
      exigirAdmin(s);
      const b = await corpo();
      const campos = CAMPOS_EMPRESA.filter(c => b[c] !== undefined);
      if(!campos.length) throw new Erro(400, 'Nada para atualizar');
      if(b.nome !== undefined && String(b.nome).trim().length < 2) throw new Erro(400, 'Nome muito curto');
      if(b.cor_primaria !== undefined && !/^#[0-9a-fA-F]{6}$/.test(b.cor_primaria)) throw new Erro(400, 'Cor inválida (use #RRGGBB)');
      if(b.logo !== undefined && b.logo !== null){
        if(!/^data:image\/(png|jpeg|webp|svg\+xml);base64,/.test(b.logo)) throw new Erro(400, 'Logo deve ser PNG, JPG, WEBP ou SVG');
        if(b.logo.length > 350000) throw new Erro(400, 'Logo muito grande (máx. ~250 KB)');
      }
      const sets = campos.map((c,i) => `${c} = ?${i+1}`).join(', ');
      await env.DB.prepare(`UPDATE empresas SET ${sets} WHERE id = ?${campos.length + 1}`)
        .bind(...campos.map(c => b[c]), s.empresa_id).run();
      return [200, await empresaPublica(env, s.empresa_id)];
    }
  }

  // ----- USUÁRIOS DA EMPRESA -----
  if(path === '/api/usuarios'){
    if(method === 'GET'){
      const { results } = await env.DB.prepare('SELECT id, email, nome, papel, criado_em FROM usuarios WHERE empresa_id = ?1 ORDER BY criado_em ASC')
        .bind(s.empresa_id).all();
      return [200, results];
    }
    if(method === 'POST'){
      exigirAdmin(s); exigirAtiva(s);
      const b = await corpo();
      const email = normEmail(b.email);
      if(!emailValido(email)) throw new Erro(400, 'E-mail inválido');
      validarSenha(b.password);
      const papel = b.papel === 'admin' ? 'admin' : 'operador';
      const novoId = uuid();
      try{
        await env.DB.prepare('INSERT INTO usuarios (id, empresa_id, email, nome, papel, senha_hash) VALUES (?1,?2,?3,?4,?5,?6)')
          .bind(novoId, s.empresa_id, email, b.nome || null, papel, await gerarHashSenha(b.password)).run();
      }catch(e){ throw traduzErroSQL(e); }
      return [201, { id: novoId, email, nome: b.nome || null, papel }];
    }
  }
  const mUser = path.match(/^\/api\/usuarios\/([a-zA-Z0-9-]+)$/);
  if(mUser && method === 'DELETE'){
    exigirAdmin(s);
    const alvo = await env.DB.prepare('SELECT id, papel FROM usuarios WHERE id = ?1 AND empresa_id = ?2').bind(mUser[1], s.empresa_id).first();
    if(!alvo) throw new Erro(404, 'Usuário não encontrado');
    if(alvo.id === s.usuario_id) throw new Erro(400, 'Você não pode excluir o seu próprio usuário');
    await env.DB.batch([
      env.DB.prepare('DELETE FROM sessions WHERE usuario_id = ?1').bind(alvo.id),
      env.DB.prepare('DELETE FROM usuarios WHERE id = ?1 AND empresa_id = ?2').bind(alvo.id, s.empresa_id)
    ]);
    return [200, { ok: true }];
  }

  // ----- DEVOLUÇÃO (tudo de uma vez no servidor) -----
  const mDev = path.match(/^\/api\/locacoes\/([a-zA-Z0-9-]+)\/devolver$/);
  if(mDev && method === 'POST'){
    exigirAtiva(s);
    const b = await (async () => { try { return await request.json(); } catch { return {}; } })();
    const loc = await env.DB.prepare('SELECT * FROM locacoes WHERE id = ?1 AND empresa_id = ?2').bind(mDev[1], s.empresa_id).first();
    if(!loc) throw new Erro(404, 'Locação não encontrada');
    if(loc.status === 'devolvida') throw new Erro(409, 'Esta locação já foi devolvida');
    const hoje = /^\d{4}-\d{2}-\d{2}$/.test(b.data_devolucao || '') ? b.data_devolucao : new Date().toISOString().slice(0,10);
    const diasAtraso = Math.max(0, Math.round((Date.parse(hoje) - Date.parse(loc.data_devolucao_prevista)) / 86400000));
    const { results: itens } = await env.DB.prepare(
      `SELECT i.ferramenta_id, i.quantidade, f.valor_diaria FROM itens_locacao i
         JOIN ferramentas f ON f.id = i.ferramenta_id WHERE i.locacao_id = ?1 AND i.empresa_id = ?2`
    ).bind(loc.id, s.empresa_id).all();
    const multa = diasAtraso * itens.reduce((t, i) => t + (i.valor_diaria || 0) * (i.quantidade || 0), 0);

    const ops = [
      env.DB.prepare(`UPDATE locacoes SET status = 'devolvida', data_devolucao_real = ?1, valor_multa = ?2 WHERE id = ?3 AND empresa_id = ?4 AND status <> 'devolvida'`)
        .bind(hoje, multa, loc.id, s.empresa_id),
      ...itens.map(i => env.DB.prepare(
        'UPDATE ferramentas SET quantidade_disponivel = MIN(quantidade_total, quantidade_disponivel + ?1) WHERE id = ?2 AND empresa_id = ?3'
      ).bind(i.quantidade, i.ferramenta_id, s.empresa_id))
    ];
    if(multa > 0) ops.push(env.DB.prepare(
      'INSERT INTO pagamentos (id, empresa_id, locacao_id, tipo, valor, observacoes) VALUES (?1,?2,?3,?4,?5,?6)'
    ).bind(uuid(), s.empresa_id, loc.id, 'multa', multa, `Multa por ${diasAtraso} dia(s) de atraso`));
    await env.DB.batch(ops);
    return [200, { ok: true, dias_atraso: diasAtraso, valor_multa: multa, data_devolucao_real: hoje }];
  }

  // ----- CRUD GENÉRICO, SEMPRE FILTRADO PELA EMPRESA -----
  const m = path.match(/^\/api\/([a-z_]+)(?:\/([a-zA-Z0-9-]+))?$/);
  if(m && TABELAS[m[1]]){
    const tabela = m[1], id = m[2], colunas = TABELAS[tabela];

    if(method === 'GET' && !id){
      let sql = `SELECT * FROM ${tabela} WHERE empresa_id = ?1`;
      const order = url.searchParams.get('order');
      const dir = url.searchParams.get('dir') === 'asc' ? 'ASC' : 'DESC';
      if(order && (colunas.includes(order) || order === 'criado_em' || order === 'numero')) sql += ` ORDER BY ${order} ${dir}`;
      const { results } = await env.DB.prepare(sql).bind(s.empresa_id).all();
      return [200, results];
    }

    if(method === 'POST' && !id){
      exigirAtiva(s);
      const body = await corpo();
      const lista = Array.isArray(body) ? body : [body];
      if(lista.length > 200) throw new Erro(400, 'Máximo de 200 registros por envio');
      const criados = [];
      for(const item of lista){
        await conferirReferencias(env, tabela, item, s.empresa_id);
        const novoId = uuid();
        const presentes = colunas.filter(c => item[c] !== undefined);
        const nomes = ['id', 'empresa_id', ...presentes];
        const valores = [novoId, s.empresa_id, ...presentes.map(c => item[c])];

        if(tabela === 'locacoes'){
          // numeração por empresa, atômica (sem número repetido)
          const r = await env.DB.prepare('UPDATE empresas SET proximo_numero = proximo_numero + 1 WHERE id = ?1 RETURNING proximo_numero')
            .bind(s.empresa_id).first();
          nomes.push('numero'); valores.push(r.proximo_numero - 1);
        }
        const insert = env.DB.prepare(`INSERT INTO ${tabela} (${nomes.join(',')}) VALUES (${nomes.map((_,i) => `?${i+1}`).join(',')})`).bind(...valores);

        try{
          if(tabela === 'itens_locacao'){
            // baixa de estoque junto com o item; falha se não houver quantidade
            const qtd = Number(item.quantidade || 1);
            if(!(qtd > 0)) throw new Erro(400, 'Quantidade inválida');
            const f = await env.DB.prepare('SELECT nome, quantidade_disponivel FROM ferramentas WHERE id = ?1 AND empresa_id = ?2').bind(item.ferramenta_id, s.empresa_id).first();
            if(!f || f.quantidade_disponivel < qtd) throw new Erro(409, `Estoque insuficiente: ${f ? f.nome : 'ferramenta'}`);
            await env.DB.batch([
              insert,
              env.DB.prepare('UPDATE ferramentas SET quantidade_disponivel = quantidade_disponivel - ?1 WHERE id = ?2 AND empresa_id = ?3')
                .bind(qtd, item.ferramenta_id, s.empresa_id)
            ]);
          } else {
            await insert.run();
          }
        }catch(e){ throw traduzErroSQL(e); }
        criados.push(await env.DB.prepare(`SELECT * FROM ${tabela} WHERE id = ?1`).bind(novoId).first());
      }
      return [201, Array.isArray(body) ? criados : criados[0]];
    }

    if(method === 'PATCH' && id){
      exigirAtiva(s);
      const body = await corpo();
      const presentes = colunas.filter(c => body[c] !== undefined);
      if(!presentes.length) throw new Erro(400, 'Nada para atualizar');
      await conferirReferencias(env, tabela, body, s.empresa_id);
      const sets = presentes.map((c,i) => `${c} = ?${i+1}`).join(', ');
      let r;
      try{
        r = await env.DB.prepare(`UPDATE ${tabela} SET ${sets} WHERE id = ?${presentes.length + 1} AND empresa_id = ?${presentes.length + 2}`)
          .bind(...presentes.map(c => body[c]), id, s.empresa_id).run();
      }catch(e){ throw traduzErroSQL(e); }
      if(!r.meta || !r.meta.changes) throw new Erro(404, 'Registro não encontrado');
      return [200, await env.DB.prepare(`SELECT * FROM ${tabela} WHERE id = ?1`).bind(id).first()];
    }

    if(method === 'DELETE' && id){
      exigirAtiva(s);
      let r;
      try{
        r = await env.DB.prepare(`DELETE FROM ${tabela} WHERE id = ?1 AND empresa_id = ?2`).bind(id, s.empresa_id).run();
      }catch(e){ throw traduzErroSQL(e); }
      if(!r.meta || !r.meta.changes) throw new Erro(404, 'Registro não encontrado');
      return [200, { ok: true }];
    }
  }

  throw new Erro(404, 'Rota não encontrada');
}

export default {
  async fetch(request, env){
    const origin = request.headers.get('Origin') || '*';
    if(request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders(origin) });
    try{
      const [status, data] = await rotear(request, env, new URL(request.url));
      return json(data, status, origin);
    }catch(e){
      if(e instanceof Erro) return json({ message: e.message }, e.status, origin);
      console.error(e);
      return json({ message: 'Erro no servidor' }, 500, origin);
    }
  }
};
