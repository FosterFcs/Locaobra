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
  locacoes: ['cliente_id','data_retirada','data_devolucao_prevista','data_devolucao_real','tipo_cobranca','valor_total','valor_caucao','valor_multa','status','observacoes','local_entrega_id','endereco_entrega','forma_pagamento'],
  itens_locacao: ['locacao_id','ferramenta_id','quantidade','valor_unitario','subtotal'],
  pagamentos: ['locacao_id','tipo','valor','forma_pagamento','data_pagamento','observacoes'],
  // endereços de entrega / obras de cada cliente
  locais_entrega: ['cliente_id','nome','endereco','bairro','cidade','cep','contato','telefone','observacoes','status']
};

// Referências que precisam pertencer à mesma empresa
const REFERENCIAS = {
  locacoes: { cliente_id: 'clientes', local_entrega_id: 'locais_entrega' },
  itens_locacao: { locacao_id: 'locacoes', ferramenta_id: 'ferramentas' },
  pagamentos: { locacao_id: 'locacoes' },
  locais_entrega: { cliente_id: 'clientes' }
};

const CAMPOS_EMPRESA = ['nome','cnpj','telefone','email','endereco','cidade','cor_primaria','logo','formas_pagamento'];
const CAMPOS_EMPRESA_PUBLICOS = 'id, nome, cnpj, telefone, email, endereco, cidade, cor_primaria, logo, plano, teste_ate, assinatura_plano, assinatura_ciclo, assinatura_status, pago_ate, fatura_url, fundador, preco_travado_ate, pix_modo, pix_chave, pix_tipo, pix_nome, pix_cidade, loc_asaas_env, formas_pagamento';
const DIAS_TESTE = 14; // teste grátis (padrão de mercado: 7 a 15 dias)

/* ---------------- planos e cobrança (Asaas) ---------------- */
const PLANOS = {
  essencial:    { nome: 'Essencial',    usuarios: 2, mensal: 49.90, anual: 478.80 }, // anual = 12 x 39,90
  profissional: { nome: 'Profissional', usuarios: 5, mensal: 89.90, anual: 838.80 }  // anual = 12 x 69,90
};
const USUARIOS_NO_TESTE = 5;
const VAGAS_FUNDADOR = 20;      // primeiras locadoras com preço travado por 12 meses
const DIAS_TOLERANCIA = 3;      // dias de acesso após o vencimento antes de bloquear
const CICLO_ASAAS = { mensal: 'MONTHLY', anual: 'YEARLY' };
const DIAS_CICLO = { mensal: 31, anual: 366 };
const ASAAS_URL = { sandbox: 'https://api-sandbox.asaas.com/v3', production: 'https://api.asaas.com/v3' };
const PAGO = ['RECEIVED', 'CONFIRMED', 'RECEIVED_IN_CASH'];
const ESTORNADO = ['REFUNDED', 'REFUND_REQUESTED', 'REFUND_IN_PROGRESS', 'CHARGEBACK_REQUESTED', 'CHARGEBACK_DISPUTE', 'AWAITING_CHARGEBACK_REVERSAL'];
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
    `SELECT s.expira_em, u.id AS usuario_id, u.email, u.nome, u.papel, u.empresa_id, e.plano, e.teste_ate, e.pago_ate
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
// Datas no fuso de Brasília (YYYY-MM-DD)
function hojeBR(){ return new Date(Date.now() - 3 * 3600000).toISOString().slice(0, 10); }
function somaDias(ymd, dias){ const d = new Date(ymd + 'T12:00:00Z'); d.setUTCDate(d.getUTCDate() + dias); return d.toISOString().slice(0, 10); }
function diasEntre(de, ate){ return Math.round((Date.parse(ate + 'T12:00:00Z') - Date.parse(de + 'T12:00:00Z')) / 86400000); }

// plano: teste (até teste_ate) | assinante (até pago_ate + tolerância) | ativo (liberado manualmente) | suspenso
function situacaoAcesso(e){
  const hoje = hojeBR();
  if(e.plano === 'suspenso') return { liberado: false, motivo: 'Conta suspensa. Fale com o suporte para reativar.' };
  if(e.plano === 'ativo') return { liberado: true };
  if(e.plano === 'assinante'){
    if(e.pago_ate && somaDias(e.pago_ate, DIAS_TOLERANCIA) >= hoje) return { liberado: true };
    return { liberado: false, motivo: 'Sua assinatura está vencida. Pague a fatura em aberto para voltar a registrar.' };
  }
  if(e.teste_ate && e.teste_ate >= hoje) return { liberado: true, dias_teste: diasEntre(hoje, e.teste_ate) };
  return { liberado: false, motivo: 'Seu período de teste terminou. Assine um plano para continuar registrando.' };
}
function exigirAtiva(s){
  const a = situacaoAcesso(s);
  if(!a.liberado) throw new Erro(402, a.motivo + ' Seus dados continuam guardados.');
}
function limiteUsuarios(e){
  if(e.plano === 'ativo') return Infinity;
  if(e.plano === 'assinante') return (PLANOS[e.assinatura_plano] || PLANOS.essencial).usuarios;
  return USUARIOS_NO_TESTE;
}

async function empresaPublica(env, empresaId){
  const e = await env.DB.prepare(`SELECT ${CAMPOS_EMPRESA_PUBLICOS} FROM empresas WHERE id = ?1`).bind(empresaId).first();
  if(!e) return e;
  const a = situacaoAcesso(e);
  return { ...e, acesso_liberado: a.liberado, motivo_bloqueio: a.motivo || null, dias_teste: a.dias_teste ?? null,
           fatura_url: e.assinatura_status === 'ativa' ? null : e.fatura_url };
}

/* ---------------- Asaas ---------------- */
async function asaas(env, metodo, caminho, corpo){
  if(!env.ASAAS_API_KEY) throw new Erro(503, 'Pagamentos ainda não configurados. Fale com o suporte.');
  return asaasCom(env.ASAAS_API_KEY, env.ASAAS_ENV === 'production' ? 'production' : 'sandbox', metodo, caminho, corpo);
}
// chamada ao Asaas com uma chave qualquer (a da Foster Tech ou a de uma locadora)
async function asaasCom(chave, ambiente, metodo, caminho, corpo){
  const base = ASAAS_URL[ambiente === 'production' ? 'production' : 'sandbox'];
  const res = await fetch(base + caminho, {
    method: metodo,
    headers: { 'Content-Type': 'application/json', 'User-Agent': 'LocaObra/1.0', access_token: chave },
    body: corpo ? JSON.stringify(corpo) : undefined
  });
  const dados = await res.json().catch(() => ({}));
  if(!res.ok){
    const msg = dados?.errors?.[0]?.description;
    console.error('Asaas', metodo, caminho, res.status, JSON.stringify(dados));
    throw new Erro(502, msg ? `Asaas: ${msg}` : 'Falha ao falar com o sistema de pagamento. Tente de novo.');
  }
  return dados;
}
function soDigitos(v){ return String(v || '').replace(/\D/g, ''); }
function cpfCnpjValido(v){
  if(v.length === 11){
    if(/^(\d)\1+$/.test(v)) return false;
    const calc = n => { let s = 0; for(let i = 0; i < n; i++) s += Number(v[i]) * (n + 1 - i); const r = (s * 10) % 11; return r === 10 ? 0 : r; };
    return calc(9) === Number(v[9]) && calc(10) === Number(v[10]);
  }
  if(v.length === 14){
    if(/^(\d)\1+$/.test(v)) return false;
    const calc = n => { const w = n === 12 ? [5,4,3,2,9,8,7,6,5,4,3,2] : [6,5,4,3,2,9,8,7,6,5,4,3,2];
      let s = 0; for(let i = 0; i < n; i++) s += Number(v[i]) * w[i]; const r = s % 11; return r < 2 ? 0 : 11 - r; };
    return calc(12) === Number(v[12]) && calc(13) === Number(v[13]);
  }
  return false;
}

// Confere a assinatura no Asaas (fonte da verdade) e atualiza a empresa
async function sincronizarAssinatura(env, empresaId, { forcar = false } = {}){
  const e = await env.DB.prepare('SELECT * FROM empresas WHERE id = ?1').bind(empresaId).first();
  if(!e || !e.assinatura_id || !env.ASAAS_API_KEY) return;
  if(!forcar && e.ultimo_sync && Date.now() - e.ultimo_sync < 15000) return;
  const hoje = hojeBR();
  try{
    const r = await asaas(env, 'GET', `/subscriptions/${e.assinatura_id}/payments?limit=50`);
    const pags = (r.data || []).filter(p => !p.deleted);
    const pagos = pags.filter(p => PAGO.includes(p.status));
    const abertos = pags.filter(p => p.status === 'PENDING' || p.status === 'OVERDUE').sort((a, b) => (a.dueDate < b.dueDate ? -1 : 1));
    const vencido = abertos.find(p => p.status === 'OVERDUE');
    let ate = null;
    for(const p of pagos){ const u = somaDias(p.dueDate || hoje, DIAS_CICLO[e.assinatura_ciclo] || 31); if(!ate || u > ate) ate = u; }
    let status = e.assinatura_status;
    if(status !== 'cancelada'){
      if(ate && ate >= hoje) status = 'ativa';
      else if(vencido) status = 'vencida';
      else if(pags.some(p => ESTORNADO.includes(p.status))) status = 'estornada';
      else if(!ate) status = 'pendente';
    }
    const fatura = abertos[0]?.invoiceUrl || e.fatura_url;
    const plano = ate ? 'assinante' : e.plano;
    await env.DB.prepare('UPDATE empresas SET pago_ate = ?1, assinatura_status = ?2, fatura_url = ?3, plano = ?4, ultimo_sync = ?5 WHERE id = ?6')
      .bind(ate, status, fatura, plano === 'ativo' ? 'ativo' : plano, Date.now(), empresaId).run();
  }catch(err){ console.error('sincronizar falhou', e.assinatura_id, err && err.message); }
}

async function webhookAsaas(request, env){
  const esperado = (env.ASAAS_WEBHOOK_TOKEN || '').trim();
  if(!esperado) throw new Erro(500, 'Webhook não configurado');
  const recebido = (request.headers.get('asaas-access-token') || '').trim();
  if(!iguais(hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(recebido))),
             hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(esperado))))) throw new Erro(401, 'Não autorizado');
  let evt; try { evt = await request.json(); } catch { throw new Erro(400, 'Corpo inválido'); }
  if(evt.id){
    const ja = await env.DB.prepare('SELECT 1 FROM eventos_asaas WHERE id = ?1').bind(evt.id).first();
    if(ja) return { received: true, duplicate: true };
  }
  const subId = evt.payment?.subscription || evt.subscription?.id;
  const e = subId ? await env.DB.prepare('SELECT id, plano, assinatura_ciclo, pago_ate FROM empresas WHERE assinatura_id = ?1').bind(subId).first() : null;
  if(e){
    const p = evt.payment || {};
    switch(evt.event){
      case 'PAYMENT_CONFIRMED':
      case 'PAYMENT_RECEIVED': {
        const ate = somaDias(p.dueDate || hojeBR(), DIAS_CICLO[e.assinatura_ciclo] || 31);
        const novo = !e.pago_ate || ate > e.pago_ate ? ate : e.pago_ate;
        await env.DB.prepare(`UPDATE empresas SET pago_ate = ?1, assinatura_status = 'ativa', plano = CASE WHEN plano = 'ativo' THEN 'ativo' ELSE 'assinante' END WHERE id = ?2`).bind(novo, e.id).run();
        break;
      }
      case 'PAYMENT_CREATED':
        if(p.invoiceUrl) await env.DB.prepare('UPDATE empresas SET fatura_url = ?1 WHERE id = ?2').bind(p.invoiceUrl, e.id).run();
        break;
      case 'PAYMENT_OVERDUE':
        await env.DB.prepare(`UPDATE empresas SET assinatura_status = 'vencida', fatura_url = COALESCE(?1, fatura_url) WHERE id = ?2`).bind(p.invoiceUrl || null, e.id).run();
        break;
      case 'PAYMENT_REFUNDED':
      case 'PAYMENT_CHARGEBACK_REQUESTED':
        await env.DB.prepare(`UPDATE empresas SET assinatura_status = 'estornada', pago_ate = NULL WHERE id = ?1`).bind(e.id).run();
        break;
      case 'SUBSCRIPTION_DELETED':
      case 'SUBSCRIPTION_INACTIVATED':
        await env.DB.prepare(`UPDATE empresas SET assinatura_status = 'cancelada' WHERE id = ?1`).bind(e.id).run();
        break;
    }
  }
  if(evt.id) await env.DB.prepare('INSERT OR IGNORE INTO eventos_asaas (id) VALUES (?1)').bind(evt.id).run();
  return { received: true };
}

async function conferirReferencias(env, tabela, item, empresaId){
  const refs = REFERENCIAS[tabela] || {};
  for(const [col, alvo] of Object.entries(refs)){
    if(item[col] === undefined || item[col] === null || item[col] === '') continue;
    const ok = await env.DB.prepare(`SELECT 1 AS ok FROM ${alvo} WHERE id = ?1 AND empresa_id = ?2`).bind(item[col], empresaId).first();
    if(!ok) throw new Erro(400, `Referência inválida: ${col}`);
  }
}

function traduzErroSQL(e){
  const m = String(e && e.message || e);
  if(m.includes('UNIQUE') && m.includes('ferramentas')) return new Erro(409, 'Já existe uma ferramenta com esse código');
  if(m.includes('UNIQUE') && m.includes('usuarios')) return new Erro(409, 'Já existe um usuário com esse e-mail');
  if(m.includes('FOREIGN KEY')) return new Erro(409, 'Não é possível excluir: o registro está ligado a locações, pagamentos ou locais de entrega');
  if(m.includes('CHECK')) return new Erro(409, 'Estoque insuficiente');
  return e;
}

/* ---------------- Pix da locadora ---------------- */
const b64 = u8 => btoa(String.fromCharCode(...u8));
const deb64 = t => Uint8Array.from(atob(t), c => c.charCodeAt(0));
async function chaveCripto(env){
  if(!env.CRIPTO_CHAVE) throw new Erro(503, 'Recebimento pelo Asaas ainda não habilitado no servidor. Fale com o suporte.');
  const bruto = deb64(env.CRIPTO_CHAVE.trim());
  if(bruto.length !== 32) throw new Erro(500, 'CRIPTO_CHAVE inválida');
  return crypto.subtle.importKey('raw', bruto, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function cifrar(env, texto){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await chaveCripto(env), new TextEncoder().encode(texto));
  return `v1:${b64(iv)}:${b64(new Uint8Array(ct))}`;
}
async function decifrar(env, guardado){
  const [v, iv, ct] = String(guardado || '').split(':');
  if(v !== 'v1') throw new Erro(400, 'Chave do Asaas não configurada');
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: deb64(iv) }, await chaveCripto(env), deb64(ct));
  return new TextDecoder().decode(pt);
}
// Pix com Asaas: incluído no Profissional (e liberado durante o teste e nas contas liberadas pelo suporte)
function asaasPermitido(e){ return e.plano === 'teste' || e.plano === 'ativo' || e.assinatura_plano === 'profissional'; }

// ---- BR Code (Pix copia e cola) estático, padrão EMV do Banco Central ----
function semAcento(t){ return String(t || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toUpperCase().replace(/[^A-Z0-9 ]/g, ' ').replace(/\s+/g, ' ').trim(); }
function campoEMV(id, valor){ const v = String(valor); return id + String(v.length).padStart(2, '0') + v; }
function crc16(t){
  let crc = 0xFFFF;
  for(let i = 0; i < t.length; i++){
    crc ^= t.charCodeAt(i) << 8;
    for(let j = 0; j < 8; j++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xFFFF : (crc << 1) & 0xFFFF;
  }
  return crc.toString(16).toUpperCase().padStart(4, '0');
}
function normalizarChavePix(tipo, chave){
  const c = String(chave || '').trim();
  if(tipo === 'cpf'){ const d = soDigitos(c); if(d.length !== 11 || !cpfCnpjValido(d)) throw new Erro(400, 'CPF da chave Pix inválido'); return d; }
  if(tipo === 'cnpj'){ const d = soDigitos(c); if(d.length !== 14 || !cpfCnpjValido(d)) throw new Erro(400, 'CNPJ da chave Pix inválido'); return d; }
  if(tipo === 'celular'){ let d = soDigitos(c); if(d.length === 10 || d.length === 11) d = '55' + d; if(!/^55\d{10,11}$/.test(d)) throw new Erro(400, 'Celular da chave Pix inválido (use DDD + número)'); return '+' + d; }
  if(tipo === 'email'){ const e = c.toLowerCase(); if(!emailValido(e) || e.length > 77) throw new Erro(400, 'E-mail da chave Pix inválido'); return e; }
  if(tipo === 'aleatoria'){ const a = c.toLowerCase(); if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(a)) throw new Erro(400, 'Chave aleatória inválida'); return a; }
  throw new Erro(400, 'Escolha o tipo da chave Pix');
}
function brcodeEstatico({ chave, nome, cidade, valor, txid, descricao }){
  let conta = campoEMV('00', 'br.gov.bcb.pix') + campoEMV('01', chave);
  const desc = semAcento(descricao).slice(0, 40);
  if(desc && (conta.length + 4 + desc.length) <= 99) conta += campoEMV('02', desc);
  const tx = String(txid || '***').replace(/[^A-Za-z0-9]/g, '').slice(0, 25) || '***';
  let p = campoEMV('00', '01') + campoEMV('26', conta) + campoEMV('52', '0000') + campoEMV('53', '986');
  if(valor > 0) p += campoEMV('54', Number(valor).toFixed(2));
  p += campoEMV('58', 'BR') + campoEMV('59', semAcento(nome).slice(0, 25) || 'LOCADORA') + campoEMV('60', semAcento(cidade).slice(0, 15) || 'BRASIL');
  p += campoEMV('62', campoEMV('05', tx)) + '6304';
  return p + crc16(p);
}

// registra o pagamento uma única vez (a troca de status protege contra repetição)
async function marcarCobrancaPaga(env, c, origem){
  const r = await env.DB.prepare(`UPDATE cobrancas_pix SET status = 'paga', pago_em = ?1 WHERE id = ?2 AND status = 'pendente'`)
    .bind(new Date().toISOString(), c.id).run();
  if(!r.meta || !r.meta.changes) return false;
  await env.DB.prepare('INSERT INTO pagamentos (id, empresa_id, locacao_id, tipo, valor, forma_pagamento, data_pagamento, observacoes) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)')
    .bind(uuid(), c.empresa_id, c.locacao_id, 'pagamento', c.valor, 'pix', hojeBR(), `Pix ${origem}${c.descricao ? ' — ' + c.descricao : ''}`).run();
  return true;
}
async function chaveAsaasLocadora(env, empresaId){
  const e = await env.DB.prepare('SELECT loc_asaas_key, loc_asaas_env FROM empresas WHERE id = ?1').bind(empresaId).first();
  if(!e || !e.loc_asaas_key) throw new Erro(400, 'Conecte a conta Asaas da locadora em Minha empresa');
  return { chave: await decifrar(env, e.loc_asaas_key), ambiente: e.loc_asaas_env };
}
// confere no Asaas da locadora se a cobrança foi paga (reserva, caso o aviso automático falhe)
async function conferirCobrancaAsaas(env, c){
  if(c.modo !== 'asaas' || c.status !== 'pendente' || !c.asaas_id) return;
  if(c.ultimo_check && Date.now() - c.ultimo_check < 8000) return;
  await env.DB.prepare('UPDATE cobrancas_pix SET ultimo_check = ?1 WHERE id = ?2').bind(Date.now(), c.id).run();
  try{
    const { chave, ambiente } = await chaveAsaasLocadora(env, c.empresa_id);
    const p = await asaasCom(chave, ambiente, 'GET', `/payments/${c.asaas_id}`);
    if(PAGO.includes(p.status)) await marcarCobrancaPaga(env, c, 'confirmado pelo Asaas');
    else if(p.deleted || p.status === 'REFUNDED') await env.DB.prepare(`UPDATE cobrancas_pix SET status = 'cancelada' WHERE id = ?1 AND status = 'pendente'`).bind(c.id).run();
  }catch(err){ console.error('conferir pix', c.id, err && err.message); }
}
async function webhookLocadora(request, env, empresaId){
  const e = await env.DB.prepare('SELECT id, loc_asaas_wh_token FROM empresas WHERE id = ?1').bind(empresaId).first();
  const recebido = (request.headers.get('asaas-access-token') || '').trim();
  const esperado = (e && e.loc_asaas_wh_token) || '';
  const h = async t => hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t)));
  if(!esperado || !iguais(await h(recebido), await h(esperado))) throw new Erro(401, 'Não autorizado');
  let evt; try { evt = await request.json(); } catch { throw new Erro(400, 'Corpo inválido'); }
  const chaveEvt = evt.id ? `loc:${empresaId}:${evt.id}` : null;
  if(chaveEvt && await env.DB.prepare('SELECT 1 FROM eventos_asaas WHERE id = ?1').bind(chaveEvt).first()) return { received: true, duplicate: true };
  const p = evt.payment || {};
  if(p.id){
    const c = await env.DB.prepare('SELECT * FROM cobrancas_pix WHERE asaas_id = ?1 AND empresa_id = ?2').bind(p.id, empresaId).first();
    if(c){
      if(evt.event === 'PAYMENT_RECEIVED' || evt.event === 'PAYMENT_CONFIRMED') await marcarCobrancaPaga(env, c, 'recebido pelo Asaas');
      else if(evt.event === 'PAYMENT_DELETED' || evt.event === 'PAYMENT_REFUNDED')
        await env.DB.prepare(`UPDATE cobrancas_pix SET status = 'cancelada' WHERE id = ?1 AND status = 'pendente'`).bind(c.id).run();
    }
  }
  if(chaveEvt) await env.DB.prepare('INSERT OR IGNORE INTO eventos_asaas (id) VALUES (?1)').bind(chaveEvt).run();
  return { received: true };
}
function cobrancaPublica(c){ const { ultimo_check, empresa_id, ...r } = c; return r; }

/* ---------------- rotas ---------------- */
async function rotear(request, env, url){
  const path = url.pathname.replace(/\/+$/, '');
  const method = request.method;
  const corpo = async () => { try { return await request.json(); } catch { throw new Erro(400, 'Corpo inválido'); } };

  // ----- PLANOS (público) E WEBHOOK DO ASAAS -----
  if(path === '/api/planos' && method === 'GET'){
    const { n } = await env.DB.prepare('SELECT COUNT(*) AS n FROM empresas WHERE fundador = 1').first();
    return [200, { planos: Object.entries(PLANOS).map(([id, p]) => ({ id, ...p })), dias_teste: DIAS_TESTE,
                   vagas_fundador: Math.max(0, VAGAS_FUNDADOR - n), ambiente: env.ASAAS_ENV === 'production' ? 'producao' : 'teste' }];
  }
  if((path === '/webhook' || path === '/api/webhook/asaas') && method === 'POST'){
    return [200, await webhookAsaas(request, env)];
  }

  const mWhLoc = path.match(/^\/webhook\/locadora\/([a-zA-Z0-9-]+)$/);
  if(mWhLoc && method === 'POST') return [200, await webhookLocadora(request, env, mWhLoc[1])];

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
    const testeAte = somaDias(hojeBR(), DIAS_TESTE);
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
    if(!situacaoAcesso(s).liberado) await sincronizarAssinatura(env, s.empresa_id);
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
      if(b.formas_pagamento !== undefined && b.formas_pagamento !== null){
        let lista;
        try{ lista = JSON.parse(b.formas_pagamento); }catch{ throw new Erro(400, 'Formas de pagamento inválidas'); }
        if(!Array.isArray(lista) || lista.length > 30 || lista.some(f => typeof f !== 'string' || !f.trim() || f.length > 40))
          throw new Erro(400, 'Formas de pagamento inválidas (até 30, com até 40 letras cada)');
      }
      const sets = campos.map((c,i) => `${c} = ?${i+1}`).join(', ');
      await env.DB.prepare(`UPDATE empresas SET ${sets} WHERE id = ?${campos.length + 1}`)
        .bind(...campos.map(c => b[c]), s.empresa_id).run();
      return [200, await empresaPublica(env, s.empresa_id)];
    }
  }

  // ----- ASSINATURA DA LOCADORA -----
  if(path === '/api/assinatura' && method === 'GET'){
    await sincronizarAssinatura(env, s.empresa_id);
    return [200, await empresaPublica(env, s.empresa_id)];
  }
  if(path === '/api/assinatura' && method === 'POST'){
    exigirAdmin(s);
    const b = await corpo();
    const plano = PLANOS[b.plano] ? b.plano : null;
    const ciclo = CICLO_ASAAS[b.ciclo] ? b.ciclo : null;
    const doc = soDigitos(b.cpf_cnpj);
    const nomeResp = String(b.nome || '').trim().slice(0, 120);
    if(!plano) throw new Erro(400, 'Escolha um plano');
    if(!ciclo) throw new Erro(400, 'Escolha mensal ou anual');
    if(!cpfCnpjValido(doc)) throw new Erro(400, 'CPF ou CNPJ inválido');
    const e = await env.DB.prepare('SELECT * FROM empresas WHERE id = ?1').bind(s.empresa_id).first();
    if(e.plano === 'ativo') throw new Erro(400, 'Sua conta já está liberada pelo suporte. Não é preciso assinar.');
    if(e.assinatura_id && e.assinatura_status === 'ativa' && e.assinatura_plano === plano && e.assinatura_ciclo === ciclo)
      throw new Erro(409, 'Este plano já está ativo');
    // fatura pendente do mesmo plano: reaproveita em vez de abrir outra
    if(e.assinatura_id && e.assinatura_status === 'pendente' && e.assinatura_plano === plano && e.assinatura_ciclo === ciclo && e.fatura_url)
      return [200, { fatura_url: e.fatura_url, reaproveitada: true }];
    // troca de plano: encerra a assinatura anterior no Asaas
    if(e.assinatura_id && e.assinatura_status !== 'cancelada'){
      try { await asaas(env, 'DELETE', `/subscriptions/${e.assinatura_id}`); } catch(err){ console.error('remover antiga', err.message); }
    }
    let clienteId = e.asaas_customer_id;
    if(!clienteId){
      const achado = await asaas(env, 'GET', `/customers?cpfCnpj=${doc}&limit=1`);
      clienteId = achado?.data?.[0]?.id;
      if(!clienteId){
        const criado = await asaas(env, 'POST', '/customers', { name: nomeResp || e.nome, email: e.email || s.email, cpfCnpj: doc,
          mobilePhone: soDigitos(e.telefone) || undefined, notificationDisabled: false, externalReference: `locaobra:${e.id}` });
        clienteId = criado.id;
      }
    }
    // preço de fundador: primeiras locadoras travam o valor por 12 meses
    let fundador = e.fundador || 0, travadoAte = e.preco_travado_ate;
    if(!fundador){
      const { n } = await env.DB.prepare('SELECT COUNT(*) AS n FROM empresas WHERE fundador = 1').first();
      if(n < VAGAS_FUNDADOR){ fundador = 1; travadoAte = somaDias(hojeBR(), 365); }
    }
    const valor = PLANOS[plano][ciclo];
    // começa a cobrar no fim do teste, se ainda houver dias de teste
    const inicio = e.plano === 'teste' && e.teste_ate && e.teste_ate > hojeBR() ? e.teste_ate : hojeBR();
    const sub = await asaas(env, 'POST', '/subscriptions', {
      customer: clienteId, billingType: 'UNDEFINED', value: valor, nextDueDate: inicio, cycle: CICLO_ASAAS[ciclo],
      description: `LocaObra ${PLANOS[plano].nome} — ${ciclo === 'mensal' ? 'Mensal' : 'Anual'}`, externalReference: `locaobra:${e.id}`
    });
    const pags = await asaas(env, 'GET', `/subscriptions/${sub.id}/payments?limit=1`);
    const fatura = pags?.data?.[0]?.invoiceUrl || null;
    await env.DB.prepare(`UPDATE empresas SET cpf_cnpj = ?1, asaas_customer_id = ?2, assinatura_id = ?3, assinatura_plano = ?4, assinatura_ciclo = ?5,
        assinatura_status = 'pendente', fatura_url = ?6, fundador = ?7, preco_travado_ate = ?8, ultimo_sync = NULL WHERE id = ?9`)
      .bind(doc, clienteId, sub.id, plano, ciclo, fatura, fundador, travadoAte, e.id).run();
    return [201, { fatura_url: fatura, vencimento: inicio, valor, empresa: await empresaPublica(env, e.id) }];
  }
  if(path === '/api/assinatura/cancelar' && method === 'POST'){
    exigirAdmin(s);
    const e = await env.DB.prepare('SELECT assinatura_id, assinatura_status FROM empresas WHERE id = ?1').bind(s.empresa_id).first();
    if(!e.assinatura_id || e.assinatura_status === 'cancelada') throw new Erro(400, 'Não há assinatura para cancelar');
    await asaas(env, 'DELETE', `/subscriptions/${e.assinatura_id}`);
    await env.DB.prepare(`UPDATE empresas SET assinatura_status = 'cancelada' WHERE id = ?1`).bind(s.empresa_id).run();
    return [200, await empresaPublica(env, s.empresa_id)];
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
      const emp = await env.DB.prepare('SELECT plano, assinatura_plano FROM empresas WHERE id = ?1').bind(s.empresa_id).first();
      const { n: total } = await env.DB.prepare('SELECT COUNT(*) AS n FROM usuarios WHERE empresa_id = ?1').bind(s.empresa_id).first();
      const limite = limiteUsuarios(emp);
      if(total >= limite) throw new Erro(403, `Seu plano permite até ${limite} usuários. Mude para o Profissional para cadastrar mais.`);
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

  // ----- PIX DA LOCADORA: CONFIGURAÇÃO -----
  if(path === '/api/pix/config' && method === 'POST'){
    exigirAdmin(s);
    const b = await corpo();
    const e = await env.DB.prepare('SELECT * FROM empresas WHERE id = ?1').bind(s.empresa_id).first();
    const removerWebhook = async () => {
      if(!e.loc_asaas_key || !e.loc_asaas_wh_id) return;
      try{ const k = await decifrar(env, e.loc_asaas_key); await asaasCom(k, e.loc_asaas_env, 'DELETE', `/webhooks/${e.loc_asaas_wh_id}`); }
      catch(err){ console.error('remover webhook locadora', err && err.message); }
    };
    if(!b.modo){
      await removerWebhook();
      await env.DB.prepare('UPDATE empresas SET pix_modo = NULL, loc_asaas_key = NULL, loc_asaas_env = NULL, loc_asaas_wh_token = NULL, loc_asaas_wh_id = NULL WHERE id = ?1').bind(s.empresa_id).run();
      return [200, await empresaPublica(env, s.empresa_id)];
    }
    if(b.modo === 'simples'){
      const tipo = String(b.tipo || '');
      const chave = normalizarChavePix(tipo, b.chave);
      const nome = semAcento(b.nome || e.nome).slice(0, 25), cidade = semAcento(b.cidade || e.cidade).slice(0, 15);
      if(nome.length < 2) throw new Erro(400, 'Informe o nome do recebedor');
      if(cidade.length < 2) throw new Erro(400, 'Informe a cidade do recebedor');
      await removerWebhook();
      await env.DB.prepare(`UPDATE empresas SET pix_modo = 'simples', pix_tipo = ?1, pix_chave = ?2, pix_nome = ?3, pix_cidade = ?4,
          loc_asaas_key = NULL, loc_asaas_env = NULL, loc_asaas_wh_token = NULL, loc_asaas_wh_id = NULL WHERE id = ?5`)
        .bind(tipo, chave, nome, cidade, s.empresa_id).run();
      return [200, await empresaPublica(env, s.empresa_id)];
    }
    if(b.modo === 'asaas'){
      if(!asaasPermitido(e)) throw new Erro(403, 'O Pix com baixa automática pelo Asaas faz parte do plano Profissional.');
      const chave = String(b.api_key || '').trim();
      if(!/^\$?aact_/.test(chave) || chave.length < 30) throw new Erro(400, 'Chave de API do Asaas inválida (ela começa com $aact_)');
      // descobre o ambiente da chave e confere se ela funciona
      const ordem = chave.includes('_hmlg_') ? ['sandbox', 'production'] : ['production', 'sandbox'];
      let ambiente = null;
      for(const amb of ordem){ try{ await asaasCom(chave, amb, 'GET', '/finance/balance'); ambiente = amb; break; }catch(err){} }
      if(!ambiente) throw new Erro(400, 'O Asaas não aceitou essa chave. Confira se copiou a chave inteira, com o $ do começo.');
      await removerWebhook();
      const token = hex(crypto.getRandomValues(new Uint8Array(24)));
      let whId = null;
      try{
        const wh = await asaasCom(chave, ambiente, 'POST', '/webhooks', {
          name: 'LocaObra', url: `${url.origin}/webhook/locadora/${s.empresa_id}`, email: e.email || s.email,
          enabled: true, interrupted: false, apiVersion: 3, authToken: token, sendType: 'SEQUENTIAL',
          events: ['PAYMENT_RECEIVED', 'PAYMENT_CONFIRMED', 'PAYMENT_DELETED', 'PAYMENT_REFUNDED']
        });
        whId = wh.id || null;
      }catch(err){ console.error('criar webhook locadora', err && err.message); }
      await env.DB.prepare(`UPDATE empresas SET pix_modo = 'asaas', loc_asaas_key = ?1, loc_asaas_env = ?2, loc_asaas_wh_token = ?3, loc_asaas_wh_id = ?4 WHERE id = ?5`)
        .bind(await cifrar(env, chave), ambiente, token, whId, s.empresa_id).run();
      return [200, { ...(await empresaPublica(env, s.empresa_id)), webhook_criado: !!whId }];
    }
    throw new Erro(400, 'Modo de Pix inválido');
  }

  // ----- PIX DA LOCADORA: COBRANÇAS DE UMA LOCAÇÃO -----
  const mPix = path.match(/^\/api\/locacoes\/([a-zA-Z0-9-]+)\/pix$/);
  if(mPix){
    const loc = await env.DB.prepare('SELECT * FROM locacoes WHERE id = ?1 AND empresa_id = ?2').bind(mPix[1], s.empresa_id).first();
    if(!loc) throw new Erro(404, 'Locação não encontrada');
    if(method === 'GET'){
      let { results } = await env.DB.prepare('SELECT * FROM cobrancas_pix WHERE locacao_id = ?1 AND empresa_id = ?2 ORDER BY criado_em DESC').bind(loc.id, s.empresa_id).all();
      const pend = results.filter(c => c.modo === 'asaas' && c.status === 'pendente');
      if(pend.length){
        for(const c of pend.slice(0, 3)) await conferirCobrancaAsaas(env, c);
        ({ results } = await env.DB.prepare('SELECT * FROM cobrancas_pix WHERE locacao_id = ?1 AND empresa_id = ?2 ORDER BY criado_em DESC').bind(loc.id, s.empresa_id).all());
      }
      return [200, results.map(cobrancaPublica)];
    }
    if(method === 'POST'){
      exigirAtiva(s);
      const b = await corpo();
      const valor = Math.round(Number(b.valor) * 100) / 100;
      if(!(valor >= 1) || valor > 1000000) throw new Erro(400, 'Informe um valor a partir de R$ 1,00');
      const descricao = String(b.descricao || '').trim().slice(0, 80) || null;
      const e = await env.DB.prepare('SELECT * FROM empresas WHERE id = ?1').bind(s.empresa_id).first();
      const numero = `${String(loc.numero || 0).padStart(4, '0')}/${String(loc.data_retirada || '').slice(2, 4)}`;
      const id = uuid();
      if(e.pix_modo === 'simples'){
        const txid = `LO${String(loc.numero || 0).padStart(4, '0')}${id.replace(/-/g, '').slice(0, 10)}`;
        const payload = brcodeEstatico({ chave: e.pix_chave, nome: e.pix_nome, cidade: e.pix_cidade, valor, txid, descricao: `Locacao ${numero}` });
        await env.DB.prepare('INSERT INTO cobrancas_pix (id, empresa_id, locacao_id, modo, valor, descricao, payload) VALUES (?1,?2,?3,?4,?5,?6,?7)')
          .bind(id, s.empresa_id, loc.id, 'simples', valor, descricao, payload).run();
      } else if(e.pix_modo === 'asaas'){
        if(!asaasPermitido(e)) throw new Erro(403, 'O Pix pelo Asaas faz parte do plano Profissional. No seu plano, use o Pix simples (chave Pix) em Minha empresa.');
        const cli = await env.DB.prepare('SELECT * FROM clientes WHERE id = ?1 AND empresa_id = ?2').bind(loc.cliente_id, s.empresa_id).first();
        const doc = soDigitos(cli && cli.documento);
        if(!cpfCnpjValido(doc)) throw new Erro(400, 'Para cobrar pelo Asaas, o cliente precisa ter CPF ou CNPJ válido no cadastro.');
        const { chave, ambiente } = await chaveAsaasLocadora(env, s.empresa_id);
        const achado = await asaasCom(chave, ambiente, 'GET', `/customers?cpfCnpj=${doc}&limit=1`);
        let clienteId = achado?.data?.[0]?.id;
        if(!clienteId){
          const novo = await asaasCom(chave, ambiente, 'POST', '/customers', { name: cli.nome, cpfCnpj: doc, email: cli.email || undefined,
            mobilePhone: soDigitos(cli.telefone) || undefined, notificationDisabled: true });
          clienteId = novo.id;
        }
        const pg = await asaasCom(chave, ambiente, 'POST', '/payments', { customer: clienteId, billingType: 'PIX', value: valor,
          dueDate: somaDias(hojeBR(), 2), description: `Locação ${numero}${descricao ? ' — ' + descricao : ''}`.slice(0, 500),
          externalReference: `locaobra-loc:${loc.id}` });
        const qr = await asaasCom(chave, ambiente, 'GET', `/payments/${pg.id}/pixQrCode`);
        await env.DB.prepare('INSERT INTO cobrancas_pix (id, empresa_id, locacao_id, modo, asaas_id, valor, descricao, payload, fatura_url) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)')
          .bind(id, s.empresa_id, loc.id, 'asaas', pg.id, valor, descricao, qr.payload, pg.invoiceUrl || null).run();
      } else {
        throw new Erro(400, 'Configure o recebimento por Pix em Minha empresa');
      }
      return [201, cobrancaPublica(await env.DB.prepare('SELECT * FROM cobrancas_pix WHERE id = ?1').bind(id).first())];
    }
  }
  const mPixAcao = path.match(/^\/api\/pix\/([a-zA-Z0-9-]+)\/(pago|cancelar)$/);
  if(mPixAcao && method === 'POST'){
    exigirAtiva(s);
    const c = await env.DB.prepare('SELECT * FROM cobrancas_pix WHERE id = ?1 AND empresa_id = ?2').bind(mPixAcao[1], s.empresa_id).first();
    if(!c) throw new Erro(404, 'Cobrança não encontrada');
    if(c.status !== 'pendente') throw new Erro(409, c.status === 'paga' ? 'Esta cobrança já está paga' : 'Esta cobrança foi cancelada');
    if(mPixAcao[2] === 'pago'){
      if(c.modo === 'asaas'){
        await conferirCobrancaAsaas(env, { ...c, ultimo_check: null });
        const atual = await env.DB.prepare('SELECT status FROM cobrancas_pix WHERE id = ?1').bind(c.id).first();
        if(atual.status !== 'paga') throw new Erro(409, 'O Asaas ainda não confirmou este pagamento. Aguarde alguns instantes.');
      } else {
        await marcarCobrancaPaga(env, c, 'confirmado manualmente');
      }
    } else {
      if(c.modo === 'asaas' && c.asaas_id){
        try{ const { chave, ambiente } = await chaveAsaasLocadora(env, s.empresa_id); await asaasCom(chave, ambiente, 'DELETE', `/payments/${c.asaas_id}`); }
        catch(err){ console.error('cancelar pix', err && err.message); }
      }
      await env.DB.prepare(`UPDATE cobrancas_pix SET status = 'cancelada' WHERE id = ?1 AND status = 'pendente'`).bind(c.id).run();
    }
    return [200, cobrancaPublica(await env.DB.prepare('SELECT * FROM cobrancas_pix WHERE id = ?1').bind(c.id).first())];
  }

  // ----- DEVOLUÇÃO (tudo de uma vez no servidor) -----
  const mDev = path.match(/^\/api\/locacoes\/([a-zA-Z0-9-]+)\/devolver$/);
  if(mDev && method === 'POST'){
    exigirAtiva(s);
    const b = await (async () => { try { return await request.json(); } catch { return {}; } })();
    const loc = await env.DB.prepare('SELECT * FROM locacoes WHERE id = ?1 AND empresa_id = ?2').bind(mDev[1], s.empresa_id).first();
    if(!loc) throw new Erro(404, 'Locação não encontrada');
    if(loc.status === 'devolvida') throw new Erro(409, 'Esta locação já foi devolvida');
    const hoje = /^\d{4}-\d{2}-\d{2}$/.test(b.data_devolucao || '') ? b.data_devolucao : hojeBR();
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
