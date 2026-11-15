-- ==========================================================
-- LocaObra — banco D1 multiempresa (várias locadoras num só banco)
-- Toda tabela de dados tem empresa_id. O Worker sempre filtra por ele.
-- ==========================================================

CREATE TABLE IF NOT EXISTS empresas (
  id TEXT PRIMARY KEY,
  nome TEXT NOT NULL,
  cnpj TEXT,
  telefone TEXT,
  email TEXT,
  endereco TEXT,
  cidade TEXT,
  cor_primaria TEXT DEFAULT '#f59e0b',
  logo TEXT,                                  -- imagem em data URL (até ~250 KB)
  proximo_numero INTEGER NOT NULL DEFAULT 1,  -- numeração de contratos por empresa
  plano TEXT NOT NULL DEFAULT 'teste',        -- teste | ativo | suspenso
  teste_ate TEXT,
  criado_em TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS usuarios (
  id TEXT PRIMARY KEY,
  empresa_id TEXT NOT NULL REFERENCES empresas(id),
  email TEXT UNIQUE NOT NULL,
  nome TEXT,
  papel TEXT NOT NULL DEFAULT 'operador',     -- admin | operador
  senha_hash TEXT NOT NULL,                   -- pbkdf2$iteracoes$salt$hash
  criado_em TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  usuario_id TEXT NOT NULL REFERENCES usuarios(id),
  empresa_id TEXT NOT NULL REFERENCES empresas(id),
  criado_em TEXT DEFAULT (datetime('now')),
  expira_em TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS clientes (
  id TEXT PRIMARY KEY,
  empresa_id TEXT NOT NULL REFERENCES empresas(id),
  tipo_pessoa TEXT DEFAULT 'fisica',
  nome TEXT NOT NULL,
  documento TEXT NOT NULL,
  telefone TEXT,
  email TEXT,
  endereco TEXT,
  cidade TEXT,
  observacoes TEXT,
  status TEXT DEFAULT 'ativo',
  criado_em TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS ferramentas (
  id TEXT PRIMARY KEY,
  empresa_id TEXT NOT NULL REFERENCES empresas(id),
  codigo TEXT NOT NULL,
  nome TEXT NOT NULL,
  categoria TEXT,
  foto_url TEXT,
  valor_diaria REAL NOT NULL,
  valor_semanal REAL,
  valor_mensal REAL,
  valor_reposicao REAL,
  quantidade_total INTEGER DEFAULT 1,
  quantidade_disponivel INTEGER DEFAULT 1 CHECK (quantidade_disponivel >= 0),
  status TEXT DEFAULT 'disponivel',
  observacoes TEXT,
  criado_em TEXT DEFAULT (datetime('now')),
  UNIQUE (empresa_id, codigo)
);

CREATE TABLE IF NOT EXISTS locacoes (
  id TEXT PRIMARY KEY,
  empresa_id TEXT NOT NULL REFERENCES empresas(id),
  numero INTEGER,
  cliente_id TEXT NOT NULL REFERENCES clientes(id),
  data_retirada TEXT NOT NULL,
  data_devolucao_prevista TEXT NOT NULL,
  data_devolucao_real TEXT,
  tipo_cobranca TEXT NOT NULL,
  valor_total REAL DEFAULT 0,
  valor_caucao REAL DEFAULT 0,
  valor_multa REAL DEFAULT 0,
  status TEXT DEFAULT 'ativa',
  observacoes TEXT,
  criado_em TEXT DEFAULT (datetime('now')),
  UNIQUE (empresa_id, numero)
);

CREATE TABLE IF NOT EXISTS itens_locacao (
  id TEXT PRIMARY KEY,
  empresa_id TEXT NOT NULL REFERENCES empresas(id),
  locacao_id TEXT NOT NULL REFERENCES locacoes(id),
  ferramenta_id TEXT NOT NULL REFERENCES ferramentas(id),
  quantidade INTEGER DEFAULT 1,
  valor_unitario REAL NOT NULL,
  subtotal REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS pagamentos (
  id TEXT PRIMARY KEY,
  empresa_id TEXT NOT NULL REFERENCES empresas(id),
  locacao_id TEXT NOT NULL REFERENCES locacoes(id),
  tipo TEXT NOT NULL,
  valor REAL NOT NULL,
  forma_pagamento TEXT,
  data_pagamento TEXT DEFAULT (datetime('now')),
  observacoes TEXT
);

CREATE INDEX IF NOT EXISTS idx_usuarios_empresa ON usuarios(empresa_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expira ON sessions(expira_em);
CREATE INDEX IF NOT EXISTS idx_clientes_empresa ON clientes(empresa_id);
CREATE INDEX IF NOT EXISTS idx_ferramentas_empresa ON ferramentas(empresa_id);
CREATE INDEX IF NOT EXISTS idx_locacoes_empresa ON locacoes(empresa_id);
CREATE INDEX IF NOT EXISTS idx_locacoes_cliente ON locacoes(cliente_id);
CREATE INDEX IF NOT EXISTS idx_itens_empresa ON itens_locacao(empresa_id);
CREATE INDEX IF NOT EXISTS idx_itens_locacao ON itens_locacao(locacao_id);
CREATE INDEX IF NOT EXISTS idx_pagamentos_empresa ON pagamentos(empresa_id);
-- código da ferramenta único por empresa, sem diferenciar maiúsculas
CREATE UNIQUE INDEX IF NOT EXISTS idx_ferramentas_codigo_unico ON ferramentas(empresa_id, UPPER(TRIM(codigo)));
