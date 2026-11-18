-- LocaObra — locais de entrega/obra e várias formas de pagamento (nov/2026)
-- Já aplicada no locaobra-db em 18/11/2026.
CREATE TABLE IF NOT EXISTS locais_entrega (
  id TEXT PRIMARY KEY,
  empresa_id TEXT NOT NULL REFERENCES empresas(id),
  cliente_id TEXT NOT NULL REFERENCES clientes(id),
  nome TEXT NOT NULL,
  endereco TEXT NOT NULL,
  bairro TEXT, cidade TEXT, cep TEXT, contato TEXT, telefone TEXT, observacoes TEXT,
  status TEXT DEFAULT 'ativo',
  criado_em TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_locais_empresa ON locais_entrega(empresa_id, cliente_id);
ALTER TABLE locacoes ADD COLUMN local_entrega_id TEXT;
ALTER TABLE locacoes ADD COLUMN endereco_entrega TEXT;
ALTER TABLE locacoes ADD COLUMN forma_pagamento TEXT;
ALTER TABLE empresas ADD COLUMN formas_pagamento TEXT;
