-- Migração: Pix da locadora (rodar uma vez no locaobra-db)
ALTER TABLE empresas ADD COLUMN pix_modo TEXT;
ALTER TABLE empresas ADD COLUMN pix_chave TEXT;
ALTER TABLE empresas ADD COLUMN pix_tipo TEXT;
ALTER TABLE empresas ADD COLUMN pix_nome TEXT;
ALTER TABLE empresas ADD COLUMN pix_cidade TEXT;
ALTER TABLE empresas ADD COLUMN loc_asaas_key TEXT;
ALTER TABLE empresas ADD COLUMN loc_asaas_env TEXT;
ALTER TABLE empresas ADD COLUMN loc_asaas_wh_token TEXT;
ALTER TABLE empresas ADD COLUMN loc_asaas_wh_id TEXT;
CREATE TABLE IF NOT EXISTS cobrancas_pix (
  id TEXT PRIMARY KEY,
  empresa_id TEXT NOT NULL REFERENCES empresas(id),
  locacao_id TEXT NOT NULL REFERENCES locacoes(id),
  modo TEXT NOT NULL,
  asaas_id TEXT,
  valor REAL NOT NULL,
  descricao TEXT,
  status TEXT NOT NULL DEFAULT 'pendente',
  payload TEXT NOT NULL,
  fatura_url TEXT,
  ultimo_check INTEGER,
  criado_em TEXT DEFAULT (datetime('now')),
  pago_em TEXT
);
CREATE INDEX IF NOT EXISTS idx_cobrancas_locacao ON cobrancas_pix(empresa_id, locacao_id);
CREATE INDEX IF NOT EXISTS idx_cobrancas_asaas ON cobrancas_pix(asaas_id);
