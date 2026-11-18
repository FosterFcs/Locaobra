-- Gatilhos do modo compatível (servidor antigo). Já aplicados no locaobra-db.
-- Separam os campos marcados nas observações: [[LO:{l,e,f,u}]] em locacoes e [[PG:{u}]] em pagamentos.
CREATE TRIGGER lo_loc_ins AFTER INSERT ON locacoes
WHEN instr(NEW.observacoes, '[[LO:') > 0
BEGIN
  UPDATE locacoes SET
    local_entrega_id = json_extract(substr(NEW.observacoes, instr(NEW.observacoes,'[[LO:') + 5, length(NEW.observacoes) - instr(NEW.observacoes,'[[LO:') - 6), '$.l'),
    endereco_entrega = json_extract(substr(NEW.observacoes, instr(NEW.observacoes,'[[LO:') + 5, length(NEW.observacoes) - instr(NEW.observacoes,'[[LO:') - 6), '$.e'),
    forma_pagamento  = json_extract(substr(NEW.observacoes, instr(NEW.observacoes,'[[LO:') + 5, length(NEW.observacoes) - instr(NEW.observacoes,'[[LO:') - 6), '$.f'),
    criado_por = COALESCE(json_extract(substr(NEW.observacoes, instr(NEW.observacoes,'[[LO:') + 5, length(NEW.observacoes) - instr(NEW.observacoes,'[[LO:') - 6), '$.u'), criado_por),
    observacoes = NULLIF(rtrim(substr(NEW.observacoes, 1, instr(NEW.observacoes,'[[LO:') - 1), ' '||char(10)||char(13)), '')
  WHERE id = NEW.id;
END;
-- lo_loc_upd: igual ao lo_loc_ins, com AFTER UPDATE OF observacoes ON locacoes
-- lo_pag_ins: AFTER INSERT ON pagamentos, marcador [[PG:{"u":...}]] → registrado_por
-- lo_emp_fp: não usado pelo app (formas ficam em clientes tipo_pessoa = 'config_formas')
