CREATE TRIGGER IF NOT EXISTS lo_loc_ins AFTER INSERT ON locacoes
WHEN instr(NEW.observacoes, '[[LO:') > 0
BEGIN
  UPDATE locacoes SET
    local_entrega_id = json_extract(substr(NEW.observacoes, instr(NEW.observacoes,'[[LO:') + 5, length(NEW.observacoes) - instr(NEW.observacoes,'[[LO:') - 6), '$.l'),
    endereco_entrega = json_extract(substr(NEW.observacoes, instr(NEW.observacoes,'[[LO:') + 5, length(NEW.observacoes) - instr(NEW.observacoes,'[[LO:') - 6), '$.e'),
    forma_pagamento  = json_extract(substr(NEW.observacoes, instr(NEW.observacoes,'[[LO:') + 5, length(NEW.observacoes) - instr(NEW.observacoes,'[[LO:') - 6), '$.f'),
    observacoes = NULLIF(rtrim(substr(NEW.observacoes, 1, instr(NEW.observacoes,'[[LO:') - 1), ' '||char(10)||char(13)), '')
  WHERE id = NEW.id;
END;
CREATE TRIGGER IF NOT EXISTS lo_loc_upd AFTER UPDATE OF observacoes ON locacoes
WHEN instr(NEW.observacoes, '[[LO:') > 0
BEGIN
  UPDATE locacoes SET
    local_entrega_id = json_extract(substr(NEW.observacoes, instr(NEW.observacoes,'[[LO:') + 5, length(NEW.observacoes) - instr(NEW.observacoes,'[[LO:') - 6), '$.l'),
    endereco_entrega = json_extract(substr(NEW.observacoes, instr(NEW.observacoes,'[[LO:') + 5, length(NEW.observacoes) - instr(NEW.observacoes,'[[LO:') - 6), '$.e'),
    forma_pagamento  = json_extract(substr(NEW.observacoes, instr(NEW.observacoes,'[[LO:') + 5, length(NEW.observacoes) - instr(NEW.observacoes,'[[LO:') - 6), '$.f'),
    observacoes = NULLIF(rtrim(substr(NEW.observacoes, 1, instr(NEW.observacoes,'[[LO:') - 1), ' '||char(10)||char(13)), '')
  WHERE id = NEW.id;
END;
CREATE TRIGGER IF NOT EXISTS lo_emp_fp AFTER UPDATE OF endereco ON empresas
WHEN instr(NEW.endereco, '[[FP:') > 0
BEGIN
  UPDATE empresas SET
    formas_pagamento = substr(NEW.endereco, instr(NEW.endereco,'[[FP:') + 5, length(NEW.endereco) - instr(NEW.endereco,'[[FP:') - 6),
    endereco = NULLIF(rtrim(substr(NEW.endereco, 1, instr(NEW.endereco,'[[FP:') - 1), ' '||char(10)||char(13)), '')
  WHERE id = NEW.id;
END;
