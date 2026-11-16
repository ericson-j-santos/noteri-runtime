# Worker Pool nativo no Noteri — correção segura do SHA de regras e automação

## Estado comprovado — 15/11/2026 (DEV)

- Regras oficiais: `ericson-j-santos/chatgpt-operational-rules/main@58dcd4200f412a866278027ba9e433439a03f3b3`, versão 1.6.21.
- `noteri-runtime/main@e10b3a00a9b3ec803ed4a4cc8f4f8c62b06c8928` permanece **sem alteração**.
- Iniciador **instalado** da API `NoteriWorkerPoolApi`: `RULES_SHA=4e6091a133f8d7d157abe6f83c31ca597812e0a4` conforme verificação anterior da origem instalada.
- Iniciador **candidato no GitHub**: `RULES_SHA=58dcd4200f412a866278027ba9e433439a03f3b3`. O código não está instalado.
- Fonte nativa Worker Pool instalada: `engineering-worker-pool@21fd68dec6f0da92b3e7da201463401ac5429d64`; 38 arquivos oficiais preservados e exatamente um arquivo extra conhecido `app/__pycache__/secure_file.cpython-314.pyc`, SHA-256 `3f4032ec92f939eb96d6c6eb869613c6cc30f5cba4ecee880215511e34058c6e`. O gate original rejeita a release enquanto esse extra existir.
- API viva `127.0.0.1:8097` recebeu autenticação real `AUTHENTICATED_READBACK_OK`, controle negativo HTTP 401 e replay positivo do contrato.
- Leitura SQLite `mode=ro`, `PRAGMA query_only=ON`, resultou `queued=1,leased=running=validating=0`, workers cadastrados **0**, corte cercado desativado. A tarefa é **smoke sintético ReqSys** `codex-worker-pool-smoke#1914`, derivação de identidade confirmada e lane `enabled=false`. Não há issue real #1914 a ser criada.

**Classificação da mudança:** reparo de divergência preexistente, sem declarar Builder/modelo real ou Validator formal já realizados. CI verde ou script de leitura não liberam instalação, PR nem integração.

## Automação implementada no código candidato

`scripts/noteri_worker_pool_rules_pin_sync.py` usa exclusivamente a API pública fixa de `chatgpt-operational-rules/main`; não aceita endpoint, caminho, repositório ou SHA arbitrários do chamador.

| Modo | Efeito | Resultado esperado |
|---|---|---|
| `plan` | Consulta o SHA oficial e compara o arquivo versionado sem escrever | `RULES_SHA_ALIGNED` ou `RULES_SHA_DRIFT` |
| `check` | Mesma leitura; código de saída 2 em divergência | Bloqueia o job de CI |
| `prepare` | Exige confirmação fixa, branch `fix/`, `feat/` ou `repair/`, checkout limpo, remoto `noteri-runtime`, HEAD completo esperado e API de regras confirmada | Atualiza **somente** o arquivo versionado em worktree isolado; não comita, não abre PR, não publica |

A CI existente (`.github/workflows/ci.yml`) executa `--mode check` **dentro do job `tests`**, sem outro job, sem novo gatilho ou armazenamento de artefato. O repositório é público e utiliza runner padrão `ubuntu-latest`; GitHub declara esse recurso gratuito em repositórios públicos. Em rede/API indisponível, bloqueia e não inventa o SHA. Isso **detecta** novos desvios em cada CI; não monitora a alteração do repositório das regras instantaneamente, nem executa reparos físicos automaticamente.

Para futuras correções, um executor autorizado pode usar `prepare` somente com `--expected-head <SHA40 da branch já validada>` e `--confirm PREPARE-RULES-PIN-CANDIDATE`, sob sessão/Gateway versionados. O modo é deliberadamente recusado em checkout detached, branch protegida, diff sujo ou remoto divergente. Abrir PR draft/merge exige critérios próprios de admissão, Builder real, CAS, Validator independente, SHA exato e autorização.

## Plano de manutenção física — preparado, **não autorizado nem executado**

**Antes de qualquer parada:** titular deve autorizar especificamente o alvo `Noteri DEV`, a tarefa `\\Automation\\NoteriWorkerPoolApi`, backup consistente, parada/reinício, substituição atômica do iniciador versionado e quarentena **somente** do arquivo `.pyc` conhecido com hash acima; confirmar ausência de tarefas/reservas em andamento e de novas admissões, estado NORMAL, sessão `SESSION_LAUNCH_OK`, `state_validated=true`, Gateway e worktree exclusivos; custo incremental R$ 0,00. Ausência de qualquer requisito: **não modificar**.

**Pré-backup:** capturar tarefa real por COM e export XML (hash), identidade S4U, ação e processo dono da porta 8097, hashes dos dois scripts instalados, release/manifesto/venv, estado de fila e reservas, e referência de credencial **sem expor seu conteúdo**. Criar cópia íntegra/verificável do iniciador e um backup **consistente** do SQLite com sua API de backup; não copiar `pool.db` isoladamente enquanto WAL estiver ativo. Manter cópias em área privada com controle de acesso e hash; registrar correlação e checkpoint. Sem prova de backup + readback, não parar.

**Transição atômica depois da aprovação:** bloquear novas admissões e comprovar drenagem; parar exclusivamente a tarefa fixada através da capability permitida; preservar e mover para quarentena exata o único bytecode conhecido após validar hash e ausência de arquivos inesperados; reler 38/38 do manifesto para reabrir o gate imutável; substituir de forma atômica somente o iniciador por versão integrada/aprovada do mesmo repositório; checar hash de todos os arquivos instalados; reiniciar a **mesma** tarefa sem re-registro/permissões; conferir processo, health, negativa 401, contrato autenticado/replay, SHA de regras na configuração efetiva, fila sintética intacta e nenhum claim criado.

**Rollback em falha:** parar a tentativa parcialmente iniciada, restaurar os dois scripts instalados dos backups SHA-verificados e a configuração anterior da tarefa se tiver sido afetada, restaurar dados por backup consistente **somente se necessário para recuperar alterações realmente verificadas**. **Não recolocar o bytecode defeituoso no diretório ativo**, pois isso reproduziria o bloqueio de integridade no próximo restart; manter o arquivo com hash em quarentena forense e restabelecer o serviço com os arquivos oficiais íntegros. Validar a versão anterior com autenticação e controle negativo, preservar evidências e informar bloqueio se a restauração falhar. Nunca afirmar sucesso porque o comando de start retornou 2xx.

## Aceite e próxima ação

- **Código:** PIN atualizado no candidato e sincronizador controlado implementado; CI e E2E real do modo `plan` comprovados quando vinculados ao SHA e recibo.
- **Validação independente para PR:** não concluída sem Builder real, CAS relido e Validator formal.
- **Instalação física:** nenhuma alteração; API atual permanece funcionando. Para alterar, exige integração autorizada e autorização física específica.
- **Entrega completa Worker Pool:** Issue `engineering-worker-pool#62` mantém **0/6 gates integrais**, pois nenhum Builder→CAS→Validator→replay real foi comprovado.
- **Próxima ação Pareto:** provar Builder real e Validator independentes, criar PR draft apenas quando gates atuais forem cumpridos, e solicitar autorização cirúrgica de manutenção para SHA + cache simultaneamente; não reiniciar apenas por divergência do código.
- **Responsáveis:** Runtime Platform (instalação Noteri); Engineering Control Plane (Builder/Validator, CAS, fencing e PR); titular (autorização de manutenção). Prazo não estimável até esses gates.

Evidências atuais: [Noteri #42](https://github.com/ericson-j-santos/noteri-runtime/issues/42) e [Worker Pool #62](https://github.com/ericson-j-santos/engineering-worker-pool/issues/62).
