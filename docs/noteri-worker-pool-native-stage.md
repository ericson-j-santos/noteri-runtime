# Worker Pool nativo — preparação imutável no Noteri (DEV)

## Diagnóstico de entrada

A sonda física ReqSys [#40214320966](https://github.com/ericson-j-santos/reqsys-v2-enterprise-real/actions/runs/40214320966), SHA `0319faf6c1f65d8d24113f36bf71c4ab53902650`, produziu artifact `12606833094`:

- `token_reference=missing`;
- `pool_health=unreachable`;
- `task_enqueued=false`, `state_changed=false`, `secrets_read=false`.

O runner Noteri, o preflight do perfil base, a sessão e o Command Gateway passaram. Não classificar o host como offline por esse diagnóstico. A issue operacional é [noteri-runtime#42](https://github.com/ericson-j-santos/noteri-runtime/issues/42); o consumidor é [ReqSys#3096](https://github.com/ericson-j-santos/reqsys-v2-enterprise-real/issues/3096).

## Stage-only: código, não instalação

O script `scripts/noteri_worker_pool_native_stage.py` é uma etapa de **preparação**; sua existência no GitHub não significa que tenha sido executado no host.

O consumidor governado deve:

1. confirmar o host Noteri em perfil NORMAL, executor autenticado, Session Launcher e Command Gateway ativos;
2. fazer checkout do Worker Pool compartilhado em `GITHUB_WORKSPACE/_worker_pool`, usando um SHA completo validado e `persist-credentials: false`;
3. conferir que a origem é exatamente `ericson-j-santos/engineering-worker-pool`, o checkout está limpo, e o SHA observado coincide com o esperado;
4. usar a implementação publicada na `main` deste repo, nunca código de PR ou arquivo externo;
5. executar inicialmente em `mode=plan` (nenhuma gravação); sob aprovação do stage, `mode=stage`, ambos mediados pelo Gateway e com contexto imutável.

O stage nativo fixa `LOCALAPPDATA/ReqSys/NoteriWorkerPool/releases/<sha>`, copia somente `app/`, `contracts/v1/` e `requirements.txt`, gera `manifest.json` com SHA-256 de cada arquivo e só promove a pasta temporária após readback completo. Um lock exclusivo rejeita execução concorrente. Repetir o mesmo SHA compara conteúdo existente e retorna `ALREADY_STAGED` sem sobrescrever. Divergência, symlink, arquivo inesperado, SHA errado, checkout sujo, perfil ESTUDO ou host incorreto bloqueiam.

**Não existe ponteiro ativo**, serviço, Task Scheduler, instalação de dependências, token-file ou autorização de execução alterada por esse script.

## Gating posterior (ainda não implementado)

- Qualificar uma release instalável com dependências fixadas, Python nativo, serviço de API protegido em `127.0.0.1:8097` e startup persistente. O stage-only não realiza essa ativação.
- Reutilizar somente uma referência aprovada a arquivo protegido, fora do repositório e do artifact; se não existir, registrar uma **única decisão de provisionamento de credencial** e não criar/rotacionar automaticamente.
- Qualquer alteração de tarefa administrativa, ACL, elevação, serviço de sistema ou reboot requer autorização específica e replay/readback. Não usar Docker, GUI/RDC ou shell arbitrário.
- Ativação exige `/health` saudável e `/v1/contract` autenticado; o controle negativo deve rejeitar token inválido. Nenhum HTTP 200 isolado comprova operação.
- Somente após esses gates, retomar no Worker Pool a identidade `request_id=026e9c5add6137dc65e673a6` e reconciliar o SHA histórico do handoff da ReqSys#3096 sem reusar o código obsoleto. Builder, Validator independente, task real e replay sem duplicidade são outra etapa.

## Evidência e reversibilidade

Registre source SHA, branch/commit de implementação, host, perfil, correlation ID, resultado `STAGE_PLAN_READY`/`STAGED_ONLY`/`ALREADY_STAGED`, quantidade de arquivos e hashes do manifest. Nunca publique diretórios privados, credencial, conteúdo de perfil ou log de erro não sanitizado.

Testes automatizados em `tests/test_noteri_worker_pool_native_stage.py` usam fixtures temporárias: **não** provam release instalada, serviço, token, startup, E2E real nem disponibilidade 24x7 no Noteri. O CI deve estar verde no SHA final antes de considerar sequer a preparação como implementada.

**Custo adicional máximo: R$ 0,00**. Sem prova de ausência de cobrança ou de autorização humana específica, bloquear efeitos físicos.
