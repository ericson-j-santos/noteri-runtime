# Requisitos — stage-only de Worker Pool nativo (Noteri/DEV)

## Contrato

1. Não criar Worker Pool novo: consumir somente a origem oficial `ericson-j-santos/engineering-worker-pool` em SHA completo e worktree limpa.
2. `stage-only` é local DEV, host Noteri e perfil NORMAL; nunca executar no Desktop, ESTUDO, HML, STG ou produção.
3. A execução física futura deve ser mediada por Session Launcher + Command Gateway na `main` versionada; nenhum shell/RDC/GUI alternativo.
4. O checkout fonte deve residir exclusivamente em `GITHUB_WORKSPACE/_worker_pool` e ter origem oficial autenticada pelo Git; nenhuma URL, comando, caminho ativo ou alvo arbitrário oriundo da issue.
5. Somente `app/`, `contracts/v1/` e `requirements.txt` podem ser preparados, com tipos, tamanho, contagem e symlinks controlados; nenhum arquivo de credencial é incluído.
6. Destino imutável em `LOCALAPPDATA/ReqSys/NoteriWorkerPool/releases/<sha>`, com manifesto de SHA-256 por arquivo, cópia temporária validada e rename atômico.
7. Lock exclusivo; colisão e release preexistente divergente devem falhar fechado. Mesmo SHA íntegro retorna `ALREADY_STAGED` sem sobrescrever.
8. Modo padrão `plan` é não mutável; `stage` exige confirmação literal. Nenhum modo ativa serviço, executa pip, lê/gera/rotaciona credencial, muda Task Scheduler/ACL/UAC ou reinicia host.
9. Diagnósticos sanitizados sem token, caminho pessoal, stderr de Git ou traceback de credencial. Evidência deve separar staging de autenticidade/saúde do Worker Pool.
10. Testes: plano sem mutação, staging positivo, readback íntegro, replay, SHA falso, origem diferente, checkout sujo, ESTUDO, host errado, symlink, path inválido, arquivo faltante, adulteração e lock; E2E físico posterior obrigatório.
11. PR somente após testes no SHA; nenhum merge, autorização administrativa ou ativação decorrente apenas de CI verde.
12. Trabalho físico futuro exige uma decisão explícita separada de provisionamento do token e uma de ativação administrativa quando aplicáveis.

## Evidências

- [ReqSys run físico 40214320966](https://github.com/ericson-j-santos/reqsys-v2-enterprise-real/actions/runs/40214320966): token_reference=missing, pool_health=unreachable, task_enqueued=false, state_changed=false.
- [Noteri issue #42](https://github.com/ericson-j-santos/noteri-runtime/issues/42) — escopo, gates e aceitação.

Custo incremental `R$0,00`. Teste sintético não substitui instalação e E2E no Noteri.
