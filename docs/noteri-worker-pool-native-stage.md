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

### Sonda física somente leitura

`python3 -B -m scripts.noteri_worker_pool_activation_preflight` valida a
integridade da release preparada, a referência privada da credencial sem ler
seus bytes, perfil NORMAL, versão e dependências do Python, espaço, listener
loopback e presença da tarefa fixa. O resultado é sanitizado e não autoriza
ativação. Tarefa ausente ou inacessível não pode ser distinguida apenas pelo
`schtasks /Query` pontual; o resultado permanece `BLOCKED_TASK_INVENTORY` até
leitura independente da identidade e configuração da tarefa.

Na sonda física de 25/10/2026, a release e a credencial passaram, e o
interpretador disponível falhou em dependências: `boto3`, `cryptography` e
`pytest` ausentes; `fastapi`, `pydantic` e `uvicorn` em versões divergentes.
Instalar dependências no Python global do runner não é uma etapa autorizada
desta sonda. A próxima capability deve preparar um ambiente isolado,
persistente e verificável com essas versões exatas antes de avaliar start.

### Ambiente isolado, ainda sem start

`scripts/noteri_worker_pool_native_venv.py` tem os modos `plan` e `prepare`.
O plano é somente leitura. A preparação exige confirmação fixa, valida release
e credencial sem abrir os bytes do token, usa exclusivamente o `requirements.txt`
da release imutável e cria `LOCALAPPDATA/ReqSys/NoteriWorkerPool/venvs/<sha>`.
Ela instala as dependências nesse venv, executa `pip check`, relê versões e
registra um manifesto com hashes. Repetição íntegra é idempotente; uma falha
de instalação remove somente o novo venv criado por essa invocação.

O venv é criado pelo Python 3.11.15 já existente no Noteri em
`%APPDATA%/uv/python/cpython-3.11.15-windows-x86_64-none/python.exe`.
A capability confere o SHA-256 fixado do executável e sua versão antes de
prosseguir. `pip` roda somente dentro do venv e aceita apenas wheels binários;
uma dependência sem wheel compatível bloqueia e reverte a preparação. Isso
evita o build de `pydantic==2.11.4` observado com o Python 3.14 do sistema.

Esse passo não registra tarefa, não inicia API e não altera o Python global.
A ativação persistente ainda exige capability própria, autorização Risk3
específica quando aplicável, readback de saúde/contrato/autenticação e rollback.

### Ativação nativa controlada

Antes da ativação, `scripts/noteri_worker_pool_control_package.py --mode plan`
qualifica o pacote COM isolado. `--mode prepare --confirm
PREPARE-NOTERI-WORKER-POOL-COM` instala apenas `pywin32==312`, com hash do
wheel fixado, em `control/pywin32-312-cp314` na árvore privada do Worker Pool.
`--mode verify` confere os arquivos e conecta à pasta `\Automation` do Task
Scheduler sem registrar tarefa. A instalação não altera o Python global nem
o venv usado pela API.

`scripts/noteri_worker_pool_native_activation.py --mode plan` confirma release,
venv, credencial privada, perfil NORMAL, ausência da tarefa fixa e ausência de
listener TCP na porta 8097. O plano não altera o host.

`--mode activate --confirm ACTIVATE-NOTERI-WORKER-POOL-API` requer aprovação
específica para registrar a tarefa `\Automation\NoteriWorkerPoolApi` no Task
Scheduler. A capability copia dois scripts versionados para um `bin` privado,
registra uma tarefa de boot S4U com privilégio limitado e executa uma única
inicialização. O runner valida os hashes da release e do venv e a referência
da credencial antes de iniciar Uvicorn em `127.0.0.1:8097`. O banco SQLite fica
em `data/pool.db` na árvore privada do Worker Pool.
O registro usa a API COM do Task Scheduler, como a tarefa S4U já existente do
host Noteri. `schtasks` permanece apenas para leitura, início e rollback.

O registro exige token administrativo elevado. Uma chamada direta sem elevação
retorna `BLOCKED_ELEVATION_REQUIRED` antes de copiar arquivos. Em uma sessão
interativa autorizada, `scripts/noteri_worker_pool_api_uac.py --confirm
LAUNCH-NOTERI-WORKER-POOL-API-UAC` faz o preflight de leitura e solicita UAC
para essa única ativação. O prompt é visível ao operador; a tarefa resultante
continua com `LeastPrivilege`. O launcher aceita sucesso somente após reler a
tarefa e validar a API, e retorna um resultado sanitizado se UAC for cancelado
ou a ativação não ficar pronta no prazo.
O processo elevado deixa um recibo privado `activation-uac-<id>.json` no diretório
local do Worker Pool. Ele contém somente resultado, fase e confirmação de
elevação; o launcher o consulta para distinguir falha do filho de consentimento
pendente, sem registrar a credencial ou mensagens brutas do Windows.
Se o registro pelo Task Scheduler falhar, a capability conserva a resposta
nativa, limitada a 4 KiB por canal, em um arquivo privado
`registration-failure-<id>.json` na mesma árvore local. O recibo e a saída
normal carregam só o identificador aleatório; o diagnóstico não entra no Git.

A ativação só confirma sucesso quando a definição S4U relida corresponde à
ação registrada, o listener pertence ao processo filho do Python lançado
pela tarefa, `/health` indica pronto, `/v1/contract` autenticado retorna v1
e um token inválido recebe 401. Em falha, a capability encerra e remove a
tarefa recém-criada, espera a porta ficar livre e remove somente `bin` e
`data` que não existiam antes da invocação. Falha ou ambiguidade no rollback
é relatada como bloqueio e preserva os arquivos necessários para diagnóstico.
`--mode status` é somente leitura; `--mode restore` exige a mesma confirmação
fixa e só inicia uma tarefa existente cuja definição e scripts correspondem
ao código publicado.

A prova de persistência após reboot continua separada e exige autorização de
reinicialização. Esta capability não habilita fenced cutover nem enfileira a
task ReqSys #3096.

- Qualificar uma release instalável com dependências fixadas, Python nativo, serviço de API protegido em `127.0.0.1:8097` e startup persistente. O stage-only não realiza essa ativação.
- Reutilizar somente uma referência aprovada a arquivo protegido, fora do repositório e do artifact; se não existir, registrar uma **única decisão de provisionamento de credencial** e não criar/rotacionar automaticamente.
- Qualquer alteração de tarefa administrativa, ACL, elevação, serviço de sistema ou reboot requer autorização específica e replay/readback. Não usar Docker, GUI/RDC ou shell arbitrário.
- Ativação exige `/health` saudável e `/v1/contract` autenticado; o controle negativo deve rejeitar token inválido. Nenhum HTTP 200 isolado comprova operação.
- Somente após esses gates, retomar no Worker Pool a identidade `request_id=026e9c5add6137dc65e673a6` e reconciliar o SHA histórico do handoff da ReqSys#3096 sem reusar o código obsoleto. Builder, Validator independente, task real e replay sem duplicidade são outra etapa.

## Evidência e reversibilidade

Registre source SHA, branch/commit de implementação, host, perfil, correlation ID, resultado `STAGE_PLAN_READY`/`STAGED_ONLY`/`ALREADY_STAGED`, quantidade de arquivos e hashes do manifest. Nunca publique diretórios privados, credencial, conteúdo de perfil ou log de erro não sanitizado.

Testes automatizados em `tests/test_noteri_worker_pool_native_stage.py` usam fixtures temporárias: **não** provam release instalada, serviço, token, startup, E2E real nem disponibilidade 24x7 no Noteri. O CI deve estar verde no SHA final antes de considerar sequer a preparação como implementada.

**Custo adicional máximo: R$ 0,00**. Sem prova de ausência de cobrança ou de autorização humana específica, bloquear efeitos físicos.
