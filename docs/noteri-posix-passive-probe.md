# Noteri Ubuntu WSL2 — sonda POSIX passiva (staged, não ativada)

## Estado e origem

Esta implementação é posterior à qualificação HKCU de registro WSL2 documentada na
[PR #61](https://github.com/ericson-j-santos/noteri-runtime/pull/61). O inventário
anterior comprovou **registro** de uma distribuição Ubuntu WSL2, não Linux iniciado
nem serviços habilitados. Não repetir o inventário como falso progresso.

A sonda em `scripts/noteri_posix_readonly.py` **não invoca `wsl.exe`,
não inicia uma distribuição, serviço ou banco e não aceita argumentos de comando.
Ela só pode ser executada **de dentro de uma distribuição já ativa**, recebendo
uma sessão POSIX previamente autenticada e admitida pelo Session Launcher e Command Gateway.

**BLOQUEIO:** não há evidência de um transporte POSIX governado instalado no Ubuntu
do Noteri. O Gateway Windows continua a proibir `wsl` no campo
`blocked_executables`. O perfil POSIX genérico em
`chatgpt-operational-rules/config/command-gateway.policy.posix.json`
não inclui o repositório Noteri nem atesta qual distribuição Windows está em uso.
Nenhuma alteração nessa política foi autorizada por esta PR.

## Contrato deliberadamente limitado

Pré-condições verificadas **somente depois de já estar dentro do Linux**:

- kernel compatível com WSL2 e identificação `ID=ubuntu` em
  `/etc/os-release`;
- hostname `Noteri` e `WSL_DISTRO_NAME` restrito a `Ubuntu`
  ou `Ubuntu-NN.NN`;
- consulta de PID 1 para decidir se consultas ao systemd são aplicáveis.

O runtime acessa somente estes arquivos: `/proc/sys/kernel/osrelease`,
`/etc/os-release` e `/proc/1/comm`. Executa, sem
shell e com timeout de 5 segundos, **apenas**:

1. `/usr/bin/systemctl is-system-running` (somente quando PID 1 é systemd);
2. `/usr/bin/psql --version`;
3. `/usr/bin/systemctl is-active postgresql.service` (somente quando PID 1 é systemd).

Não executa `start`, `enable`, `restart`,
comandos SQL, autenticação ou conexão à rede. Não lê credenciais nem imprime
stdout/stderr brutos; apenas interpreta estados e versões sanitizados.
Parâmetros adicionais são rejeitados; a lista de comandos é imutável.

**Fronteira de confiança:** hostname, `WSL_DISTRO_NAME` e arquivos
do próprio guest são indícios locais, não prova criptográfica da identidade da
máquina Windows. O chamador deverá vincular por uma fonte independente
identidade Windows/registro da distro, repositório, HEAD SHA, rules SHA,
sessão, correlation_id e recibo do Gateway. O script marca explicitamente
`gateway_session_verified=false` e
`distro_previously_running_verified=false`, pois não pode
atestar essas condições por conta própria.

Mesmo que o script encontre `postgresql.service active`, isso **não**
prova conexão SQL, TLS, autoridade DEV, backup/restore, failover entre hosts
nem agente Qwen autônomo. Nenhuma flag de readiness de PostgreSQL ou Qwen é
verdadeira na saída da sonda.

## Gates físicos obrigatórios antes de ativar

1. Obter evidência independente, pelo plano de controle já autorizado, de que o
   **mesmo Ubuntu WSL2 já está ativo**, sem executar comando que possa iniciá-lo.
   Não basta listar o registro; sondar o estado não pode lançar a distribuição.
2. Comprovar um transporte autenticado para **aquele guest existente**, sem
   utilizar shell livre, subprocesso Windows que chame WSL ou bypass da
   blacklist atual. Se não existir, manter BLOQUEADO.
3. Definir e testar perfil POSIX específico para o Noteri, com caminhos reais
   previamente qualificados, identidade/versionamento fixados e scripts
   restritos. Não usar o perfil genérico como autorização automática.
4. Executar Session Launcher com `SESSION_LAUNCH_OK`,
   `state_validated=true`, worktree isolado no SHA exato e
   Command Gateway risco 1, sem mudar política, serviço ou estado Git.
5. Registrar run/job/correlation_id, verificar stdout sanitizado e código de
   saída, HEAD, digest/status antes/depois e repetir a leitura por um validador
   independente. Incluir teste negativo de distro/host/argumentos incorretos.
6. Se qualquer etapa puder despertar a distribuição e ativar serviços ainda
   não inventariados, **não prosseguir sem autorização específica do OWNER**
   para esse efeito e ambiente; a presente PR não a concede.

CI simulado verifica sintaxe, caminho feliz, rejeições, timeout, saída
sanitizada, comandos exatos e replay. CI não comprova execução física,
systemd, PostgreSQL ou POSIX Gateway instalado. Nenhum merge, deploy,
alteração em produção, Docker, Neon ou gasto incremental está contemplado.
