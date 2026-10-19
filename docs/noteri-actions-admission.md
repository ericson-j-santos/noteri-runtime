# Noteri: admissão do workflow de qualificação

Estado: implementação candidata; verificar a evidência física e o CI do SHA atual
antes de considerar esta rota operacional. `actions_qualified=false` e
`hml_verified=false` não são alterados por esta rotina.

## Escopo

`scripts/noteri_actions_admission.py` é uma entrada específica do Noteri, não um
dispatcher genérico. Reutiliza a sonda nativa para validar host/SHA/perfil e a
gravação atômica do produtor de recibos. Toda execução requer Session Launcher,
worktree reservado, Command Gateway, SHA completo e correlação.

O modo `inspect` consulta, via GitHub CLI oficial já instalada e sua identidade
local, apenas o registro de runners dos repositórios `noteri-runtime` e
`reqsys-v2-enterprise-real`. Não exporta tokens nem usa credenciais fornecidas por
argumento. Falta de permissão é registrada como bloqueio, nunca como lista vazia.
Somente candidatos identificados como Noteri são apresentados. Esse inventário
não comprova que um job executou.

O modo `dispatch` aceita exclusivamente `noteri-control-plane-probe.yml` e a
branch `fix/host-qualification-integration-20261019` de `noteri-runtime`.
Exige confirmação literal, perfil NORMAL observado, conta proprietária, um único
runner online/livre com todas as etiquetas, workflow ativo, branch no SHA
esperado e nenhuma qualificação ainda ativa. Não altera runner, labels, perfil,
privilégios, instalação de SQL ou produção.

O cliente usa a API `2026-03-10`, cuja resposta de despacho inclui run_id e URLs.
O checkpoint de intenção precede o único POST. Resposta incerta não é repetida.
Run_id e SHA são relidos pela API; mesmo uma submissão confirmada não representa
qualificação, conclusão do workflow ou HML. Replay relê o run sem novo POST e
não reexporta campos extras de checkpoints locais.

O journal é local ao host, fora do repositório, em
`LOCALAPPDATA/ReqSys/NoteriQualificationDispatch`. A trava impede submissões
concorrentes; interrupção abrupta pode exigir reconciliação da trava/journal.
Não remover esses registros para forçar nova submissão. O perfil não é revertido
por esta entrada: a mudança explícita para NORMAL é uma operação distinta da
janela temporária de inventário da PR #29.

## Validação e limites

31 testes unitários novos com API, contexto Windows e módulos auxiliares
simulados. Exercitam sucesso estrutural, falta de permissões, repo errado,
runners offline/ocupados, etiquetas faltantes, ambiguidade, SHA divergente,
execução já ativa, persistência antes de POST, replay sem duplicação, resposta
incerta e sanitização. Remover o gate de elegibilidade fez os controles negativos
falharem; código restaurado e os 31 testes reexecutados.

A suíte integral do repositório deve executar no CI do novo HEAD. As funções
nativas reutilizadas e o registro real não são comprovados pelos mocks; exigir
execução governada de `inspect` no Noteri e, somente com pré-condições satisfeitas,
despacho real e leitura independente dos jobs/artefatos. Não usar CI antigo.

Fontes primárias consultadas em 19/10/2026:
- https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event
- https://docs.github.com/en/rest/actions/self-hosted-runners#list-self-hosted-runners-for-a-repository

Checkpoint canônico: TODO-37. Não criar outra fila de trabalho.
