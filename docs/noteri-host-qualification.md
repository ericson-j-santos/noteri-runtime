# Qualificação governada do Noteri para execução multi-host

Estado: PARCIAL. Integração de código em branch; ativação por Actions e HML real ainda não comprovadas.

## Fluxo implementado

O workflow existente `noteri-control-plane-probe.yml` permanece exclusivamente manual.
Ele fixa o SHA das regras revisadas e usa `python3`, sem depender do alias `python`
quebrado observado no Noteri. O Session Launcher exige SHA exato, worktree isolado,
snapshot e preflight da versão do runner. Todas as consultas posteriores passam
pelo Command Gateway. Nenhum ACL, serviço, banco, perfil ou segredo do host é alterado.

O produtor grava inventário nativo e recibo vinculado à sessão. Um segundo processo
via Gateway relê o recibo e o estado real, rejeitando alterações de perfil, SQL,
arquivos ou versão. Um job hospedado separado obtém a execução e o ZIP pela API,
confere SHA-256, vínculo do artefato, identidade do runner, etapa executada e frescor;
só então chama o seletor compartilhado da PR #155 das regras.

Os dados locais não são autenticados apenas porque contêm flags: a validação
externa exige o job do mesmo SHA e os bytes do artefato desse job. A credencial
efêmera `GITHUB_TOKEN`, com `actions: read`, fica somente no job hospedado e não
é encaminhada para o redirecionamento de armazenamento do ZIP.

## Limites de confiança e de conclusão

As capacidades emitidas são somente `platform=Windows` e `native_inventory=observed`.
Serviço SQL em execução e versão de instalação no registro NÃO certificam conexão,
edição/licença, TLS, permissões SQL, build do processo, JSON, desempenho ou HML.
A saída mantém `hml_verified=false` e não despacha tarefas, implementa failover,
transfere dados, faz merge ou autoriza produção.

O perfil deve ser explicitamente NORMAL. ESTUDO gera diagnóstico bloqueado; não
há conversão automática de perfil. Um novo job não deve ser despachado sabendo
que esse requisito não está atendido. O próprio seletor continua exigindo uma
reserva/sessão atual antes do executor agir.

A evidência do Actions expira após 300 segundos. Consultar novamente a API não
renova job nem recibo. Falhas invalidam a decisão antiga. Casos de ZIP adulterado,
runner não atribuído, etapa ignorada, deriva de estado e saída residual são testes
negativos obrigatórios.

## Evidência física observada em 19/10/2026

No incremento inicial `3f6d49fabdc0507c12958e1beca35eb6eed95ef8`, às 19:23:54 UTC,
a sonda foi executada no Noteri por sessão governada e worktree limpo:
- MSSQLSERVER em execução; versão de instalação no registro 17.0.1000.7.
- ODBC Drivers 17 e 18 instalados.
- Python 3.14.6 pelo alias python3.
- Perfil ESTUDO, lido do arquivo de perfil.
- Gateway global ainda 1.6.5.

A tentativa anterior de atualizar o Gateway para main
`8a34b2b0862affb98a9e094e89802fdc6df090c0` falhou com WinError 5 ao substituir
session_launcher.py. O updater também não confirmou rollback. Não houve mudança
de permissões nem nova tentativa sob a mesma condição. A sonda independente
comparou os sete destinos gerenciados com os bytes, hashes, tamanhos e modos do
backup e confirmou o estado anterior integralmente preservado.
Hash do rollback-manifest:
`f415f09b37ef30ac765f3616810c45bb8b99d018aa3a59b3a1b349aa7c558209`.

O diagnóstico atual distingue atualização bloqueada restaurada de atualização
bem-sucedida: a segunda deve corresponder ao bundle novo, não ao backup antigo.
Essa melhoria posterior requer seu próprio readback no SHA final; a observação
física acima pertence exclusivamente ao incremento inicial.

## Testes e continuidade

A suíte nova possui 43 testes de arquivos, contratos, vínculo, repetição,
negativos e integração simulada. São testes de sandbox/CI, não execução física
do novo workflow. Os testes nativos/Windows e Actions reais não são substituídos
por fixtures de API. Os testes completos do repositório devem ser confirmados
nos logs da PR e no HEAD final.

O workflow fixa um candidato revisado das regras, sem editar a instalação global.
Esse contrato versionado não contorna o Gateway: usa o mesmo launcher, políticas,
snapshot, isolamento e execução governada. A promoção desse candidato à main é
uma operação separada, condicionada aos gates.

Checkpoint canônico: TODO-37; correlação filha
`sql-hml-multihost-integrate-20261019`.
Referências: chatgpt-operational-rules PR #155 e reqsys-data-platform PR #13.
Próximo passo: autorização de janela NORMAL, qualificação do runner no escopo
correto, execução única do workflow e leitura independente; depois identificar
banco e identidade HML protegidos antes de testar conexão/TLS/JSON.
