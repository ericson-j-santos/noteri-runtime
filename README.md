# Noteri Runtime

Runtime específico do host **Noteri**, separado do produto ReqSys e do runtime do Desktop PC24x7.

## Responsabilidade

Este repositório contém somente capacidades dependentes do host Noteri, como:

- perfil operacional `NORMAL` / `ESTUDO`;
- agente local de perfil;
- persistência e recuperação específicas do host;
- probes e evidências do runtime do Noteri;
- testes e E2E específicos desse host.

## Fora de escopo

Não duplicar aqui componentes compartilhados entre hosts:

- Command Gateway e contratos de sessão;
- Worker Pool / orquestração;
- locks e watchdog transversal;
- Builder / Validator;
- políticas globais de segurança e governança;
- lógica de negócio do ReqSys.

As regras canônicas permanecem em `ericson-j-santos/chatgpt-operational-rules`.

## Atualização governada do Gateway no Noteri

O workflow `Noteri Command Gateway Refresh` é somente `workflow_dispatch` e
reutiliza o atualizador canônico fixado por commit, manifesto e SHA-256 do
próprio script. Ele exige os SHA-256 do recibo e manifesto legados originais,
seleciona explicitamente o perfil WSL exclusivo do Noteri e falha antes da
substituição se os pins, host ou bundle divergirem. Não concede privilégios,
não abre UAC e não inicia WSL ou serviços. O updater canônico executa preflight
de substituição, backup v2, rollback e readback; a etapa seguinte compara os
hashes instalados com o manifesto aprovado. A existência deste workflow não é
autorização para dispará-lo nem comprovação de instalação física.

## Migração

A migração a partir de `ericson-j-santos/reqsys-v2-enterprise-real` é incremental e fail-closed. O código operacional antigo só pode ser removido após o equivalente neste repositório possuir testes e E2E aplicável no mesmo SHA.

## Segurança

Não versionar segredos, tokens, credenciais, nomes privados de infraestrutura, dados pessoais ou caminhos que contenham dados sensíveis. Configurações específicas da máquina devem ser injetadas por ambiente/arquivo local protegido.

## Perfil mínimo de artefatos S3

O preflight em [`docs/noteri-s3-artifact-profile.md`](docs/noteri-s3-artifact-profile.md)
qualifica no host apenas o perfil binário mínimo do transporte de artefatos do
Engineering Worker Pool. Ele permanece sem credenciais e não declara o worker ou
o transporte prontos antes dos gates físicos restantes.
