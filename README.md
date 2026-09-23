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

## Migração

A migração a partir de `ericson-j-santos/reqsys-v2-enterprise-real` é incremental e fail-closed. O código operacional antigo só pode ser removido após o equivalente neste repositório possuir testes e E2E aplicável no mesmo SHA.

## Segurança

Não versionar segredos, tokens, credenciais, nomes privados de infraestrutura, dados pessoais ou caminhos que contenham dados sensíveis. Configurações específicas da máquina devem ser injetadas por ambiente/arquivo local protegido.
