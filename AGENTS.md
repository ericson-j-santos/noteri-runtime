# AGENTS.md

Este repositório contém somente runtime específico do host Noteri.

Antes de trabalho técnico:
1. consultar a branch main de `ericson-j-santos/chatgpt-operational-rules`;
2. aplicar as regras de runtime, sessão, Command Gateway, E2E e progress watchdog pertinentes;
3. não duplicar componentes transversais do Engineering Control Plane;
4. não executar comandos por GUI/RDC como fallback;
5. não versionar segredos, credenciais ou identificadores privados de infraestrutura;
6. para mudanças funcionais, exigir teste automatizado e E2E aplicável no mesmo SHA antes de considerar concluído.
7. para qualquer mudança no watchdog persistente do Noteri, **incluir obrigatoriamente a atualização da cópia efetivamente instalada** no host: conferir tarefa/serviço de inicialização, caminho e SHA-256 anteriores, preservar backup e rollback, atualizar somente via capability autorizada do plano de controle e Command Gateway após `SESSION_LAUNCH_OK` e `state_validated=true`, revalidar caminho e SHA-256 da versão em uso e executar E2E físico `NORMAL -> ESTUDO -> NORMAL` com controle negativo, ausência de janelas CMD e readback independente. CI verde, PR aprovada, merge e checkout atualizado **não comprovam instalação**. Sem prova de versão instalada e efeito real: manter **PARCIAL/BLOQUEADO**, preservar o TODO aberto e registrar responsável/próxima ação. Não contornar por terminal, GUI ou RDC.


A migração do ReqSys é fail-closed: não remover o runtime antigo até o equivalente deste repositório estar validado no host real.
