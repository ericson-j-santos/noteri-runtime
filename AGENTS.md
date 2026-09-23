# AGENTS.md

Este repositório contém somente runtime específico do host Noteri.

Antes de trabalho técnico:
1. consultar a branch main de `ericson-j-santos/chatgpt-operational-rules`;
2. aplicar as regras de runtime, sessão, Command Gateway, E2E e progress watchdog pertinentes;
3. não duplicar componentes transversais do Engineering Control Plane;
4. não executar comandos por GUI/RDC como fallback;
5. não versionar segredos, credenciais ou identificadores privados de infraestrutura;
6. para mudanças funcionais, exigir teste automatizado e E2E aplicável no mesmo SHA antes de considerar concluído.

A migração do ReqSys é fail-closed: não remover o runtime antigo até o equivalente deste repositório estar validado no host real.
