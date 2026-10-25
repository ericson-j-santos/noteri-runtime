# Noteri — Issue #8 Qwen + RAG real, canário físico de somente leitura

## Posição na cadeia do primeiro ciclo autônomo

Objetivo global: Issue/TODO autorizado → reparo Qwen real → commit material → CAS SHA → Validator independente → PR draft única → readback/replay.

Este incremento qualifica o primeiro elo que ainda não foi comprovado: issue #8 com autorização OWNER e SHA da main atual → baseline real dos 42 casos → plano e citação produzidos pelo Qwen instalado no Noteri. Não executa Builder de código, não adquire lease, não escreve CAS, não publica branch/PR de reparo nem usa Docker físico. A PR de infraestrutura não é uma PR do agente.

## Identidades fixas na admissão

- Worker Pool main: 74035488dac6938bfc14957621e86168003cd0c6
- Blob Git do app/portfolio_bridge.py: d9a25c574163c49f695e774609949160d94f4490
- Comentário OWNER issue #8: 6404265064, comando literal atrelado à main
- Agent Core: 1fc032d4c412bdb4ed202cf1193caf0cb49490ce
- Regras operacionais: 95ae14f7e90e01a5d6d1227fa2536246725ac68c (1.6.19)
- Noteri Runtime base: 42e4f0eb3f6988e326c76b7160f9bbc9f2092a46

Os SHAs são fixados. Avanço de branch, autorização ou arquivo exige novo commit, CI e readback. Não atualizar automaticamente os valores durante a execução física.

## Bloqueio anterior e solução já presente nas regras

A tentativa remota governada qwen-issue8-main74035488-20261025 falhou com SESSION_LAUNCH_BLOCKED código 23. O clone local só tinha refspec de fetch para feat/fenced-checkpoint-continuity-20261019, de modo que o fetch não populou origin/main. A instalação do Launcher nesse Noteri usava regras 1.6.5.

A versão canônica de session_launcher.py no SHA acima (1.6.19) já contém controle positivo/negativo para fetch exato de branch em clones de refspec restrito. Este canário faz checkout do launcher canônico via GitHub Actions e cria seu próprio worktree, sem atualizar globalmente binários/serviços/policy do Noteri.

## Fluxo de admissão e execução

1. Uma PR draft com somente quatro arquivos desta tarefa é admitida. Apenas evento pull_request:edited pelo owner, adicionando o marcador OWNER_ISSUE8_NATIVE_RAG_NOTERI_20261025_ONCE numa transição de ausência → presença, pode abrir o gate físico.
2. Hosted contract roda compileall e testes positivos/negativos antes da admissão.
3. Hosted admission relê PR/main Noteri, checks tests no Noteri, test e candidate-canary no Worker Pool, issue OWNER/comment/main Worker Pool, regras e blob original.
4. Runner físico com labels self-hosted, Windows, X64, noteri, reqsys-dev e nome Noteri-runtime, ID 21 observado no GitHub.
5. Checkouts por SHA imutável: Noteri PR, Worker Pool, Agent Core, Rules. Session Launcher com preflight real de versão, SESSION_LAUNCH_OK, worktree exclusivo e snapshot SHA-256.
6. Gateway risk 2 cria venv isolado e instala httpx==0.28.1. Não instala nem baixa Qwen.
7. Gateway risk 1 executa o script host versionado; verifica o Git do host e das fontes, Git blob, autorização e main, mede baseline com 42 casos e menos de 42 aprovados, executa Qwen local via IssueRAGResearch, valida digest prefixo dae161e27b0e e seleciona citação de documento público.
8. O script reconsulta a citação em cliente independente e comprova que não houve alteração na árvore rastreada. O JSON emitido é sanitizado e inclui cas_write=false, draft_pr_created=false e state_changed=false.
9. Job hospedado separado lê artifact sanitizado, valida identidade do runner e etapas físicas realmente executadas, issue/comment/main e bytes da citação via API oficial.
10. Watchdog hospedado cancela job que não receba pickup real em 300 segundos.

Qualquer falha de bootstrap, Gateway, Ollama, GitHub API ou evidência bloqueia sem fallback por terminal/RDC/UAC. Nenhum disparo será repetido sem mudança material comprovada e novo CI.

## Recuperação governada do run #40242823952

- O job físico inicial confirmou pickup do Noteri, Session Launcher e instalação isolada de dependências, mas falhou na etapa Risk1 como `ISSUE8_NATIVE_RAG_GATEWAY_BLOCKED`.
- O workflow anterior lançava erro antes de extrair o JSON sanitizado do Gateway, escondendo o código de rejeição do preflight. A recuperação expõe apenas `ISSUE8_SANITIZED_FAILURE=issue8_...` com validação estrita; qualquer falha continua bloqueante.
- O disparo original `OWNER_ISSUE8_NATIVE_RAG_NOTERI_20261025_ONCE` permanece no histórico. A correção só admite nova transição ausência→presença do marcador `OWNER_ISSUE8_NATIVE_RAG_NOTERI_20261025_RECOVERY_ONCE`, pelo OWNER, em PR draft, após testes CI concluídos no novo SHA e revalidação da main. Não incluir o novo marcador antecipadamente.
- Esta etapa é recuperação diagnóstica; não comprova inferência Ollama nem readback independente até um novo E2E físico com recibo validado.

## Limites

Suíte simulada não equivale à inferência física. Mesmo um resultado positivo deste preflight NÃO prova a cadeia Issue→reparo→CAS Git bundle→Validator→draft PR. O próximo incremento é do Worker Pool e requer IssueRAGReceiptCAS e adapter_from_durable_issue_rag com lease/fencing, patch material, CAS real, 42/42 + 52/52, exatamente uma PR draft criada pelo agente e replay independente.

Custo adicional máximo R$0,00. Nenhum Docker no Noteri, segredos no Git ou merge/deploy automático.