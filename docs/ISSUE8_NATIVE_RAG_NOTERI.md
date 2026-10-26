# Noteri — Issue #8 Qwen + RAG real, canário físico de somente leitura

## Posição na cadeia do primeiro ciclo autônomo

Objetivo global: Issue/TODO autorizado → reparo Qwen real → commit material → CAS SHA → Validator independente → PR draft única → readback/replay.

Este incremento qualifica o primeiro elo que ainda não foi comprovado: issue #8 com autorização OWNER e SHA da main atual → baseline real dos 42 casos → plano e citação produzidos pelo Qwen instalado no Noteri. Não executa Builder de código, não adquire lease, não escreve CAS, não publica branch/PR de reparo nem usa Docker físico. A PR de infraestrutura não é uma PR do agente.

## Identidades fixas na admissão

- Worker Pool main: 047c77b6b867ff5d489bd74f6fd80989719ab85e
- Blob Git do app/portfolio_bridge.py: d9a25c574163c49f695e774609949160d94f4490
- Comentário OWNER issue #8: 6423646539, comando literal atrelado à main
- Agent Core: 1fc032d4c412bdb4ed202cf1193caf0cb49490ce
- Regras operacionais: 8af10e2cf85f18f14ba12fbbeb4afc8b8320bbe8 (1.6.19)
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


## Recuperação de integridade do workflow após integração da PR #59

- O run físico #40242823952 comprovou que houve pickup do runner Noteri e que o Session Launcher/venv passaram, mas o comando Risk1 falhou. O código de rejeição interno foi perdido pelo tratamento de exceções do workflow anterior.
- A PR #59 foi integrada no commit `78ebd2e3cb7ebe2629af54184e91bc319875e294` com uma regressão acidental: uma substituição de texto duplicou o fim do arquivo YAML. A CI existente passou porque não executava análise sintática real do workflow.
- Esta recuperação reconstrói o YAML a partir da versão íntegra, mantendo os controles de admissão. Adiciona teste de parsing real com Ruby/Psych na suíte obrigatória de CI e leitura de motivo de falha sanitizado (`ISSUE8_SANITIZED_FAILURE`), sem mostrar mensagens potencialmente sensíveis ou permitir sucesso quando houver bloqueio.
- Novo canário permitido somente na branch `fix/issue8-native-rag-yaml-gate-20261025`, com nova transição de marcador apenas após CI no SHA novo. Nenhum marcador de disparo deve constar inicialmente no corpo da PR. Não considerar testes estáticos como substituição da prova física.

## Diagnóstico de motivo RAG com allowlist compatível

No run #40247054777, a fase foi `research` mas o Gateway mostrou `issue8_gateway_execution_unavailable`: o filtro PowerShell do workflow só aceitava prefixo `issue8_`, enquanto o executor Python valida códigos confiáveis adicionais `rag_`, `github_`, `native_`, `context_`, `main_` e `owner_`. O workflow passou a aceitar exatamente o mesmo padrão estático seguro da saída Python, sem mostrar texto livre da exceção ou alterar o fail-closed. Novo canário é one-shot somente após CI no SHA atualizado.

## Limites

Suíte simulada não equivale à inferência física. Mesmo um resultado positivo deste preflight NÃO prova a cadeia Issue→reparo→CAS Git bundle→Validator→draft PR. O próximo incremento é do Worker Pool e requer IssueRAGReceiptCAS e adapter_from_durable_issue_rag com lease/fencing, patch material, CAS real, 42/42 + 52/52, exatamente uma PR draft criada pelo agente e replay independente.

Custo adicional máximo R$0,00. Nenhum Docker no Noteri, segredos no Git ou merge/deploy automático.
## Correção: leitura canônica do objeto Git no Windows

O canário #40245535354, já com diagnóstico sanitizado, encontrou
`issue8_source_blob_drift`. A API oficial mantém blob
`d9a25c574163c49f695e774609949160d94f4490`, portanto o
problema ocorre na verificação dos bytes materializados pelo checkout.
A hipótese técnica principal é `core.autocrlf` no Git for Windows: a
árvore pode estar limpa apesar de LF ter sido convertido em CRLF.

A correção usa `git show HEAD:app/portfolio_bridge.py` (comando fixo,
somente leitura) para obter bytes do Git blob sob o commit verificado.
Também exige que os bytes do checkout sejam **idênticos ao blob ou exatamente
à sua variante CRLF**, não aceita alterações mistas, continua exigindo
Git status limpo e revalida os três checkouts e os bytes após a inferência.
Nenhum teste foi enfraquecido e nenhum comando é escolhido pelo modelo.

Reexecução física deve usar o marcador novo `OWNER_ISSUE8_NATIVE_RAG_NOTERI_20261025_BLOB_NORMALIZATION_ONCE` somente após CI
passar no SHA corrente. Não reutilizar os gatilhos anteriores.

## Falha física seguinte: fase sanitizada

O run #40246401909 falhou no Gateway com `issue8_native_dependency_unavailable`,
sem voltar a registrar `issue8_source_blob_drift`. Isso demonstra mudança
na classificação, mas não comprova a causa-raiz do próximo bloqueio.
Agora cada fase interna do script é identificada por um nome fixo
(`identity/checkouts/agent_core/imports/owner/baseline/model/research/readback`).
O runner publica somente `ISSUE8_SANITIZED_PHASE` e `ISSUE8_SANITIZED_FAILURE`,
sem logs livres ou segredos. A exceção de uma biblioteca sem código conhecido
não se transforma em texto arbitrário. Um novo disparo só é elegível após
CI e transição exclusiva do marcador `OWNER_ISSUE8_NATIVE_RAG_NOTERI_20261025_PHASE_DIAGNOSTIC_ONCE`.


## Diagnóstico de inventário local do Qwen (26/10/2026)

O job físico [#40247590037](https://github.com/ericson-j-santos/noteri-runtime/actions/runs/40247590037) comprovou pickup, Session Launcher e venv, mas falhou na fase `research` com `native_model_ambiguous_or_missing`. O Worker Pool exige exatamente a etiqueta `qwen2.5-coder:7b` e o digest fixado `dae161e27b0e`; a mensagem anterior não diferencia etiqueta ausente de duplicidade. A biblioteca oficial Ollama publica o mesmo digest também sob `qwen2.5-coder:latest`, mas isso **não** comprova qual etiqueta está instalada no Noteri.

Antes do RAG, o mesmo executor Risk1 agora consulta somente `GET /api/tags` no Ollama de loopback e devolve um código sanitizado e determinístico: `issue8_model_tag_missing`, `issue8_model_pinned_under_other_tag` ou `issue8_model_tag_duplicate`. Se a etiqueta estiver presente, mantém todas as validações do Worker Pool (digest, GGUF e ausência de modelo remoto); nenhum resultado pode liberar a execução por si só. Testes positivos e negativos entram no CI.

A nova admissão física one-shot usa o marcador `OWNER_ISSUE8_NATIVE_RAG_NOTERI_20261026_POST_MODEL_READY_ONCE` em transição exclusiva pelo OWNER, somente após CI concluído no novo HEAD. A recuperação de alias ou download não ocorre neste workflow read-only: requer diagnóstico real, autorização separada de mudança de estado e execução governada via Session Launcher/Gateway, com verificação independente. Nenhum re-run sem nova precondição, sem Docker, sem gastos, sem publicação, merge ou deploy.


## Observação governada de armazenamento Ollama (26/10/2026)

- O modelo `qwen2.5-coder:7b` não foi encontrado na última sonda física.
- Adicionado modo somente leitura `--inspect-ollama-model-store` no script existente da PR #60; somente Noteri/Windows com Session Launcher e Gateway. A inspeção exige 10 GiB livres no volume do armazenamento de modelos **e** uma comparação SHA-256 de pelo menos um manifesto local com o digest retornado pela API local Ollama. Assim, diretório existente isoladamente não equivale a daemon comprovado.
- Este modo não instala modelos nem habilita inferência; código de falha sanitizado, sem caminhos de usuários nos logs. A admissão RAG deve usar agora Worker Pool 047c77b6b867ff5d489bd74f6fd80989719ab85e, autorização OWNER #6423646539 e regras 8af10e2cf85f18f14ba12fbbeb4afc8b8320bbe8 no SHA atual; controles e E2E independentes continuam obrigatórios.
