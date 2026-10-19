# Janela de qualificação Noteri: NORMAL temporário, retorno a ESTUDO

Este incremento implementa somente uma janela de inventário nativo no Noteri.
Ele não equivale a qualificação GitHub Actions, conexão SQL ou homologação HML.

A entrada `scripts/noteri_qualification_window.py` exige confirmação específica,
SHA completo e correlação. Deve ser executada pelo Session Launcher/Command
Gateway, em worktree isolado. Reutiliza o agente de perfil e a sonda existentes.

## Controles

- Exige perfil ESTUDO real e vinculado ao Noteri antes de abrir NORMAL.
- Registra intenção de restauração antes de alterar o perfil; usa lock local
  exclusivo para janelas e confere propriedade da alteração por correlação.
- Repete inventário nativo em duas leituras e testa rejeição de SHA incorreto.
- Consulta o listener e a configuração do watchdog sem iniciar, registrar,
  desbloquear ou elevar privilégios do runner. Não lê credenciais do runner.
- Retorna a ESTUDO em `finally` e verifica o resultado independentemente.
- A mesma correlação/SHA concluída não reabre a janela.
- Interrupção abrupta que impeça `finally` deixa journal pendente. A próxima
  invocação restaura somente a janela anterior e não abre outra.
- Não sobrescreve mudança de perfil identificada como pertencente a outro autor.
  Nesse conflito, mantém restauração pendente e sinaliza bloqueio.
- Não oferece shell, SQL livre, operação arbitrária, deploy ou consumo de fila.

A janela não é um mecanismo de alta disponibilidade. Falha física, desligamento
ou encerramento forçado do processo podem impedir restauração imediata; o journal
preserva a obrigação de recuperação. Outros escritores do perfil precisam
respeitar a exclusividade; não há compare-and-swap global entre aplicações.

A execução do Gateway deve possuir timeout superior ao limite combinado das
sondas fixas e à restauração. Não cancelar o processo enquanto a restauração
estiver em andamento, salvo risco maior comprovado.

## Evidência e aceite

O journal `qualification-window.json` fica junto ao perfil operacional, fora do
repositório. A saída identifica o SHA, correlação, inventário, abertura,
fechamento e restauração. `hml_verified=false` e `actions_qualified=false`
permanecem explícitos, mesmo com inventário aprovado.

25 testes de controle da janela passaram em sandbox após a última alteração,
sem skipped, com arquivos temporários reais e observações sintéticas. Controle
de mutação comprovou que remover o retorno a ESTUDO faz o teste positivo falhar;
a implementação foi restaurada e os testes reexecutados.

A evidência física e o CI do SHA publicado devem ser registrados na mesma
PR #28 e TODO-37. Não reutilizar inventário de outro SHA como aceite do incremento.
