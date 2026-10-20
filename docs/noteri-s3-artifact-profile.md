# Perfil S3 mínimo no Noteri

Este incremento qualifica somente as dependências do transporte de artefatos S3
do Engineering Worker Pool. Ele não instala o serviço FastAPI, não recebe
credenciais, não cria cliente S3, não acessa o bucket e não executa tarefa.

O workflow `noteri-s3-artifact-profile.yml` separa dois gates:

- o job hospedado confere o contrato no SHA imutável do Worker Pool e executa os
  controles positivos e negativos;
- o job hospedado também produz, a partir do checkout imutável das regras, um
  bundle mínimo do Gateway vinculado ao mesmo run e com hashes/tamanhos
  conferidos contra o `MANIFEST.json` canônico;
- o job físico, permitido somente em push do proprietário no prefixo dedicado ou
  em dispatch explícito, baixa esse artifact do próprio run, valida novamente a
  vinculação e todos os bytes e então usa Session Launcher, preflight de versão
  do runner e Command Gateway antes de instalar qualquer pacote. Não há segundo
  checkout remoto de regras no PC e o Gateway persistente do host não é
  presumido atual nem modificado por esta qualificação.

No host, o script baixa apenas `requirements-s3-artifact.txt` do commit fixado,
confere o conteúdo byte a byte e executa pip com arquivos de configuração
desativados, índice público explícito, `--isolated`, `--only-binary=:all:` e
`--no-cache-dir`, sem depender do cache local ou do cache de artefatos do Codex.
O ambiente temporário fica fora do repositório, dentro do
namespace governado `C:\dev\chatgpt-workers`, e é removido antes da emissão de
sucesso. Um processo Python isolado comprova que `boto3` e `botocore` foram
carregados desse ambiente e que não há extensão nativa.

A evidência não contém caminhos absolutos nem saída do pip. Ela registra SHA do
runtime, regras e Worker Pool, versões importadas, correlação e controles
negativos. `transport_ready` permanece falso por desenho: ainda faltam entrega
protegida da identidade técnica, preflight real do bucket e execução cercada de
uma tarefa canônica.
