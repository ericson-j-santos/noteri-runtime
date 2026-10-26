# Noteri DEV — leitura administrativa restrita do ERRORLOG SQL

Status em 26/10/2026: **STAGED / NÃO IMPLANTADO / E2E FÍSICO PENDENTE**.
Vínculos: noteri-runtime #36 e PR #64; report-builder-platform #7.

## Objetivo e limites

A autorização específica permite **somente leitura** do argumento de inicialização `-e`
e do `ERRORLOG` ativo de `MSSQL17.MSSQLSERVER`, em **Noteri DEV**.
Ela não permite alterar serviços, certificados, TLS, DSN, logins, ACLs,
privilégios, bancos ou ambientes HML/PROD.

O leitor já existente `noteri_sql_certificate_errorlog.py` consulta apenas
os campos permitidos do Registro, exige instância local SQL 2025 em execução,
perfil NORMAL, SHA de origem, limite de 8 MiB e rejeição de reparse points.
A nova entrada `noteri_sql_admin_errorlog_read.py` exige Windows/Noteri/DEV,
identidade administrativa, confirmação de contexto, SHA/correlação e
`startup_log_argument_verified=true`, recusando o candidato derivado
somente de `SQLPath`. A saída contém **apenas** classificações e flags
conservadoras, sem caminhos, linhas, logins nem impressões digitais do certificado.

## Bloqueio principal: atuador legado em LOCALAPPDATA

O instalador histórico `install_noteri_admin_actuator.py` posiciona código e
dispatcher em `LOCALAPPDATA` antes de criar uma tarefa elevada.
**Não adicionar a capability àquela tarefa, nem usar o arquivo lá
instalado como fonte executável confiável**: não há evidência de ACL administrativa
exclusiva, proteção do código, verificação dos bytes do dispatcher ou identidade
efetiva do usuário da tarefa no Noteri. Não usar `schtasks`, GUI/UAC ou terminal
irrestrito como atalho para obter a leitura.

## Pré-admissão independente (sem elevação)

`scripts/noteri_sql_admin_bundle_gate.py` é uma **sonda somente leitura**,
não é instalador, dispatcher ou concessão de privilégio. Ela verifica apenas
o candidato fixo `C:\ProgramData\ReqSys\NoteriSqlAdminBroker`:

- host Noteri, Windows, SHA hexadecimal completo e ProgramData esperado;
- diretórios existentes, sem reparse points, sob uma raiz privada;
- dono `SYSTEM` ou `Administrators` e DACL explícita que permita somente
  esses dois SIDs; raízes devem ter proteção contra herança insegura;
- os quatro arquivos fixos no subdiretório `bin`, mais `manifest.json`,
  todos regulares, sem symlink/junction, com tamanho limitado;
- manifesto v1 para host `Noteri`, ambiente `dev`, capability
  `sql-errorlog-readonly`, `source_sha` imutável e SHA-256 **dos quatro
  arquivos**:
  `noteri_sql_admin_errorlog_read.py`,
  `noteri_sql_certificate_errorlog.py`,
  `noteri_native_qualification.py` e
  `noteri_sql_admin_bundle_gate.py`.

O manifesto **não** é credencial nem autorização de elevação; o SHA informado
precisa ser conferido por um controlador independente no GitHub. A própria sonda
não deve ser executada elevada a partir de checkout, do diretório do usuário
ou de binários não conferidos. Primeiro o plano de controle **preexistente,
confiável e protegido** precisa validar o destino. Uma verificação feita
pelo próprio binário sob exame não atesta a integridade desse binário antes
de executá-lo.

A sonda retorna `ready` exclusivamente para **pré-admissão** da instalação
e declara `elevated_execution_performed=false` e `sql_read_performed=false`.
Em instalação ausente, ACL insegura, arquivo faltando, digest alterado, SHA
divergente ou direito incomprovado, bloqueia. Em Windows com ACL legítima
diferente, não afrouxar a regra automaticamente; revisar por identidade/SID.

## Critérios obrigatórios antes do uso administrativo real

1. Revalidar `noteri-runtime/main`, PR #64, revisão/CI, regras canônicas e
   identidade do executor; nunca rodar código de PR não revisado em runner físico
   com privilégio. O CI do Linux e do Windows hospedado não prova o host Noteri.
2. **Confirmar** no Noteri um canal de instalação/execução que já seja
   protegido, com arquivos somente administrativamente graváveis e identidade
   restrita. Instalar por promoção auditada de SHA e com rollback/idempotência.
   Não executar a instalação enquanto essa rota não existir comprovadamente.
3. Executar preflight independente e reler permissões e SHA-256 **no destino**.
   Nenhum `ready` emitido de checkout, mock ou outro host libera a instalação.
4. Executar exatamente uma coleta administrativamente autorizada, limitada
   ao Noteri DEV e vinculada a `correlation_id`, `idempotency_key` e SHA;
   fazer readback sanitizado independente no mesmo ambiente. Se não houver
   vínculo válido entre recibo e execução, marcar bloqueio.
5. Somente após diagnóstico, comprovar TLS obrigatório ODBC 18
   (`Encrypt=Yes`, `TrustServerCertificate=No`), DSN DEV aprovado,
   ACL efetiva de leitura, `report-builder sql-preflight` real e o
   E2E Fabric/ReqSys (geração, renderização, exportação e entrega).

Não modificar a main, configurar DNS/DSN, fazer merge, instalar CU10, reiniciar
serviço, elevar privilégio genericamente nem desabilitar validação TLS como
efeito colateral destes testes.

## Critério de evidência

Separar rigorosamente `IMPLEMENTADO`, `VALIDADO_EM_CI`, `E2E_FÍSICO`
e `OPERACIONALMENTE_COMPROVADO`. `not_observed` no Windows Application
EventLog não demonstra que não houve erro de TLS. O `ERRORLOG` é apenas
diagnóstico da inicialização: também não comprova certificado ativo,
cadeia TLS, login ODBC ou permissões SQL. Nenhuma inferência de segurança
se baseia somente em exit code zero ou pipeline verde.
