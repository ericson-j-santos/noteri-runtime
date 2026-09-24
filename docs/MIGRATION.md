# Migração do núcleo NORMAL/ESTUDO

## Fonte

- repositório: `ericson-j-santos/reqsys-v2-enterprise-real`
- SHA de origem: `43d23817d605122d224a5e3619a56848bf2d7888`
- destino: `ericson-j-santos/noteri-runtime`
- branch inicial: `migration/noteri-profile-core`

## Escopo deste incremento

Importa o núcleo específico do Noteri:
- agente local NORMAL/ESTUDO;
- controlador local;
- persistência Windows;
- launcher headless;
- E2E do agente;
- testes unitários associados.

Referências a outro host usadas apenas como caso negativo em testes foram substituídas por `other-host`.

## Compatibilidade temporária

Os caminhos locais históricos do runtime ainda são preservados neste primeiro incremento para não quebrar a instalação existente durante a extração. A mudança desses caminhos deve ocorrer somente com migração de estado e E2E próprios.

## Critério de saída

Este incremento só pode ser considerado migrado quando:
1. CI do novo repositório estiver verde no HEAD exato;
2. E2E real `NORMAL -> ESTUDO -> NORMAL` executar no Noteri;
3. leitura independente confirmar o estado final `NORMAL`;
4. nenhum segredo for publicado;
5. somente então o código equivalente poderá começar a ser removido do ReqSys.


## Incremento operacional — control plane e E2E próprio

Após o núcleo NORMAL/ESTUDO, o próximo corte transfere para este repositório:
- probe do control plane do Noteri;
- watchdog de persistência do runner;
- launcher UAC governado para persistência headless;
- workflows de probe e ativação headless;
- E2E físico próprio do `noteri-runtime`.

O ReqSys permanece temporariamente como consumidor/legado até este incremento estar
na `main`, com CI verde e E2E físico no Noteri no mesmo SHA. Só depois disso o
código equivalente pode começar a ser retirado do repositório de produto.

### Runner físico durante a migração

O runner `noteri/reqsys-dev` atualmente disponível no host Noteri é registrado no
repositório ReqSys e não é automaticamente compartilhado com outro repositório
pessoal. Por isso, o workflow `physical-e2e.yml` deste repositório permanece
`workflow_dispatch` sem gatilho automático de `push` até existir um runner
explicitamente registrado para `noteri-runtime`.

Durante essa transição, a evidência física pode ser produzida pelo harness
governado do ReqSys fazendo checkout do SHA imutável deste repositório. Registrar
um runner próprio exige bootstrap administrativo separado e não é pré-condição
para validar o código extraído.

A evidência física também deve registrar o SHA realmente observado pelo próprio
executor e falhar fechado quando ele divergir do SHA esperado. O valor recebido
por parâmetro não é evidência suficiente de identidade da versão executada.
