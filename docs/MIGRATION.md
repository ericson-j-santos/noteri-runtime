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
