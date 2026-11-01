# VM dentro de VM — Solana rodando dentro da BSC

**Colocamos a máquina virtual da Solana dentro de um contrato na BSC.** `SbpfVM.sol` é um
interpretador de bytecode **sBPF v0** (o formato dos programas Solana) escrito em Solidity. Ele
executa programas Solana instrução por instrução, on-chain, e o resultado bate bit a bit com a VM
oficial: **2.024 de 2.024 fixtures gerados pelo `solana-sbpf` são idênticos**, incluindo 1.000
programas aleatórios.

Em cima dela, o **CU Golf**: um token (GOLF) cujo mint exige rodar programas Solana dentro do
contrato. Ganha quem escrever o programa que gasta menos compute units.

```
programs/*.s ──assembler do solana-sbpf──► bytecode ──► reference/ (VM oficial, Rust) ──► fixtures/*.json
                                                 │                                              │
                                                 └──► contracts/src/SbpfVM.sol (EVM) ◄── teste diferencial
```

## Na BSC testnet (chain 97)

Segundo deploy, 2026-11-01, por `0x3D4c4eBDeeCd265FC744E10c445be9Df89361013` (≈ 0,0007 tBNB a
0,1 gwei). Endereços, argumentos do construtor e versão do compilador em
[`deployments/bscTestnet.json`](deployments/bscTestnet.json); o primeiro deploy (janelas de 400/200
blocos, hoje expiradas) está em `deployments/bscTestnet-v1.json`.

| Contrato | Endereço |
|---|---|
| `SbpfVM` | [`0xD9C7AF9165B190AdD2264853f2f6b4Aa4Bd6649F`](https://testnet.bscscan.com/address/0xD9C7AF9165B190AdD2264853f2f6b4Aa4Bd6649F) |
| `GolfToken` (GOLF) | [`0xa5aA84562DfF099f8ba8F4FcD06Eb584de006dF8`](https://testnet.bscscan.com/address/0xa5aA84562DfF099f8ba8F4FcD06Eb584de006dF8) |
| `SbpfGolf` | [`0xb12C68f3e567A3eCEEc7eaf232d9f8CcfEc368ae`](https://testnet.bscscan.com/address/0xb12C68f3e567A3eCEEc7eaf232d9f8CcfEc368ae) |
| `BountyBoard` | [`0x69D156d4523B68b09BEB02881f487949Ae6B7f3F`](https://testnet.bscscan.com/address/0x69D156d4523B68b09BEB02881f487949Ae6B7f3F) |

Parâmetros: taxa de entrada 10 GOLF (50% queimada), 100 rodadas grátis, commit 8000 blocos (~1 h a
0,45 s/bloco), reveal 4000 blocos (~30 min), taxa de bounty 5 GOLF. `GolfToken.minter` =
`SbpfGolf`; `SbpfGolf.bountyBoard` = `BountyBoard`. O bytecode on-chain confere com os artefatos
locais (tamanho e hash de metadados).

No primeiro deploy uma rodada inteira foi jogada on-chain (rodada 2, isqrt, 904 CU, reveal com 721k
gas, 100 GOLF mintados: [reveal](https://testnet.bscscan.com/tx/0x391fe4442540be47581f0699307fcf8d30c5c41dbd1ea8e92764539cf090b140),
[finalize](https://testnet.bscscan.com/tx/0x1c2fc1c85e77849f00265f837586abfdc0afbe1a84245bf5894ed983ea80554f)).

### Seed além de 256 blocos (EIP-2935)

A seed da rodada é o hash do último bloco de commit. `blockhash` só enxerga 256 blocos (~2 min na
BSC), o que obrigava janelas de reveal de minutos. `BlockSeed.sol` lê o contrato de histórico da
EIP-2935 (`0x0000F908…2935`, ativo na BSC desde o Pascal), que guarda 8191 hashes (~1 h), e o reveal
pode ir até 8000 blocos. Se mesmo assim o hash não existir, o reveal reverte com `SeedUnavailable`
em vez de aceitar seed zero. Nos testes o contrato de histórico é um mock instalado com
`hardhat_setCode` (`contracts/test/Seed.test.js`).

### Página para jogar (`web/`)

`web/index.html` é uma página estática (sem build) para jogar pela MetaMask: mostra a rodada,
monta o assembly no navegador, testa o programa de graça (`judge` via `eth_call`), faz commit e
reveal, fecha a rodada e lista o placar pelos eventos. O assembler em JS (`web/sbpf-asm.js`) é um
port do assembler do `solana-sbpf` 0.26.0 e é validado contra ele: `reference/` grava em
`fixtures/asm.json` tudo o que montou (programas de teste, sintaxe difícil, casos de erro e os
programas aleatórios desmontados pelo disassembler oficial), e `contracts/test/Asm.test.js` exige
os mesmos bytes e os mesmos erros (2060/2060). Para servir localmente:
`cd web && python3 -m http.server 8000`. O salt do commit fica no `localStorage` do navegador, com
um backup copiável na página.

## Números reais

| | |
|---|---|
| Referência | `solana-sbpf` **0.26.0** (`SBPFVersion::V0`), fixado em `reference/Cargo.toml` |
| Compilador | Solidity **0.8.28**, optimizer 10.000 runs, evm `cancun`, sem via-IR |
| Fixtures iguais | **2.024 / 2.024**: 818 por opcode, 114 de memória, 52 rejeitados/inválidos, 40 de programas demo, **1.000 / 1.000 aleatórios** |
| Gás por instrução sBPF | **~530 gas** em loops longos (medido com `npm run gas`) |
| Custo fixo por execução | ~33 k gas (tx + verificador + setup da VM, programa de 1 instrução) |

Gás dos programas demo (`fixtures/programs.json`, maior input de cada um):

| Programa | Input | CU | Gás total | Gás/instrução* |
|---|---|---|---|---|
| fib | n = 255 | 1790 | 972 531 | ~525 |
| popcount | 0xffffffffffffffff | 388 | 232 045 | ~515 |
| isqrt | 0xffffffffffffffff | 327 | 210 822 | ~546 |
| gcd | (832040, 514229) | 172 | 139 167 | ~622 |
| max8 | 8 × u64 | 23 | 70 296 | ~1 700 |
| hello | — | 7 | 42 420 | ~1 600 |

\* (gás total − custo fixo) / CU. Programas curtos pagam proporcionalmente mais pelo custo fixo.

Loops longos: 2 002 instruções → 1,10 M gas; 20 002 → 10,7 M; 100 002 → 53,1 M (~531 gas/instrução,
constante). No limite de bloco da BSC (140 M) cabem uns 250 mil instruções por transação.

CU Golf (teste local): reveal de `popcount` em 4 inputs = 1 552 CU, **~983 k gas**.

## Limites, sem maquiagem

- **Reduzido de propósito.** Só ALU64, ALU32, saltos de 64 bits, LDX/ST/STX, `lddw` e `exit`.
  **Sem syscalls** (`sol_log`, hashes…), **sem `call`/`callx`**, sem accounts, sem CPI, sem heap,
  sem rodata, sem carregamento de ELF. `call`/`callx` passam no verificador (como na referência) e
  falham na execução com `Invalid`, exatamente o que a referência devolve nesta configuração.
- **sBPF v0 apenas.** Versões mais novas (v1–v4) mudam opcodes e semântica; não misture.
- **Lento em gás.** ~530 gas por instrução é umas 100× o custo de uma operação EVM nativa. Serve
  para rotinas puras de poucos milhares de instruções, não para rodar um programa Solana de verdade.
- **Memória mínima.** Pilha de 4 KiB em `0x2_0000_0000` (leitura/escrita) e input em
  `0x4_0000_0000` (somente leitura). Qualquer outro endereço é `AccessViolation`.
- **Não é bridge, não é validador, não é produção.** É uma demo verificável.
- **O que o teste diferencial garante e o que não garante.** Garante que, para os 2.024 fixtures
  (inclusive os aleatórios), status, `r0` e CU são iguais aos da VM oficial na mesma configuração
  (regiões iguais, sem syscalls, `max_call_depth = 1`). Não garante equivalência para instruções fora
  do subconjunto nem para configurações diferentes da referência.

## O que tem aqui

| Caminho | O que é |
|---|---|
| `reference/` | Harness Rust. Monta `programs/*.s` com o assembler do `solana-sbpf`, executa na VM oficial e grava `fixtures/*.json`. Também gera os 1.000 programas aleatórios (seed fixa). |
| `fixtures/` | JSON gerado pela referência (commitado). Formato na seção abaixo. |
| `programs/` | Programas demo em assembly sBPF: `fib`, `popcount`, `isqrt`, `max8`, `gcd`, `hello`. |
| `contracts/src/SbpfVM.sol` | Interpretador + verificador. `run()` **nunca reverte** por erro do programa: devolve `Status`. |
| `contracts/src/Tasks.sol` | As 5 tarefas do golf com gerador de input e implementação nativa (aritmética de 64 bits com wraparound, igual à VM). |
| `contracts/src/SbpfGolf.sol` | O jogo: rodadas de commit-reveal, taxa de entrada, leilão da próxima tarefa, mint do prêmio. |
| `contracts/src/GolfToken.sol` | ERC-20 (OpenZeppelin) com `minter` único (o SbpfGolf) e teto de 21 M. |
| `contracts/src/BountyBoard.sol` | Bounties de código otimizado, pagos em qualquer ERC-20, julgados on-chain contra um programa de referência. |
| `contracts/test/` | `Differential` (lê `fixtures/` e compara tudo), `Golf`, `Bounty`. |
| `scripts/` | `gas.js` (benchmark), `deploy.js`, `verify.js`, `play.js` (joga uma rodada). |
| `web/` | Página para jogar (MetaMask) e o assembler sBPF em JS. |

### Interface da VM

```solidity
enum Status { Ok, Invalid, DivideByZero, AccessViolation, CuExceeded }

/// Executa um programa sBPF. Nunca reverte por erro do programa: devolve o status.
function run(bytes calldata program, bytes calldata input, uint64 maxCu)
    external pure returns (Status status, uint64 r0, uint64 cuUsed);

function verify(bytes calldata program) public pure returns (bool);
```

`Invalid` cobre o que a referência rejeita no verificador (opcode desconhecido, salto fora do
programa ou para o meio de um `lddw`, escrita em r10, shift por imediato ≥ largura, divisão por
imediato zero, `lddw` incompleto…) e o que ela aborta em execução fora do subconjunto (`call`,
`callx`, sair do fim do programa sem `exit`).

Na entrada: `r1 = 0x4_0000_0000` (input), `r10 = 0x2_0000_1000` (topo da pilha), demais zero.
1 CU por instrução executada (`lddw` conta 1). O medidor checa **antes** de executar, igual à
referência: com `maxCu = 2`, um programa de 3 instruções devolve `CuExceeded`.

### Formato do fixture

```json
{
  "name": "fib_3",
  "program": "0x79110000000000...",
  "input": "0x0a00000000000000",
  "maxCu": 5000,
  "expect": { "status": "Ok", "r0": "0x37", "cu": 75 }
}
```

Em caso de erro só o `status` é comparado (o CU consumido até o erro não faz parte do contrato).

## Mecânica do token: CU Golf

1. **Tarefa conhecida antes do commit**: a vencedora do leilão da rodada anterior; sem lances,
   `round % 5` (fib, popcount, isqrt, max8, gcd).
2. **Commit** (janela de `COMMIT_BLOCKS`): `keccak256(abi.encode(msg.sender, round, keccak256(program), salt))`
   e paga a taxa de entrada em GOLF (zero nas `FREE_ROUNDS` primeiras rodadas, porque ninguém tem GOLF antes do primeiro mint).
3. **Seed** = `blockhash` do último bloco de commit, gravada no primeiro reveal. A janela de reveal
   tem no máximo 250 blocos, então o blockhash ainda existe.
4. **Reveal**: o contrato confere o commit, verifica o programa (≤ 256 instruções), executa em
   **K = 4** inputs derivados da seed (`maxCu = 5 000` cada), compara cada `r0` com a implementação
   nativa em `Tasks.sol` e soma os CU. Resposta errada reverte com `ProgramRejected`.
5. **Vencedor**: menor CU total. Empate → commit mais antigo.
6. **Finalize**: qualquer um chama depois da janela. O vencedor recebe o mint da rodada
   (100 GOLF, metade a cada 1 000 rodadas, teto de 21 M) mais as taxas de entrada da rodada. Sem
   vencedor, o prêmio acumula.

Por que não dá para trapacear: as entradas vêm de um blockhash posterior ao commit (nada de
hardcode); o commit fecha antes de qualquer reveal e inclui o endereço (nada de copiar); só o melhor
da rodada ganha (Sybil não ajuda).

### Utilidade do token (só o que já funciona no contrato)

- **Taxa de entrada** (`SbpfGolf.commit`): `ENTRY_FEE` em GOLF por commit, `ENTRY_BURN_BPS` queimado,
  o resto vai para o prêmio da rodada. Quem comita e não revela perde a taxa.
- **Bounties de código otimizado** (`BountyBoard`): quem posta deposita o prêmio em qualquer ERC-20,
  queima `BOUNTY_FEE` em GOLF e publica um programa sBPF de referência (lento, mas correto) com casos
  de borda. Candidatos disputam por commit-reveal; o contrato roda referência e candidato nos mesmos
  inputs (4 aleatórios da seed + casos de borda), descarta inputs em que a referência falha e exige
  `r0` igual nos demais. Menor CU ganha, pagamento automático. Só funções puras, porque é o que a VM
  reduzida suporta; o resultado é assembly sBPF, útil para quem otimiza programas Solana à mão.
- **Leilão da próxima tarefa** (`SbpfGolf.bid`): oferta em GOLF por uma tarefa da lista ou por um
  bounty ativo (`1000 + id`). A maior oferta vence e é queimada; as perdedoras são devolvidas
  (`claimRefund`). Com um bounty como tarefa, a correção usa o programa de referência do bounty.

Nenhuma promessa de valorização ou retorno. Token com promessa de lucro pode ser valor mobiliário
(CVM); taxa de entrada somada a prêmio pode cair em regra de jogos. Validar com advogado antes da
mainnet. O blockhash pode ser levemente influenciado por validadores: aceitável para um jogo, não
para prêmios altos.

Parâmetros iniciais (constructor de `SbpfGolf` e `BountyBoard`, ajustar depois de medir):
K = 4, `maxCu` = 5 000 por input, programa ≤ 256 instruções, reveal ≤ 250 blocos; `scripts/deploy.js`
usa taxa 10 GOLF (50 % queimada), 100 rodadas grátis, commit 400 blocos, reveal 200 blocos, taxa de
bounty 5 GOLF.

## Como reproduzir

```bash
# 1. Fixtures a partir da VM oficial (Rust 1.7x; baixa o solana-sbpf 0.26.0)
cd reference && cargo run --release        # grava ../fixtures/*.json (1000 aleatórios; passe outro N como argumento)
cd ..

# 2. Contratos e testes (Node 22)
npm install                                # .npmrc liga legacy-peer-deps (conflito de peer do hardhat-chai-matchers)
npm test                                   # 20 testes: diferencial (5 conjuntos), golf, bounty, seed EIP-2935, assembler JS
npm run gas                                # tabela de gás

# Sem acesso a binaries.soliditylang.org? Use o solc-js do npm (mesma versão 0.8.28):
USE_SOLCJS=1 npm test
```

Deploy na BSC testnet:

```bash
export PRIVATE_KEY=0x...        # carteira com tBNB (RPC padrão: bsc-testnet-rpc.publicnode.com; troque com BSC_TESTNET_RPC)
npx hardhat run scripts/deploy.js --network bscTestnet          # grava deployments/bscTestnet.json
ETHERSCAN_API_KEY=... npx hardhat run scripts/verify.js --network bscTestnet
GOLF=0x... PROGRAM=programs/isqrt.s npx hardhat run scripts/play.js --network bscTestnet   # commit; depois reveal; depois finalize
```

Verificação no BscScan: a chave da Etherscan API V2 serve para a BSC, mas o plano grátis não cobre
essa chain ("Free API access is not supported for this chain"). Sem plano pago, use o formulário
em `testnet.bscscan.com/verifyContract` para cada endereço: tipo *Solidity (Standard-Json-Input)*,
compilador `v0.8.28+commit.7893614a`, licença MIT, arquivo
[`deployments/verify/standard-input.json`](deployments/verify/standard-input.json) (o mesmo para os
quatro), nome do contrato `contracts/src/<Nome>.sol:<Nome>` e, para `SbpfGolf` e `BountyBoard`, os
argumentos do construtor de `constructorArgsAbiEncoded` em `deployments/bscTestnet.json`.

Escrevendo um programa (sintaxe do assembler do `solana-sbpf`; `;` inicia comentário):

```asm
; popcount: input [u64 x] -> r0
    ldxdw r1, [r1+0]
    mov64 r0, 0
loop:
    jeq r1, 0, done
    mov64 r2, r1
    and64 r2, 1
    add64 r0, r2
    rsh64 r1, 1
    ja loop
done:
    exit
```

## Decisões e desvios da especificação

- **Hardhat em vez de Foundry.** O ambiente onde isto foi construído não permitiu instalar o
  Foundry (download de binários externos bloqueado). Os contratos são independentes de framework;
  os testes são em JS (`contracts/test/`). Uma port para `forge test` lendo `fixtures/` com
  `vm.parseJson` é direta.
- **Seed** = `blockhash(commitEnd)` puro, como na spec.
- **`call`/`callx`** aceitos pelo verificador e rejeitados na execução, espelhando a referência (que
  devolve `UnsupportedInstruction` / `CallDepthExceeded` → `Invalid`).
- **Taxa de entrada zero nas primeiras rodadas** (`FREE_ROUNDS`): a spec não cobre o bootstrap, e
  sem isso ninguém consegue comitar na rodada 1.

## Próximos passos

1. Verificar os contratos no BscScan (deploy na testnet feito; falta a verificação, ver acima).
2. Gás: ~530 → meta 300–400 por instrução (despacho por tabela de saltos em Yul, menos `byte()` na
   decodificação, registradores r0..r3 em variáveis).
3. Fase 2: mini-EVM como programa Solana (referência `revm`, mesma metodologia).
4. Fase 3: `step(preStateRoot, provas) → postStateRoot` para prova de fraude de um passo; os mesmos
   fixtures servem para testar.
