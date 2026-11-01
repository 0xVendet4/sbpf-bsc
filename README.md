# VM dentro de VM — Solana rodando dentro da BSC

**Colocamos a máquina virtual da Solana dentro de um contrato na BSC.** Parte 1: uma VM sBPF v0
reduzida e o jogo CU Golf. Parte 2 (abaixo): programas Solana compilados de verdade, com contas,
CPI e PDAs, iguais ao agave, incluindo **o SPL Token oficial da mainnet da Solana publicado e
rodando na BSC testnet**. **Parte 1:** `SbpfVM.sol` é um
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

## Parte 2 — programas Solana de verdade rodando na BSC

A parte 1 é uma VM reduzida (sBPF v0, sem syscalls). A parte 2 roda **programas Solana compilados
de verdade** (arquivos `.so`, sBPF v0 e v3) dentro da EVM, com contas, syscalls, sysvars, CPI e
PDAs, e o resultado é **o mesmo do agave** (o validador da Solana): erro, compute units, log,
return data e contas finais.

```
.so (ELF sBPF v3) ──► SolanaStore.deployProgram ──► código de contrato (SSTORE2), verificado 1 vez
.so (ELF sBPF v0) ──► writeProgram ×N + finalizeProgram ──► SolanaLoader (relocações, como o agave)
instrução (metas + dados) ──► SolanaStore.invoke ──► SolanaRuntime ──► SolanaVM ──(CPI)──► SolanaCpi
                                                       │ serializa as contas (ABIv1)  │ suspende e retoma
                                                       └─ aplica as regras do loader ◄┘ log: SolanaLog
```

| Contrato | O que faz |
|---|---|
| `SolanaVM.sol` | Carregador ELF estrito (SIMD-0189), verificador e interpretador sBPF v3, mapa de memória do agave, syscalls de log, memória, return data, sysvars, sha256/keccak, panic e PDA (`sol_create_program_address`, `sol_try_find_program_address`, curva ed25519 via precompile `modexp`). Numa CPI a VM se suspende e devolve o estado. |
| `SolanaCpi.sol` | `sol_invoke_signed_c` e `sol_invoke_signed_rust` como no agave 4.3: tradução da instrução, dos `AccountInfo` e das seeds, regras de privilégio (signer/writable), assinatura por PDA e o **system program** (CreateAccount, Assign, Transfer, Allocate). |
| `SolanaRuntime.sol` | Serializa as contas (ABIv1 com direct mapping), roda a VM, executa as CPIs e aplica as regras do loader (`deserialize_parameters`: lamports, realloc, dono, saldo). |
| `SolanaLog.sol` | Log no formato do agave (`Program … invoke [1]`, `Program log:`, `consumed X of Y compute units`, `failed: …`). |
| `SolanaLoader.sol` | Carregador de ELF **sBPF v0** (o formato de quase todos os programas da mainnet, como o SPL Token): seções, relocações `R_BPF_64_64`/`64_RELATIVE`/`64_32`, registro de funções por murmur3 e região só leitura **byte a byte iguais ao `Executable::load` do agave**. Roda uma vez, na publicação. |
| `SolanaStore.sol` | Guarda programas e contas Solana na BSC e processa instruções por transação. Programas grandes sobem em pedaços (`writeProgram`) e são carregados em `finalizeProgram`. |

**Conferido contra o agave.** `reference-runtime/` roda os mesmos programas no Mollusk 0.16.4
(agave 4.3, o runtime da mainnet) e grava `fixtures/solana/programs.json`: **65 de 65 cenários
idênticos**, incluindo a memória de input serializada byte a byte. Os programas são os exemplos do
repositório do agave (hello, clock, write-to-account, simple-transfer) e um programa de teste
montado em `reference-runtime/src/main.rs` para PDAs e CPI pela ABI C e Rust com assinatura por
PDA (transfer, create_account, allocate, assign e 20 casos de erro). O ISA v3 bate em
**1.518 de 1.518** casos contra o `solana-sbpf`.

### SPL Token oficial rodando na BSC

O binário do SPL Token que está na mainnet da Solana (o `token.so` do Mollusk 0.16.4, a
reimplementação p-token: 108 KB, sBPF v0, 12.826 instruções) é publicado sem nenhuma alteração no
`SolanaStore` no endereço `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` e responde às instruções
de sempre: InitializeMint2, InitializeAccount3, MintTo, Transfer, TransferChecked, Approve, Revoke,
Burn, CloseAccount, FreezeAccount, SetAuthority, SyncNative e os erros (`InsufficientFunds`,
`OwnerMismatch`, `AccountFrozen`…).

**Conferido contra o agave.** `reference-runtime/` roda **40 cenários** do SPL Token no Mollusk
(com rent ligado) e grava `fixtures/solana/token.json`; a EVM dá o mesmo resultado nos 40 (erro,
código custom, CU, log e contas finais). O carregamento também é conferido: a região só leitura
de 105.744 bytes, os 29 pontos de entrada e a entrada do programa saem iguais ao carregador do
agave (`test/Loader.test.js`).

Na Solana o Transfer custa 76 CU; aqui também, e custa **~1,05 M de gás** na BSC (≈ 0,0001 BNB a
0,1 gwei).

### Na BSC testnet (deploy de 2026-11-01, v2 com o carregador v0)

| Contrato | Endereço |
|---|---|
| `SolanaVM` | [`0xcD7EacC778218cF789D1cE5740a667c05d26610E`](https://testnet.bscscan.com/address/0xcD7EacC778218cF789D1cE5740a667c05d26610E) |
| `SolanaCpi` | [`0xF43dA7CE1a50a06a516dE09A1289f9Ff2e69055C`](https://testnet.bscscan.com/address/0xF43dA7CE1a50a06a516dE09A1289f9Ff2e69055C) |
| `SolanaLog` | [`0x4d57137b664c11524a1c8D8A27c1171405A86f24`](https://testnet.bscscan.com/address/0x4d57137b664c11524a1c8D8A27c1171405A86f24) |
| `SolanaRuntime` | [`0x5DB7829346dDBc6Ef37c2E209EB467421311e579`](https://testnet.bscscan.com/address/0x5DB7829346dDBc6Ef37c2E209EB467421311e579) |
| `SolanaLoader` | [`0xCeA431eEB87d8ECe5255E7d2c7E119a9E4F8abc0`](https://testnet.bscscan.com/address/0xCeA431eEB87d8ECe5255E7d2c7E119a9E4F8abc0) |
| `SolanaStore` | [`0xdc164254E5E50BbFE643D5CaA8C14BE9fA6971AA`](https://testnet.bscscan.com/address/0xdc164254E5E50BbFE643D5CaA8C14BE9fA6971AA) |

SPL Token publicado e usado de verdade (`deployments/bscTestnet-token-demo.json`):

| O que | CU | Gás | Tx |
|---|---|---|---|
| Publicar o SPL Token: 5 pedaços de ≤24 KB | | 4 × ~5,25 M + 2,25 M | [1º pedaço](https://testnet.bscscan.com/tx/0x8558037185571c1a168e65d6566209d89448e853b775ffe7dfb76f61edd90d46) |
| `finalizeProgram`: carregar o ELF v0 on-chain e verificar | | 12,380,757 | [tx](https://testnet.bscscan.com/tx/0x4489a09bba091ed28077b4d1949c09a6134331ce8e0e15d752e837cc79ae2265) |
| `InitializeMint2` (6 casas) | 202 | 965,688 | [tx](https://testnet.bscscan.com/tx/0x250a5ff314a437c167374ab69980c341de377b18a35adcc61dc587d95b8dba94) |
| `InitializeAccount3` | 233 | 1,087,333 | [tx](https://testnet.bscscan.com/tx/0x0143ad12bb6d03bcecd2700f3c78eb04135c748515b26ca8f0077ea355bb517f) |
| `MintTo` 1,000000 | 120 | 1,093,019 | [tx](https://testnet.bscscan.com/tx/0x9ecf274067a9d7e8573c46f99756587dfc75ae37c9c4a1a55dea04b8ba9508fa) |
| `Transfer` 0,250000 de A para B | 76 | 1,049,334 | [tx](https://testnet.bscscan.com/tx/0x98377247e95bdd42cd6bc719dd81788468a5f82ed42f3e371e4f7174e74e29f9) |

Saldos finais lidos do `SolanaStore`: supply 1.000.000, A 750.000, B 250.000 (unidades mínimas).

O primeiro deploy da parte 2 (só sBPF v3) continua no ar em `deployments/bscTestnet-solana-v1.json`,
com as transações abaixo:

| O que | Gás | Tx |
|---|---|---|
| Publicar o `simple_transfer_program` (54 KB, verificado no deploy) | 15,398,950 | [tx](https://testnet.bscscan.com/tx/0x7564535f330b832203ad3a43b93508f6742f8bb4c25541dae4d13d4952eb04c8) |
| `hello`: o programa loga "Hello, Solana!" | 217,997 | [tx](https://testnet.bscscan.com/tx/0x9dd25127ebe1838e76a6c2ffe4da4d2be4e137822fd426548c11ec6008b5909b) |
| CPI: programa compilado chama o system program e transfere 2500 lamports | 2,870,110 | [tx](https://testnet.bscscan.com/tx/0x97c6bfca5aebced830530601e1139d2ca1b96cd8b6a303a16b41c6369207fdf6) |
| PDA: `try_find_program_address(["vault"])` on-chain | 267,364 | [tx](https://testnet.bscscan.com/tx/0xe8dce6929b6d96753d2460538095ab7787a25a5cecf5e6f37544f02653dfec3c) |
| Cofre PDA: o programa assina pela conta derivada e paga 1234 lamports | 712,776 | [tx](https://testnet.bscscan.com/tx/0x2084d7f034a208de324e85b4b6936ee37cfa66d6429f6407b0a927f2522d562a) |

Reproduzir: `npx hardhat run scripts/deploy-solana.js --network bscTestnet` (com `REUSE=SolanaVM,…`
reaproveita contratos já publicados com o mesmo bytecode), depois `scripts/token-demo.js` (SPL
Token) e `scripts/solana-demo.js` (programas v3). O cliente mínimo, com chaves, PDAs e as
instruções do SPL Token, está em `scripts/solana-client.js`.

### Como usar o `SolanaStore`

- **Chaves e assinaturas.** Uma chave Solana (32 bytes) é assinada por `msg.sender` quando os 20
  últimos bytes são o endereço dele; cada endereço controla 2^96 chaves (prefixo de 12 bytes).
  PDAs são derivados como na Solana e só o programa dono assina por eles (seeds na CPI).
- **Lamports são wei.** `deposit(key)` credita o BNB enviado; `withdraw(key, lamports, to)` saca.
- **System program direto:** `transfer`, `createAccount`, `allocate`, `assign`.
- **Programas:** `deployProgram(programId, elf)` publica numa transação (até ~50 KB por causa do
  limite de 16,7 M de gás por transação da BSC); acima disso, `writeProgram(programId, pedaço)`
  várias vezes e `finalizeProgram(programId)` (só quem abriu o upload). O formato (v0 ou v3) é
  detectado pelo cabeçalho do ELF. `invoke(programId, metas, data, cuLimit)` roda a
  instrução e emite `Invoked` com CU, return data e o log; falha reverte com
  `ProgramFailed(err, custom, logs)` (err = índice do `InstructionError` + 1). `simulate(…, signer)`
  roda sem gravar.

### Limites da parte 2

- **CPI só para o system program** (CreateAccount, Assign, Transfer, Allocate). O SPL Token roda
  chamado direto, mas um programa sBPF ainda não chama outro (por exemplo o Associated Token
  Account chamando o SPL Token): erro explícito. Ainda não testamos um programa Anchor completo.
- **Sem taxas.** Lamports são wei. A sysvar Rent existe com os valores do agave (6960 lamports por
  byte), então os programas que exigem conta isenta de rent (como o SPL Token) funcionam igual.
- **Programas v0 grandes custam ~1 M de gás por instrução** porque a imagem só leitura (106 KB no
  SPL Token) é montada a cada execução; guardar a imagem pronta é a próxima otimização.
- **Quem publica.** Um programa é publicado por quem assina a chave dele, e a carteira que fez o
  deploy do `SolanaStore` (gênese) pode publicar em ids ainda livres, como `Tokenkeg…`. Na mainnet
  isso precisa de governança.
- Syscalls não implementadas: secp256k1_recover, curvas (ed25519/ristretto/bn128), poseidon,
  blake3, sha512, big_mod_exp, epoch stake, sibling instructions, `sol_alloc_free_` (devolvem erro
  explícito).
- **Gás:** ~200 k para uma instrução pequena, 0,5–0,8 M com contas e CPI simples, ~2,9 M para a CPI
  do programa de 54 KB (o ELF é copiado entre os contratos). Publicar um programa custa ~280 gás por
  byte (SSTORE2 + verificação).
- **Não auditado.** Testnet apenas. A mainnet (parte 3) usa carteira nova.

## Parte 1 na BSC testnet (chain 97)

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

## Prova de fraude de um passo (`SbpfVM.step` + `SbpfDispute`)

Rodar um programa Solana inteiro na BSC custa ~530 gas por instrução, o que inviabiliza programas
reais (50 mil a 200 mil CU viram 26 a 106 milhões de gas). A saída é a fase 3 da spec: executar
fora da cadeia e **provar na cadeia só a instrução em disputa**.

- `SbpfVM.State` = (pc, cu, halted, status, r0..r10, keccak da pilha de 4 KiB). O compromisso é
  `stateHash(State)`; o estado inicial é fixo (`initialState()`).
- `SbpfVM.step(State, pilha, program, input, maxCu)` executa exatamente uma instrução. O mesmo loop
  Yul de `execute` roda com orçamento de 1, então não há duas semânticas: `contracts/test/Step.test.js`
  aplica `step` até parar em todos os 1.769 fixtures que passam no verificador (54 mil instruções)
  e exige o mesmo (status, r0, cu) de `execute`. Um passo custa **~51k gas** (a pilha inteira vai
  em calldata; sem Merkle, de propósito: 4 KiB é barato na BSC e elimina uma classe de bugs).
  `trace(..., orçamento)` devolve também a pilha, para o provador gerar os estados intermediários.
- `SbpfDispute`: alguém afirma "`execute(program, input, maxCu)` para após N instruções em
  `endHash`" com caução; qualquer um contesta com a mesma caução; bisseção (quem afirmou posta o
  hash do meio, quem contestou escolhe o lado) até sobrar uma instrução; `prove` roda esse passo no
  SbpfVM e decide (**~106k gas**). Quem não joga no prazo perde; o vencedor leva as duas cauções.
  Afirmações não contestadas viram `Confirmed` e `result(id)` fica disponível para outros
  contratos. Testes em `contracts/test/Dispute.test.js`: afirmação honesta, falsa no fim, falsa no
  meio, número de instruções errado, abandono de cada lado, provas com programa/input trocados.
  Para isqrt(u64::MAX), 327 instruções, a disputa inteira leva 9 rodadas de bisseção.

Na testnet: `SbpfVM` v2 (com `step`) em [`0xF910103187F855Fb6aa5F0826Ac43E4f4C7Acc49`](https://testnet.bscscan.com/address/0xF910103187F855Fb6aa5F0826Ac43E4f4C7Acc49)
e `SbpfDispute` em [`0x3d5346d0291ECB33c9bb93c31Dbb52db2a75D07F`](https://testnet.bscscan.com/address/0x3d5346d0291ECB33c9bb93c31Dbb52db2a75D07F)
(caução 0,001 BNB, janela de contestação 8000 blocos, 4000 por jogada). Uma disputa inteira foi
jogada on-chain (`scripts/dispute-demo.js`, transações em `deployments/bscTestnet-dispute-demo.json`):
A afirmou isqrt(u64::MAX) com r0 errado, B contestou, 9 rodadas de bisseção (~37k gas quem posta,
~40k quem escolhe) e a [prova do passo 326→327](https://testnet.bscscan.com/tx/0xb59378df44c3d5f9765c5ee59a8e32b87688ef13c702a205d07b6b00b047053f)
(100k gas) derrubou a afirmação; B recebeu as duas cauções. Custo total da disputa para o
contestador: ~0,0005 BNB em gas.

O que isto ainda não é: o programa continua sem syscalls e sem contas (próxima fase), e o input
entra inteiro no passo final (para inputs grandes, trocar por Merkle).

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
npm test                                   # 36 testes: diferencial, passo único, disputa, golf, bounty, seed, assembler JS
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

0. Parte 2: CPI de um programa sBPF para outro (hoje só o system program; o próximo alvo é o
   Associated Token Account chamando o SPL Token), guardar a imagem v0 pronta (hoje ~1 M de gás por
   instrução do SPL Token), prova de fraude com memória em Merkle para a VM v3, menos gás na CPI
   (não copiar o ELF entre contratos), exemplo Anchor.
1. Verificar os contratos no BscScan (deploy na testnet feito; falta a verificação, ver acima).
2. Gás: ~530 → meta 300–400 por instrução (despacho por tabela de saltos em Yul, menos `byte()` na
   decodificação, registradores r0..r3 em variáveis).
3. Fase 2: mini-EVM como programa Solana (referência `revm`, mesma metodologia).
4. Fase 3: `step(preStateRoot, provas) → postStateRoot` para prova de fraude de um passo; os mesmos
   fixtures servem para testar.
