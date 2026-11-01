# Solana dentro da BSC — interpretador sBPF em Solidity

Uma VM dentro da VM: bytecode **sBPF** (o formato dos programas Solana) executado
**dentro da EVM** da BNB Smart Chain, mais um token cujo mint só acontece se um
programinha sBPF rodar on-chain e retornar sucesso.

```
programs/*.s ──(js/assembler.js)──► bytecode sBPF ──► SbpfVM.sol (EVM/BSC)
                                         │
                                         └──► js/vm.js (mesma semântica, off-chain: minerador + oráculo de testes)
```

## O que tem aqui

| Arquivo | O que faz |
|---|---|
| `contracts/SbpfVM.sol` | Interpretador sBPF (biblioteca). Registradores r0–r10, mapa de memória do Solana, syscalls, compute budget. |
| `contracts/SolanaRuntime.sol` | "Cluster" mínimo: `deploy` de programas (bytecode guardado via SSTORE2), conta de dados persistente por programa, `invoke` (grava estado e emite logs), `simulate` e `execute` (playground). |
| `contracts/ProofOfExecutionToken.sol` | Token BEP-20 **POE**: o mint exige um nonce que faça o puzzle sBPF retornar 0. O contrato reexecuta o programa para verificar. |
| `js/vm.js` | VM de referência em JS (BigInt), idêntica à de Solidity. |
| `js/assembler.js` | Montador sBPF (labels, rodata com `.ascii`, `call` para syscalls por nome). |
| `js/miner.js`, `scripts/mine.js` | Minerador: roda o **mesmo bytecode** off-chain até achar o nonce. |
| `programs/` | `hello.s`, `fib.s` (chamadas internas), `counter.s` (estado persistente), `keccak.s` (syscall), `puzzle.s` (mineração). |

## Design

### Escopo do sBPF suportado
- **ALU64 e ALU32**: add, sub, mul, div, or, and, lsh, rsh, neg, mod, xor, mov, arsh; `le16/32/64` e `be16/32/64`.
  Semântica do **sBPF v1 (rbpf)**: `add32/sub32/mul32` estendem o sinal para 64 bits, as demais operações de 32 bits zeram a parte alta. Shifts mascarados (`&63` / `&31`). Divisão ou mod por zero gera erro.
- **Memória**: `ldx{b,h,w,dw}`, `st{b,h,w,dw}`, `stx{b,h,w,dw}`, `lddw` (instrução de 16 bytes).
- **Saltos**: ja, jeq, jgt, jge, jset, jne, jsgt, jsge, jlt, jle, jslt, jsle (imediato ou registrador).
- **Chamadas**: `call` com `src=1` é chamada interna relativa ao pc (estilo SBPFv2+), `callx rN` (alvo em `src`), `exit`. Cada chamada salva r6–r9 e abre um frame novo de pilha (r10 += 4 KiB). Profundidade máxima 4.
- **Syscalls** (identificadas pelo hash murmur3 do nome, igual ao Solana): `sol_log_`, `sol_log_64_`, `sol_log_compute_units_`, `sol_keccak256` (usa o keccak **nativo** da EVM), `sol_memcpy_`, `sol_memmove_`, `sol_memset_`, `sol_memcmp_`, `abort`, `sol_panic_`.

Fora do escopo por enquanto: carregar ELF (o input é bytecode cru, .text + rodata), relocations, CPI, contas múltiplas, sha256/secp256k1/ed25519, verificador estático.

### Mapa de memória (igual ao Solana)
| Endereço | Região | Tamanho |
|---|---|---|
| `0x1_0000_0000` | programa (somente leitura, .text + rodata) | tamanho do bytecode |
| `0x2_0000_0000` | pilha | 4 frames × 4 KiB |
| `0x3_0000_0000` | heap | 4 KiB |
| `0x4_0000_0000` | input (leitura e escrita) | tamanho do input |

Na entrada, `r1` aponta para o input e `r10` para o topo do frame 0.

### Gas e limites
- **~1.080 gas por instrução sBPF** (medido com `npm run gas`).
- 1 compute unit por instrução, 100 CU por syscall (+ custo por byte em keccak/mem*). O chamador passa o `computeBudget`; se estourar, reverte com `ComputeBudgetExceeded`.
- Na prática o teto é o gas do bloco: uns 100 mil instruções por transação na BSC.
- Mint do POE: puzzle de 366 instruções → **~514 mil gas** por mint (centavos na BSC).
- Invoke do contador (`counter.s`) com estado persistente: ~84 mil gas.

### Token POE (Proof of Execution)
- Input do puzzle: `[32 bytes seed = keccak(challenge, minerador)][u64 nonce][u64 alvo]`.
- O puzzle (`programs/puzzle.s`) faz 32 rodadas de mistura ARX/multiplicação e retorna `0` se `hash < alvo`.
- O minerador acha o nonce **off-chain rodando o mesmo bytecode sBPF** na VM JS (~11 mil execuções/s num core). O contrato **reexecuta on-chain** para verificar.
- O seed inclui o endereço do minerador, então copiar o nonce de outra pessoa não funciona (front-running).
- O challenge muda a cada mint (corrida entre mineradores, estilo 0xBitcoin).
- Recompensa: 50 POE, halving a cada 100 mil mints, teto de 21 milhões.
- A dificuldade se reajusta a cada 32 mints mirando 60 s por mint (ajuste limitado a 4× por vez).
- O puzzle é imutável (`puzzleHash` público). Qualquer pessoa pode auditar o que está sendo executado.

### Por que sBPF-em-Solidity e não mini-EVM-como-programa-Solana?
- **sBPF em Solidity (o que está aqui)**: sBPF é simples (instruções de 8 bytes, 11 registradores, sem gas dinâmico), então cabe num interpretador on-chain auditável. O custo é alto por instrução (~1k gas), mas a BSC tem bloco grande e gas barato.
- **Mini-EVM no Solana**: o limite de 1,4M CU por transação e a semântica de storage/gas da EVM tornam um interpretador EVM útil bem mais caro e complexo (já existe gente fazendo isso, como Neon EVM). Para uma demo com "wow", o sentido BSC ← Solana é mais enxuto e verificável.

## Como usar

```bash
npm install
npm test                    # compila e roda os 47 testes
npm run test:offline        # idem, usando o solc-js do npm (sem baixar o compilador)
npm run gas                 # gas por instrução
node scripts/asm.js programs/hello.s

# BSC testnet
export PRIVATE_KEY=0x...
npx hardhat run scripts/deploy.js --network bscTestnet
TOKEN=0x... ROUNDS=3 npx hardhat run scripts/mine.js --network bscTestnet
```

Escrevendo um programa:

```asm
    lddw r1, msg          ; endereço na rodata
    mov64 r2, 19
    call sol_log_         ; syscall pelo nome
    mov64 r0, 0           ; 0 = sucesso
    exit
msg:
    .ascii "Hello from sBPF/BSC"
```

## Testes
- Testes de cada opcode com casos de borda, conferidos na VM Solidity **e** na VM JS.
- Testes de erro: divisão por zero, acesso fora das regiões, escrita no programa, estouro de budget, profundidade de chamada, syscall abort, instrução inválida.
- **Fuzz diferencial**: 300 programas aleatórios (ALU, saltos, load/store, byteswap) executados nas duas VMs. O r0, as compute units e o tipo de erro precisam ser iguais.
- Runtime: deploy, estado persistente, revert quando o programa falha, simulate, budget.
- Token: mineração com a VM JS + mint verificado on-chain, nonce inválido, prova amarrada ao minerador, retarget.

Limitação honesta: as duas VMs foram escritas juntas, então o fuzz pega bugs de implementação, mas não divergências em relação ao rbpf/Agave. O próximo passo de validação é rodar os mesmos programas no `solana-sbpf` real e comparar.

## Próximos passos
1. Otimizar o loop (meta: ~300–400 gas/instrução): pc, steps e registradores em variáveis locais/assembly, despacho por tabela.
2. Loader de ELF simples para rodar programas compilados com `cargo build-sbf` (sem relocations primeiro).
3. Validação cruzada contra o `solana-sbpf`.
4. Front-end "playground": colar assembly, ver os registradores passo a passo, rodar on-chain.
