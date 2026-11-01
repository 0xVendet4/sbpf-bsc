// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title SbpfVM — interpretador sBPF v0 (formato legado dos programas Solana) em Solidity
/// @notice Executa um programa sBPF instrução por instrução dentro da EVM. A semântica segue o
///         crate `solana-sbpf` 0.26.0 (`interpreter.rs` e `verifier.rs`, SBPFVersion::V0) e é
///         conferida pelos fixtures em `fixtures/`, gerados pela VM oficial.
///
///         Subconjunto suportado: ALU64, ALU32, JMP (64 bits), LDX, ST, STX, lddw, exit.
///         Fora do subconjunto: call/callx, syscalls, heap, rodata, ELF, accounts, CPI.
///         `call`/`callx` passam no verificador (como na referência) e falham na execução com
///         `Invalid`, que é o que a referência também devolve (UnsupportedInstruction /
///         CallDepthExceeded com max_call_depth = 1).
///
/// @dev Mapa de memória:
///         0x2_0000_0000  pilha, 4 KiB, leitura/escrita (um único frame; r10 aponta para o topo)
///         0x4_0000_0000  input, somente leitura
///      Registradores: r0..r9 de uso geral, r10 = frame pointer (somente leitura).
///      Compute units: 1 por instrução executada (lddw conta 1).
contract SbpfVM {
    enum Status {
        Ok,
        Invalid,
        DivideByZero,
        AccessViolation,
        CuExceeded
    }

    uint64 public constant STACK_START = 0x200000000;
    uint64 public constant STACK_SIZE = 4096;
    uint64 public constant INPUT_START = 0x400000000;

    uint256 private constant VM_BYTES = 4512; // 352 (regs) + 4096 (pilha) + ip + cu
    uint256 private constant IP_OFF = 4448;
    uint256 private constant CU_OFF = 4480;
    uint256 private constant RUNNING = 0x100; // _exec: não parou dentro do orçamento

    /// @notice Verifica e executa um programa. Nunca reverte por erro do programa: devolve o status.
    /// @param program bytecode sBPF (múltiplo de 8 bytes)
    /// @param input   bytes mapeados em INPUT_START (r1 aponta para eles)
    /// @param maxCu   limite de compute units (instruções)
    /// @return status resultado da execução
    /// @return r0     valor de retorno (0 quando status != Ok)
    /// @return cuUsed compute units consumidas (inclui a instrução que falhou)
    function run(bytes calldata program, bytes calldata input, uint64 maxCu)
        external
        pure
        returns (Status status, uint64 r0, uint64 cuUsed)
    {
        if (!verify(program)) return (Status.Invalid, 0, 0);
        return execute(program, input, maxCu);
    }

    // ------------------------------------------------------------------ verificador

    /// @notice Verificador estático, equivalente ao `RequisiteVerifier` do solana-sbpf para V0.
    function verify(bytes calldata program) public pure returns (bool) {
        uint256 len = program.length;
        if (len == 0 || len % 8 != 0) return false;
        uint256 n = len / 8;
        uint256 base = 0;
        assembly {
            base := program.offset
        }

        unchecked {
            for (uint256 i = 0; i < n; i++) {
                uint256 opc;
                uint256 dst;
                uint256 src;
                int256 off;
                int256 imm;
                assembly {
                    let w := calldataload(add(base, mul(i, 8)))
                    opc := byte(0, w)
                    dst := and(byte(1, w), 0x0f)
                    src := shr(4, byte(1, w))
                    off := signextend(1, or(byte(2, w), shl(8, byte(3, w))))
                    imm := signextend(3, or(or(byte(4, w), shl(8, byte(5, w))), or(shl(16, byte(6, w)), shl(24, byte(7, w)))))
                }
                uint256 cls = opc & 7;
                uint256 op = opc & 0xf0;
                bool isReg = (opc & 8) != 0;
                bool store = false;

                if (cls == 7 || cls == 4) {
                    // ALU64 / ALU32
                    if (op == 0xd0) {
                        // le (0xd4) / be (0xdc): só ALU32, imm ∈ {16, 32, 64}
                        if (cls != 4) return false;
                        if (imm != 16 && imm != 32 && imm != 64) return false;
                    } else if (op > 0xc0) {
                        return false;
                    } else if (op == 0x80) {
                        // neg: só a forma sem registrador (0x84 / 0x87)
                        if (isReg) return false;
                    } else if (!isReg) {
                        if ((op == 0x30 || op == 0x90) && imm == 0) return false; // div/mod por imediato 0
                        if (op == 0x60 || op == 0x70 || op == 0xc0) {
                            // shift por imediato: 0 <= imm < bits
                            if (imm < 0 || imm >= (cls == 7 ? int256(64) : int256(32))) return false;
                        }
                    }
                } else if (cls == 5) {
                    // JMP
                    if (op == 0x00) {
                        if (isReg) return false; // ja = 0x05
                        if (!_jumpOk(base, n, i, off)) return false;
                    } else if (op == 0x80) {
                        // 0x85 call (resolvido em execução), 0x8d callx (imm = registrador alvo)
                        if (isReg && (imm < 0 || imm >= 10)) return false;
                    } else if (op == 0x90) {
                        if (isReg) return false; // exit = 0x95
                    } else if (op > 0xd0) {
                        return false;
                    } else {
                        if (!_jumpOk(base, n, i, off)) return false;
                    }
                } else if (cls == 1) {
                    if ((opc & 0xe7) != 0x61) return false; // ldx{w,h,b,dw}
                } else if (cls == 2) {
                    if ((opc & 0xe7) != 0x62) return false; // st{w,h,b,dw}
                    store = true;
                } else if (cls == 3) {
                    if ((opc & 0xe7) != 0x63) return false; // stx{w,h,b,dw}
                    store = true;
                } else if (opc == 0x18) {
                    // lddw: não pode ser a última instrução e o slot seguinte precisa ter opcode 0
                    if (i + 1 >= n) return false;
                    uint256 nextOpc;
                    assembly {
                        nextOpc := byte(0, calldataload(add(base, mul(add(i, 1), 8))))
                    }
                    if (nextOpc != 0) return false;
                    i++;
                } else {
                    return false;
                }

                // registradores: src <= 10; dst <= 9, ou dst == 10 apenas em stores
                if (src > 10) return false;
                if (dst > 10 || (dst == 10 && !store)) return false;
            }
        }
        return true;
    }

    function _jumpOk(uint256 base, uint256 n, uint256 i, int256 off) private pure returns (bool) {
        unchecked {
            int256 t = int256(i) + 1 + off;
            if (t < 0 || t >= int256(n)) return false;
            uint256 targetOpc;
            assembly {
                targetOpc := byte(0, calldataload(add(base, mul(t, 8))))
            }
            return targetOpc != 0; // não pode pular para o meio de um lddw
        }
    }

    // ------------------------------------------------------------------ interpretador

    /// @notice Executa um programa já verificado. Chamar sem `verify` em bytecode arbitrário não é
    ///         seguro para a equivalência com a referência (opcodes desconhecidos são tratados
    ///         como `Invalid`, mas registradores fora de r0..r10 não são checados).
    function execute(bytes calldata program, bytes calldata input, uint64 maxCu)
        public
        pure
        returns (Status status, uint64 r0, uint64 cuUsed)
    {
        uint256 codeOff;
        uint256 inPacked;
        uint256 vm;
        assembly ("memory-safe") {
            codeOff := program.offset
            inPacked := or(shl(128, input.offset), input.length)
            vm := mload(0x40)
            mstore(0x40, add(vm, VM_BYTES))
            for { let p := vm } lt(p, add(vm, VM_BYTES)) { p := add(p, 32) } { mstore(p, 0) }
            mstore(add(vm, 32), INPUT_START) // r1 = input
            mstore(add(vm, 320), add(STACK_START, STACK_SIZE)) // r10 = topo da pilha
        }
        uint256 st = _exec(vm, codeOff, program.length / 8, inPacked, maxCu, type(uint256).max);
        uint256 ret;
        uint256 cu;
        assembly ("memory-safe") {
            ret := mload(vm)
            cu := mload(add(vm, CU_OFF))
        }
        status = Status(st);
        r0 = st == 0 ? uint64(ret) : 0;
        cuUsed = uint64(cu);
    }

    // ------------------------------------------------------------------ passo único (prova de fraude)

    /// @notice Estado da VM entre duas instruções. `keccak256(abi.encode(State))` é o compromisso
    ///         usado na bisseção; `stackHash` = keccak256 dos 4096 bytes da pilha.
    struct State {
        uint64 pc;
        uint64 cu;
        bool halted;
        Status status; // válido quando halted
        uint64[11] regs;
        bytes32 stackHash;
    }


    error StateHalted();
    error BadStack();

    /// @notice Estado inicial de `execute(program, input, maxCu)` (não depende de program/input).
    function initialState() public pure returns (State memory s) {
        s.regs[1] = INPUT_START;
        s.regs[10] = STACK_START + STACK_SIZE;
        s.stackHash = keccak256(new bytes(STACK_SIZE));
    }

    function stateHash(State memory s) public pure returns (bytes32) {
        return keccak256(abi.encode(s));
    }

    /// @notice Executa exatamente uma instrução a partir de `s`. Equivalência: para todo programa
    ///         verificado, aplicar `step` até `halted` dá o mesmo (status, r0, cu) que `execute`
    ///         (contracts/test/Step.test.js).
    /// @param s       estado anterior (não pode estar parado)
    /// @param stack   os 4096 bytes da pilha em `s` (conferidos contra `s.stackHash`)
    /// @param program bytecode já verificado (quem chama confere o hash)
    /// @param input   input (quem chama confere o hash)
    function step(State calldata s, bytes calldata stack, bytes calldata program, bytes calldata input, uint64 maxCu)
        external
        pure
        returns (State memory t)
    {
        (t,) = _steps(s, stack, program, input, maxCu, 1);
    }

    /// @notice Executa até `budget` instruções a partir de `s` e devolve também a pilha resultante.
    ///         Para uso fora da cadeia (gerar os estados intermediários da bisseção).
    function trace(State calldata s, bytes calldata stack, bytes calldata program, bytes calldata input, uint64 maxCu, uint256 budget)
        external
        pure
        returns (State memory t, bytes memory stackOut)
    {
        uint256 vm;
        (t, vm) = _steps(s, stack, program, input, maxCu, budget);
        stackOut = new bytes(STACK_SIZE);
        assembly ("memory-safe") {
            mcopy(add(stackOut, 32), add(vm, 352), 4096)
        }
    }

    function _steps(State calldata s, bytes calldata stack, bytes calldata program, bytes calldata input, uint64 maxCu, uint256 budget)
        private
        pure
        returns (State memory t, uint256 vm)
    {
        if (s.halted) revert StateHalted();
        if (stack.length != STACK_SIZE || keccak256(stack) != s.stackHash) revert BadStack();
        uint256 codeOff;
        uint256 inPacked;
        assembly ("memory-safe") {
            codeOff := program.offset
            inPacked := or(shl(128, input.offset), input.length)
            vm := mload(0x40)
            mstore(0x40, add(vm, VM_BYTES))
            calldatacopy(vm, add(s, 128), 352) // regs (uint64[11] fixo: 5º slot do struct)
            calldatacopy(add(vm, 352), stack.offset, 4096)
            mstore(add(vm, IP_OFF), calldataload(s)) // pc
            mstore(add(vm, CU_OFF), calldataload(add(s, 32))) // cu
        }
        uint256 st = _exec(vm, codeOff, program.length / 8, inPacked, maxCu, budget);
        t.halted = st != RUNNING;
        t.status = t.halted ? Status(st) : Status.Ok;
        assembly ("memory-safe") {
            mstore(t, mload(add(vm, IP_OFF)))
            mstore(add(t, 32), mload(add(vm, CU_OFF)))
            let regs := mload(add(t, 128))
            for { let i := 0 } lt(i, 11) { i := add(i, 1) } {
                mstore(add(regs, mul(i, 32)), mload(add(vm, mul(i, 32))))
            }
            mstore(add(t, 160), keccak256(add(vm, 352), 4096))
        }
    }

    /// @dev Loop principal em Yul. Poucas variáveis locais de propósito (limite da pilha da EVM).
    ///      `vm` aponta para 11 palavras de registradores, 4096 bytes de pilha, ip e cu.
    ///      `inPacked` = (offset do input em calldata) << 128 | (tamanho do input).
    ///      Executa até parar ou até `budget` instruções; devolve o Status, ou RUNNING se não parou.
    function _exec(uint256 vm, uint256 codeOff, uint256 n, uint256 inPacked, uint256 maxCu, uint256 budget)
        private
        pure
        returns (uint256 st)
    {
        assembly ("memory-safe") {
            let regs := vm

            // lê `size` bytes little-endian a partir dos bytes mais altos da palavra w
            function le(w, size) -> v {
                for { let i := 0 } lt(i, size) { i := add(i, 1) } { v := or(v, shl(mul(i, 8), byte(i, w))) }
            }
            // traduz um endereço virtual para leitura; devolve (ok, palavra lida)
            function load(vaddr, size, regs_, inp) -> ok, w {
                let s := sub(vaddr, 0x200000000)
                if lt(s, 4096) {
                    if iszero(gt(add(s, size), 4096)) {
                        ok := 1
                        w := mload(add(add(regs_, 352), s))
                    }
                    leave
                }
                let q := sub(vaddr, 0x400000000)
                let inlen := and(inp, 0xffffffffffffffffffffffffffffffff)
                if lt(q, inlen) {
                    if iszero(gt(add(q, size), inlen)) {
                        ok := 1
                        w := calldataload(add(shr(128, inp), q))
                    }
                }
            }
            // escreve `size` bytes little-endian na pilha (única região gravável)
            function store(vaddr, size, value, regs_) -> ok {
                let s := sub(vaddr, 0x200000000)
                if lt(s, 4096) {
                    if iszero(gt(add(s, size), 4096)) {
                        ok := 1
                        let p := add(add(regs_, 352), s)
                        for { let i := 0 } lt(i, size) { i := add(i, 1) } {
                            mstore8(add(p, i), byte(sub(31, i), value))
                        }
                    }
                }
            }
            function bswap(v, nbytes) -> out {
                for { let i := 0 } lt(i, nbytes) { i := add(i, 1) } {
                    out := or(shl(8, out), and(shr(mul(8, i), v), 0xff))
                }
            }
            function offset(w) -> o {
                o := signextend(1, or(byte(2, w), shl(8, byte(3, w))))
            }
            function memsize(opc) -> size {
                size := 4
                switch and(opc, 0x18)
                case 0x08 { size := 2 }
                case 0x10 { size := 1 }
                case 0x18 { size := 8 }
            }

            let ip := mload(add(vm, 4448))
            let cu := mload(add(vm, 4480))
            st := 0x100 // RUNNING
            for {} 1 {} {
                if iszero(budget) { break }
                budget := sub(budget, 1)
                st := 0 // qualquer `break` abaixo é uma parada; o fim do corpo volta a RUNNING
                // medidor de instruções: igual à referência, checa antes de executar
                if iszero(lt(cu, maxCu)) {
                    st := 4
                    break
                }
                cu := add(cu, 1)
                if iszero(lt(ip, n)) {
                    st := 1 // ExecutionOverrun
                    break
                }
                let w := calldataload(add(codeOff, shl(3, ip)))
                let opc := byte(0, w)
                let dstp := add(regs, shl(5, and(byte(1, w), 0x0f)))
                let imm := or(or(byte(4, w), shl(8, byte(5, w))), or(shl(16, byte(6, w)), shl(24, byte(7, w))))
                ip := add(ip, 1)

                switch and(opc, 7)
                case 7 {
                    // ---------------- ALU64 (imediato estendido com sinal)
                    let a := mload(dstp)
                    let b := and(signextend(3, imm), 0xffffffffffffffff)
                    if and(opc, 8) { b := mload(add(regs, shl(5, shr(4, byte(1, w))))) }
                    switch and(opc, 0xf0)
                    case 0x00 { a := and(add(a, b), 0xffffffffffffffff) }
                    case 0x10 { a := and(sub(a, b), 0xffffffffffffffff) }
                    case 0x20 { a := and(mul(a, b), 0xffffffffffffffff) }
                    case 0x30 {
                        if iszero(b) {
                            st := 2
                            break
                        }
                        a := div(a, b)
                    }
                    case 0x40 { a := or(a, b) }
                    case 0x50 { a := and(a, b) }
                    case 0x60 { a := and(shl(and(b, 63), a), 0xffffffffffffffff) }
                    case 0x70 { a := shr(and(b, 63), a) }
                    case 0x80 { a := and(sub(0, a), 0xffffffffffffffff) }
                    case 0x90 {
                        if iszero(b) {
                            st := 2
                            break
                        }
                        a := mod(a, b)
                    }
                    case 0xa0 { a := xor(a, b) }
                    case 0xb0 { a := b }
                    case 0xc0 { a := and(sar(and(b, 63), signextend(7, a)), 0xffffffffffffffff) }
                    default {
                        st := 1
                        break
                    }
                    mstore(dstp, a)
                }
                case 4 {
                    // ---------------- ALU32
                    let a := and(mload(dstp), 0xffffffff)
                    let b := imm
                    if and(opc, 8) { b := and(mload(add(regs, shl(5, shr(4, byte(1, w))))), 0xffffffff) }
                    switch and(opc, 0xf0)
                    // add/sub/mul: resultado i32 estendido com sinal para 64 bits (sBPF v0)
                    case 0x00 { a := and(signextend(3, add(a, b)), 0xffffffffffffffff) }
                    case 0x10 { a := and(signextend(3, sub(a, b)), 0xffffffffffffffff) }
                    case 0x20 { a := and(signextend(3, mul(a, b)), 0xffffffffffffffff) }
                    case 0x30 {
                        if iszero(b) {
                            st := 2
                            break
                        }
                        a := div(a, b)
                    }
                    case 0x40 { a := or(a, b) }
                    case 0x50 { a := and(a, b) }
                    case 0x60 { a := and(shl(and(b, 31), a), 0xffffffff) }
                    case 0x70 { a := shr(and(b, 31), a) }
                    case 0x80 { a := and(sub(0, a), 0xffffffff) }
                    case 0x90 {
                        if iszero(b) {
                            st := 2
                            break
                        }
                        a := mod(a, b)
                    }
                    case 0xa0 { a := xor(a, b) }
                    case 0xb0 { a := b }
                    case 0xc0 { a := and(sar(and(b, 31), signextend(3, a)), 0xffffffff) }
                    case 0xd0 {
                        // le (0xd4): só trunca; be (0xdc): inverte os bytes
                        a := mload(dstp)
                        switch imm
                        case 16 { a := and(a, 0xffff) }
                        case 32 { a := and(a, 0xffffffff) }
                        if and(opc, 8) { a := bswap(a, shr(3, imm)) }
                    }
                    default {
                        st := 1
                        break
                    }
                    mstore(dstp, a)
                }
                case 5 {
                    // ---------------- JMP / exit / call
                    switch opc
                    case 0x05 { ip := add(ip, offset(w)) }
                    case 0x95 { break }
                    default {
                        if eq(and(opc, 0xf0), 0x80) {
                            // call / callx: fora do subconjunto (sem syscalls, sem frames)
                            st := 1
                            break
                        }
                        let a := mload(dstp)
                        let b := and(signextend(3, imm), 0xffffffffffffffff)
                        if and(opc, 8) { b := mload(add(regs, shl(5, shr(4, byte(1, w))))) }
                        switch and(opc, 0xf0)
                        case 0x10 { a := eq(a, b) }
                        case 0x20 { a := gt(a, b) }
                        case 0x30 { a := iszero(lt(a, b)) }
                        case 0x40 { a := iszero(iszero(and(a, b))) }
                        case 0x50 { a := iszero(eq(a, b)) }
                        case 0x60 { a := sgt(signextend(7, a), signextend(7, b)) }
                        case 0x70 { a := iszero(slt(signextend(7, a), signextend(7, b))) }
                        case 0xa0 { a := lt(a, b) }
                        case 0xb0 { a := iszero(gt(a, b)) }
                        case 0xc0 { a := slt(signextend(7, a), signextend(7, b)) }
                        case 0xd0 { a := iszero(sgt(signextend(7, a), signextend(7, b))) }
                        default {
                            st := 1
                            break
                        }
                        if a { ip := add(ip, offset(w)) }
                    }
                }
                case 1 {
                    // ---------------- LDX: dst = *(size*)(src + off)
                    let a := mload(add(regs, shl(5, shr(4, byte(1, w)))))
                    let ok, mw := load(and(add(a, offset(w)), 0xffffffffffffffff), memsize(opc), regs, inPacked)
                    if iszero(ok) {
                        st := 3
                        break
                    }
                    mstore(dstp, le(mw, memsize(opc)))
                }
                case 2 {
                    // ---------------- ST: *(size*)(dst + off) = imm (estendido com sinal)
                    if iszero(store(and(add(mload(dstp), offset(w)), 0xffffffffffffffff), memsize(opc), signextend(3, imm), regs)) {
                        st := 3
                        break
                    }
                }
                case 3 {
                    // ---------------- STX: *(size*)(dst + off) = src
                    let a := mload(add(regs, shl(5, shr(4, byte(1, w)))))
                    if iszero(store(and(add(mload(dstp), offset(w)), 0xffffffffffffffff), memsize(opc), a, regs)) {
                        st := 3
                        break
                    }
                }
                default {
                    // ---------------- lddw (0x18): 16 bytes, imm64 = imm | imm2 << 32
                    if iszero(eq(opc, 0x18)) {
                        st := 1
                        break
                    }
                    w := calldataload(add(codeOff, shl(3, ip)))
                    mstore(dstp, or(imm, shl(32, or(or(byte(4, w), shl(8, byte(5, w))), or(shl(16, byte(6, w)), shl(24, byte(7, w)))))))
                    ip := add(ip, 1)
                }
                st := 0x100
            }
            mstore(add(vm, 4448), ip)
            mstore(add(vm, 4480), cu)
        }
    }
}
