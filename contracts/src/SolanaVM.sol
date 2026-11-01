// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title SolanaVM — máquina virtual sBPF v3 com o ambiente de execução dos programas Solana
/// @notice Executa o bytecode de um programa Solana real (ELF .so compilado para sBPF v3, o formato
///         da mainnet) dentro da EVM: carregador ELF estrito, verificador, interpretador com frames
///         de chamada, mapa de memória por regiões (rodata, pilha, heap, input de contas) e as
///         syscalls do runtime (logs, memória, return data, sysvars, hashes) com o custo em compute
///         units do agave.
///
///         Semântica: `solana-sbpf` 0.23/0.26 (`interpreter.rs`, `verifier.rs`, `elf.rs`,
///         `memory_region.rs`, SBPFVersion::V3) e `solana-syscalls` 4.3 (agave). Conferida pelos
///         fixtures em `fixtures/v3` (VM oficial) e `fixtures/solana` (Mollusk/agave).
///
/// @dev Mapa de memória (cada região é um intervalo [start, start+len) de endereços virtuais):
///         0x0_0000_0000  rodata (só leitura, tamanho do segmento PF_R do ELF)
///         0x1_0000_0000  bytecode (não mapeado: ler dá AccessViolation)
///         0x2_0000_0000  pilha, 64 frames × 4 KiB, leitura/escrita
///         0x3_0000_0000  heap, 32 KiB, leitura/escrita
///         0x4_0000_0000  input: regiões passadas por quem chama (serialização das contas)
///      Uma região de input gravável pode ter `reserved` > len: uma escrita além de `len` mas dentro
///      de `reserved` faz a região crescer até `reserved` (realloc de conta do agave).
contract SolanaVM {
    enum Status {
        Ok,
        Invalid, // verificador, ELF ou instrução não suportada (UnsupportedInstruction / ExecutionOverrun)
        DivideByZero,
        AccessViolation,
        CuExceeded, // ExceededMaxInstructions / ComputationalBudgetExceeded
        CallDepthExceeded,
        CallOutsideTextSegment,
        SyscallError, // ver `err`
        Cpi // suspensa numa CPI (sol_invoke_signed_*): estado em `suspended`, `err` = 1 se Rust, 0 se C
    }

    // códigos de `Result.err` quando status == SyscallError (SyscallError do agave)
    uint64 private constant E_ABORT = 1;
    uint64 private constant E_PANIC = 2; // mensagem no log (tipo 3)
    uint64 private constant E_INVALID_STRING = 3;
    uint64 private constant E_COPY_OVERLAPPING = 4;
    uint64 private constant E_INVALID_POINTER = 5;
    uint64 private constant E_RETURN_DATA_TOO_LARGE = 6;
    uint64 private constant E_UNALIGNED_POINTER = 7;
    uint64 private constant E_INVALID_LENGTH = 8;
    uint64 private constant E_UNIMPLEMENTED = 9; // syscall real do agave ainda não implementada aqui
    uint64 private constant E_ARITHMETIC_OVERFLOW = 10;
    uint64 private constant E_TOO_MANY_SLICES = 11;
    uint64 private constant E_UNSUPPORTED_SYSVAR = 12;
    /// @notice InstructionError devolvido por uma syscall (CPI, gerado pelo SolanaCpi): err = 13 | índice << 8 | custom << 32
    uint64 private constant E_INSTRUCTION = 13;
    /// @notice erro específico da CPI/PDA (CpiError, SyscallError::BadSeeds): err = 14 | subcódigo << 8 | n << 32
    uint64 private constant E_CPI = 14;

    /// @notice Região de memória de input. `reserved` ≥ data.length permite crescer (realloc).
    struct Region {
        uint64 vaddr;
        bool writable;
        uint64 reserved;
        bytes data;
    }

    struct Sysvar {
        bytes32 id;
        bytes data;
    }

    struct Env {
        bytes32 programId;
        uint64 maxCu;
        uint64 r2; // endereço virtual dos dados da instrução (agave: vm.registers[2])
        Sysvar[] sysvars;
    }

    /// @notice Estado de uma execução suspensa numa CPI: o runtime executa a instrução chamada e
    ///         retoma a VM com `resumeElfVerified` (as regiões de input voltam em `Result.regions`).
    struct Suspended {
        uint64[11] regs; // r0..r10 no momento da syscall (r1..r5 são os argumentos)
        uint64 pc; // próxima instrução
        uint64 cu; // compute units consumidas
        uint64 depth; // profundidade de chamadas internas
        bytes frames; // frames salvos (64 bytes cada)
        bytes stack; // bytes já alocados da pilha
        bytes heap; // bytes já alocados do heap
        bytes returnData;
    }

    struct Result {
        Status status;
        uint64 err;
        uint64 r0;
        uint64 cu;
        uint64 pc; // instrução em que parou
        uint256 fault; // AccessViolation: vaddr | len << 64 | escrita << 128 | dentroDeSyscall << 129
        bytes returnData;
        bytes logs; // entradas [tipo:1][tamanho:4][payload]; tipo 0 texto, 1 pubkey, 2 campos, 3 panic
        bytes[] regions; // conteúdo final de cada região de input
        Suspended suspended; // só com status Cpi
    }

    /// @notice Prefixo das imagens v0 montadas pelo SolanaLoader.
    bytes4 private constant IMAGE_V0 = 0x7f534230;
    uint64 private constant RODATA_START = 0;
    uint64 private constant BYTECODE_START = 0x100000000;
    uint64 private constant STACK_START = 0x200000000;
    uint64 private constant HEAP_START = 0x300000000;
    uint64 private constant INPUT_START = 0x400000000;
    uint64 private constant FRAME_SIZE = 4096;
    uint64 private constant MAX_CALL_DEPTH = 64;
    uint64 private constant STACK_SIZE = 64 * 4096;
    uint64 private constant HEAP_SIZE = 32 * 1024;
    uint256 private constant MAX_REGIONS = 128;
    uint256 private constant MAX_RETURN_DATA = 1024;
    uint256 private constant LOG_CAPACITY = 16384;
    uint256 private constant MAX_ACCOUNT_DATA_LEN = 10 * 1024 * 1024;

    // custos (agave SVMTransactionExecutionCost)
    uint64 private constant SYSCALL_BASE = 100;
    uint64 private constant LOG_64_UNITS = 100;
    uint64 private constant LOG_PUBKEY_UNITS = 100;
    uint64 private constant MEM_OP_BASE = 10;
    uint64 private constant CPI_BYTES_PER_UNIT = 250;
    uint64 private constant SYSVAR_BASE = 100;
    uint64 private constant SHA256_BASE = 85;
    uint64 private constant SHA256_BYTE = 1;
    uint64 private constant SHA256_MAX_SLICES = 20000;

    // hashes murmur3 dos nomes das syscalls (agave 4.3, todas as features ativas)
    uint32 private constant H_ABORT = 0xb6fc1a11;
    uint32 private constant H_SOL_PANIC = 0x686093bb;
    uint32 private constant H_SOL_LOG = 0x207559bd;
    uint32 private constant H_SOL_LOG_64 = 0x5c2a3178;
    uint32 private constant H_SOL_LOG_PUBKEY = 0x7ef088ca;
    uint32 private constant H_SOL_LOG_COMPUTE_UNITS = 0x52ba5096;
    uint32 private constant H_SOL_CREATE_PROGRAM_ADDRESS = 0x9377323c;
    uint32 private constant H_SOL_TRY_FIND_PROGRAM_ADDRESS = 0x48504a38;
    uint32 private constant H_SOL_SHA256 = 0x11f49d86;
    uint32 private constant H_SOL_KECCAK256 = 0xd7793abb;
    uint32 private constant H_SOL_SECP256K1_RECOVER = 0x17e40350;
    uint32 private constant H_SOL_BLAKE3 = 0x174c5122;
    uint32 private constant H_SOL_SHA512 = 0x9229cdcc;
    uint32 private constant H_SOL_CURVE_VALIDATE_POINT = 0xaa2607ca;
    uint32 private constant H_SOL_CURVE_GROUP_OP = 0xdd1c41a6;
    uint32 private constant H_SOL_CURVE_MULTISCALAR_MUL = 0x60a40880;
    uint32 private constant H_SOL_CURVE_DECOMPRESS = 0x080c98b0;
    uint32 private constant H_SOL_CURVE_PAIRING_MAP = 0xf111a47e;
    uint32 private constant H_SOL_GET_CLOCK_SYSVAR = 0xd56b5fe9;
    uint32 private constant H_SOL_GET_EPOCH_SCHEDULE_SYSVAR = 0x23a29a61;
    uint32 private constant H_SOL_GET_RENT_SYSVAR = 0xbf7188f6;
    uint32 private constant H_SOL_GET_LAST_RESTART_SLOT = 0x188a0031;
    uint32 private constant H_SOL_GET_EPOCH_REWARDS_SYSVAR = 0xfdba2b3b;
    uint32 private constant H_SOL_MEMCPY = 0x717cc4a3;
    uint32 private constant H_SOL_MEMMOVE = 0x434371f8;
    uint32 private constant H_SOL_MEMSET = 0x3770fb22;
    uint32 private constant H_SOL_MEMCMP = 0x5fdcde31;
    uint32 private constant H_SOL_GET_PROCESSED_SIBLING_INSTRUCTION = 0xadb8efc8;
    uint32 private constant H_SOL_GET_STACK_HEIGHT = 0x85532d94;
    uint32 private constant H_SOL_SET_RETURN_DATA = 0xa226d3eb;
    uint32 private constant H_SOL_GET_RETURN_DATA = 0x5d2245e4;
    uint32 private constant H_SOL_INVOKE_SIGNED_C = 0xa22b9c85;
    uint32 private constant H_SOL_INVOKE_SIGNED_RUST = 0xd7449092;
    uint32 private constant H_SOL_ALT_BN128_GROUP_OP = 0xae0c318b;
    uint32 private constant H_SOL_BIG_MOD_EXP = 0x780e4c15;
    uint32 private constant H_SOL_POSEIDON = 0xc4947c21;
    uint32 private constant H_SOL_REMAINING_COMPUTE_UNITS = 0xedef5aee;
    uint32 private constant H_SOL_ALT_BN128_COMPRESSION = 0x334fd5ed;
    uint32 private constant H_SOL_GET_SYSVAR = 0x13c1b505;
    uint32 private constant H_SOL_GET_EPOCH_STAKE = 0x5be92f4a;
    uint32 private constant H_SOL_ALLOC_FREE = 0x83f00e8f; // alocador antigo (só programas v0 antigos)
    uint32 private constant H_SOL_LOG_DATA = 0x7317b434;

    // ids das sysvars (bytes32 = pubkey)
    bytes32 private constant SV_CLOCK = 0x06a7d51718c774c928566398691d5eb68b5eb8a39b4b6d5c73555b2100000000;
    bytes32 private constant SV_EPOCH_SCHEDULE = 0x06a7d51718dc3fee02d3e47f0100f8b054f7942e60591e3f508719a805000000;
    bytes32 private constant SV_RENT = 0x06a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a00000000;
    bytes32 private constant SV_EPOCH_REWARDS = 0x06a7d51718dc3fee02a558bf83ce66e144422a1c34950b27c1869b5a9c000000;
    bytes32 private constant SV_LAST_RESTART_SLOT = 0x06a7d5171906dde1cd3f947dcab4c8f4f4f51bad0f9813b800d289471fc00000;

    // ------------------------------------------------------------------ bloco de memória da VM
    // offsets (bytes) dentro do bloco `vm`
    uint256 private constant REGS = 0; // r0..r10, 11 palavras
    uint256 private constant PC = 352;
    uint256 private constant CU = 384;
    uint256 private constant DEPTH = 416;
    uint256 private constant SC = 448; // imm da syscall pendente
    uint256 private constant LOGP = 480; // ponteiro do buffer de logs
    uint256 private constant LOGL = 512; // bytes usados
    uint256 private constant RETP = 544;
    uint256 private constant RETL = 576;
    uint256 private constant PID = 608;
    uint256 private constant MAXCU = 640;
    uint256 private constant NREG = 672;
    uint256 private constant V0 = 704; // programa v0: tabela de funções (offset | n << 64) | endereço do texto << 128
    uint256 private constant FAULT = 736;
    uint256 private constant FRAMES = 768; // 64 frames × 64 bytes
    uint256 private constant REGTAB = 4864; // MAX_REGIONS × 5 palavras: start, len, host, flags, reserved
    uint256 private constant LASTREG = 25344; // 4864 + 128 × 160: última região de entrada achada pela busca binária
    uint256 private constant VM_BYTES = 25376;

    uint256 private constant ST_RUNNING = 0x100;
    uint256 private constant ST_SYSCALL = 0x101;
    uint256 private constant MASK64 = 0xffffffffffffffff;
    uint256 private constant M48 = 0xffffffffffff;

    // ------------------------------------------------------------------ API

    /// @notice Executa um programa: ELF sBPF v3 ou imagem v0 montada pelo SolanaLoader.
    function runElf(bytes calldata elf, Region[] calldata input, Env calldata env) external view returns (Result memory r) {
        return _runElf(elf, input, env, true);
    }

    /// @notice Como `runElf`, mas sem passar o verificador: só para programas já aceites por
    ///         `verifyElf` (o verificador custa ~700 gás por instrução do programa inteiro).
    function runElfVerified(bytes calldata elf, Region[] calldata input, Env calldata env) external view returns (Result memory r) {
        return _runElf(elf, input, env, false);
    }

    function _runElf(bytes calldata elf, Region[] calldata input, Env calldata env, bool check) private view returns (Result memory r) {
        (uint256 vm, bytes calldata text, uint256 entry) = _boot(elf, input, env, check);
        if (vm == 0) {
            r.status = Status.Invalid;
            return r;
        }
        _start(vm, entry, env);
        return _loop(vm, text, input, env);
    }

    /// @notice Retoma uma execução suspensa numa CPI (status `Cpi`), com r0 = 0 (a CPI deu certo).
    ///         `input` são as regiões de input depois da CPI (mesma ordem e endereços do `runElf`).
    function resumeElfVerified(bytes calldata elf, Region[] calldata input, Env calldata env, Suspended calldata s)
        external
        view
        returns (Result memory r)
    {
        (uint256 vm, bytes calldata text, ) = _boot(elf, input, env, false);
        if (vm == 0 || s.pc >= text.length / 8) {
            r.status = Status.Invalid;
            return r;
        }
        _restore(vm, s);
        return _loop(vm, text, input, env);
    }

    /// @dev Carrega o programa (e verifica, se `check`) e monta a memória; vm = 0 se inválido.
    function _boot(bytes calldata elf, Region[] calldata input, Env calldata env, bool check)
        private
        pure
        returns (uint256 vm, bytes calldata text, uint256 entry)
    {
        uint256 pk = _parsePacked(elf);
        text = elf[pk & M48:(pk & M48) + ((pk >> 48) & M48)];
        entry = (pk >> 192) & M48;
        if (pk == 0 || (check && !_verify(text, _v0(elf) != 0))) return (0, text, 0);
        uint256 ro = pk >> 96;
        vm = _setup(elf[ro & M48:(ro & M48) + ((ro >> 48) & M48)], input, env);
        _mode(vm, elf);
    }

    /// @dev `parseElf` empacotado: textOff | textLen << 48 | roOff << 96 | roLen << 144 | entry << 192
    ///      | 1 << 255; 0 se o programa é inválido ou a entrada está fora do texto.
    function _parsePacked(bytes calldata elf) private pure returns (uint256) {
        (bool ok, uint256 textOff, uint256 textLen, uint256 roOff, uint256 roLen, uint64 entry) = parseElf(elf);
        if (!ok || entry >= textLen / 8) return 0;
        return (1 << 255) | textOff | (textLen << 48) | (roOff << 96) | (roLen << 144) | (uint256(entry) << 192);
    }

    /// @notice Carrega o programa e verifica o bytecode (o que o loader do Solana faz uma vez, ao publicar).
    function verifyElf(bytes calldata elf) external pure returns (bool) {
        (bool ok, uint256 textOff, uint256 textLen, , , uint64 entry) = parseElf(elf);
        return ok && entry < textLen / 8 && _verify(elf[textOff:textOff + textLen], _v0(elf) != 0);
    }

    /// @notice Executa bytecode sBPF v3 já extraído: `text` é verificado; `rodata` é mapeado em 0.
    function run(bytes calldata text, uint64 entry, bytes calldata rodata, Region[] calldata input, Env calldata env)
        external
        view
        returns (Result memory r)
    {
        if (entry >= text.length / 8 || !verify(text)) {
            r.status = Status.Invalid;
            return r;
        }
        uint256 vm = _setup(rodata, input, env);
        _start(vm, entry, env);
        return _loop(vm, text, input, env);
    }

    /// @dev Registradores iniciais: r1 = input, r2 = dados da instrução, r10 = topo do primeiro frame.
    function _start(uint256 vm, uint256 entry, Env calldata env) private pure {
        assembly ("memory-safe") {
            mstore(add(vm, 32), INPUT_START) // r1
            mstore(add(vm, 64), and(calldataload(add(env, 64)), MASK64)) // r2
            mstore(add(vm, 320), add(STACK_START, FRAME_SIZE)) // r10 = topo do primeiro frame
            mstore(add(vm, PC), entry)
        }
    }

    /// @dev Programa v0: a região só leitura fica em 0x1_0000_0000 (com o texto dentro dela) e as
    ///      chamadas usam a tabela de funções da imagem (logo depois do cabeçalho).
    function _mode(uint256 vm, bytes calldata elf) private pure {
        uint256 info = _v0(elf);
        if (info == 0) return;
        uint256 nfunc = info >> 66;
        uint256 textVaddr = BYTECODE_START + uint32(bytes4(elf[8:12]));
        assembly ("memory-safe") {
            mstore(add(vm, REGTAB), BYTECODE_START)
            mstore(add(vm, V0), or(or(add(elf.offset, 20), shl(64, nfunc)), shl(128, textVaddr)))
        }
    }

    /// @dev Imagem v0 do SolanaLoader: 1 << 65 | nfunc << 66 (0 para ELF v3).
    function _v0(bytes calldata elf) private pure returns (uint256) {
        if (elf.length < 20 || bytes4(elf[0:4]) != IMAGE_V0) return 0;
        return (1 << 65) | (uint256(uint32(bytes4(elf[16:20]))) << 66);
    }

    /// @dev Repõe registos, medidor, frames, pilha, heap e return data de uma execução suspensa.
    function _restore(uint256 vm, Suspended calldata s) private pure {
        uint64 ip = s.pc;
        uint64 cu = s.cu;
        uint64 depth = s.depth;
        bytes calldata frames = s.frames;
        if (frames.length > 4096 || depth > MAX_CALL_DEPTH) revert BadSnapshot();
        assembly ("memory-safe") {
            calldatacopy(vm, s, 352) // r0..r10 (uint64[11] ocupa as primeiras 11 palavras da struct)
            mstore(add(vm, PC), ip)
            mstore(add(vm, CU), cu)
            mstore(add(vm, DEPTH), depth)
            calldatacopy(add(vm, FRAMES), frames.offset, frames.length)
        }
        _sparse(vm, 1, s.stack);
        _sparse(vm, 2, s.heap);
        // return data suspenso: programa que o definiu (32 bytes) || dados
        bytes calldata ret = s.returnData;
        if (ret.length > MAX_RETURN_DATA + 32 || (ret.length != 0 && ret.length < 32)) revert BadSnapshot();
        if (ret.length != 0) {
            assembly ("memory-safe") {
                let p := mload(add(vm, RETP))
                calldatacopy(sub(p, 32), ret.offset, ret.length)
                mstore(add(vm, RETL), sub(ret.length, 32))
            }
        }
    }

    /// @dev Repõe os bytes alocados de uma região esparsa (pilha ou heap).
    function _sparse(uint256 vm, uint256 i, bytes calldata data) private pure {
        uint256 e = vm + REGTAB + i * 160;
        uint256 cap = data.length;
        uint256 size;
        assembly ("memory-safe") {
            size := mload(add(e, 32))
        }
        if (cap > size) revert BadSnapshot();
        if (cap == 0) return;
        uint256 p = _alloc(cap + 32) + 32; // palavra anterior: tamanho (resultado sem cópia)
        assembly ("memory-safe") {
            calldatacopy(p, data.offset, cap)
            mstore(add(e, 64), p)
            mstore(add(e, 96), or(3, shl(64, cap)))
        }
    }

    error BadSnapshot();

    /// @dev Corre até parar e monta o resultado.
    function _loop(uint256 vm, bytes calldata text, Region[] calldata input, Env calldata env) private view returns (Result memory r) {
        uint256 n = text.length / 8;
        uint256 codeOff;
        assembly {
            codeOff := text.offset
        }
        uint256 st;
        uint64 err;
        for (;;) {
            st = _exec(vm, codeOff, n);
            if (st != ST_SYSCALL) break;
            (st, err) = _syscall(vm, env);
            if (st != 0) break;
        }
        return _result(vm, st, err, input.length);
    }

    function _result(uint256 vm, uint256 st, uint64 err, uint256 nInput) private pure returns (Result memory r) {
        r.status = Status(st);
        r.err = err;
        uint256 cu;
        uint256 ip;
        uint256 r0;
        uint256 fault;
        assembly ("memory-safe") {
            r0 := mload(vm)
            cu := mload(add(vm, CU))
            ip := mload(add(vm, PC))
            fault := mload(add(vm, FAULT))
        }
        r.r0 = st == 0 ? uint64(r0) : 0;
        r.cu = uint64(cu);
        r.pc = uint64(ip);
        r.fault = fault;
        r.returnData = _take(vm, RETP, RETL, 0);
        r.logs = _take(vm, LOGP, LOGL, 0);
        r.regions = new bytes[](nInput);
        for (uint256 i = 0; i < nInput; i++) {
            r.regions[i] = _regionBytes(vm, 3 + i);
        }
        if (st == uint256(Status.Cpi)) _snapshot(vm, r.suspended);
        else r.suspended.returnData = _take(vm, RETP, RETL, 32); // dono do return data (CPI aninhada)
    }

    /// @dev Conteúdo de uma região (os `len` bytes a partir do host; esparsa: os alocados), sem
    ///      cópia: o buffer da região tem uma palavra livre antes, onde vai o tamanho.
    function _regionBytes(uint256 vm, uint256 i) private pure returns (bytes memory out) {
        uint256 e = vm + REGTAB + i * 160;
        assembly ("memory-safe") {
            let len := mload(add(e, 32))
            let fl := mload(add(e, 96))
            if and(shr(1, fl), 1) { len := shr(64, fl) }
            out := 0x60
            if len {
                out := sub(mload(add(e, 64)), 32)
                mstore(out, len)
            }
        }
    }

    /// @dev Guarda o estado da VM suspensa numa CPI.
    function _snapshot(uint256 vm, Suspended memory s) private pure {
        uint256 depth;
        assembly ("memory-safe") {
            depth := mload(add(vm, DEPTH))
        }
        for (uint256 i = 0; i < 11; i++) {
            uint256 v;
            assembly ("memory-safe") {
                v := mload(add(vm, mul(i, 32)))
            }
            s.regs[i] = uint64(v);
        }
        uint256 ip;
        uint256 cu;
        assembly ("memory-safe") {
            ip := mload(add(vm, PC))
            cu := mload(add(vm, CU))
        }
        s.pc = uint64(ip);
        s.cu = uint64(cu);
        s.depth = uint64(depth);
        bytes memory frames = new bytes(depth * 64);
        assembly ("memory-safe") {
            mcopy(add(frames, 32), add(vm, FRAMES), mload(frames))
        }
        s.frames = frames;
        s.stack = _regionBytes(vm, 1);
        s.heap = _regionBytes(vm, 2);
        s.returnData = _take(vm, RETP, RETL, 32); // programa que definiu o return data || dados
    }

    // ------------------------------------------------------------------ ELF

    /// @notice Analisador estrito de ELF do sBPF v3 (`Executable::load_with_strict_parser`).
    ///         Devolve: ok (cabeçalhos válidos e versão 3), offset/tamanho do segmento executável
    ///         (bytecode) dentro de `elf`, offset/tamanho do segmento só leitura (mapeado no
    ///         endereço 0) e o índice da instrução de entrada.
    function parseElf(bytes calldata elf)
        public
        pure
        returns (bool ok, uint256 textOff, uint256 textLen, uint256 roOff, uint256 roLen, uint64 entry)
    {
        if (elf.length >= 20 && bytes4(elf[0:4]) == IMAGE_V0) return _parseImage(elf);
        if (elf.length < 64) return (false, 0, 0, 0, 0, 0);
        uint256 base;
        assembly {
            base := elf.offset
        }
        // e_ident: \x7fELF, ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_NONE, abiversion 0, pad 0
        if (bytes16(elf[0:16]) != bytes16(0x7f454c46020101000000000000000000)) return (false, 0, 0, 0, 0, 0);
        uint256 phnum = _u16(base, 56);
        if (
            _u16(base, 18) != 247 // EM_BPF
                || _u32(base, 20) != 1 // e_version
                || _u64(base, 32) != 64 // e_phoff
                || _u32(base, 48) != 3 // e_flags = sBPF v3
                || _u16(base, 52) != 64 // e_ehsize
                || _u16(base, 54) != 56 // e_phentsize
                || phnum == 0 || 64 + 56 * phnum > elf.length
        ) return (false, 0, 0, 0, 0, 0);

        // segmentos esperados, em ordem: PF_R em 0 (opcional) e PF_X em 1<<32, contíguos após a tabela
        bool skipRo = _u32(base, 64 + 4) != 4; // PF_R
        if (!skipRo && phnum < 2) return (false, 0, 0, 0, 0, 0);
        uint256 expectedOff = 64 + 56 * phnum;
        uint256 h = 64;
        if (!skipRo) {
            (ok, roOff, roLen) = _phdr(base, elf.length, h, 4, 0, expectedOff);
            if (!ok) return (false, 0, 0, 0, 0, 0);
            expectedOff += roLen;
            h += 56;
        }
        (ok, textOff, textLen) = _phdr(base, elf.length, h, 1, BYTECODE_START, expectedOff);
        if (!ok) return (false, 0, 0, 0, 0, 0);
        uint256 e = _u64(base, 24); // e_entry
        // entry + 7 dentro do segmento e alinhado a 8
        if (e + 7 < BYTECODE_START || e + 7 >= BYTECODE_START + textLen || e % 8 != 0) return (false, 0, 0, 0, 0, 0);
        entry = uint64((e - BYTECODE_START) / 8);
        ok = true;
    }

    /// @dev Imagem v0 montada pelo SolanaLoader: "\x7fSB0" | entry | textAddr | textLen | nfunc
    ///      | tabela de funções | região só leitura (com o texto em textAddr).
    function _parseImage(bytes calldata img)
        private
        pure
        returns (bool ok, uint256 textOff, uint256 textLen, uint256 roOff, uint256 roLen, uint64 entry)
    {
        entry = uint32(bytes4(img[4:8]));
        uint256 textAddr = uint32(bytes4(img[8:12]));
        textLen = uint32(bytes4(img[12:16]));
        roOff = 20 + 8 * uint256(uint32(bytes4(img[16:20])));
        if (roOff > img.length) return (false, 0, 0, 0, 0, 0);
        roLen = img.length - roOff;
        if (textAddr + textLen > roLen) return (false, 0, 0, 0, 0, 0);
        textOff = roOff + textAddr;
        ok = true;
    }

    /// @dev Confere um program header (PT_LOAD, flags, offset contíguo, vaddr, tamanhos).
    function _phdr(uint256 base, uint256 len, uint256 h, uint256 flags, uint256 vaddr, uint256 expectedOff)
        private
        pure
        returns (bool ok, uint256 off, uint256 size)
    {
        off = _u64(base, h + 8);
        size = _u64(base, h + 32); // p_filesz
        if (
            _u32(base, h) != 1 // PT_LOAD
                || _u32(base, h + 4) != flags || off != expectedOff || off >= len || off % 8 != 0
                || _u64(base, h + 16) != vaddr || _u64(base, h + 24) != vaddr // p_vaddr, p_paddr
                || size != _u64(base, h + 40) // p_memsz
                || size > len - off || size % 8 != 0 || size >= 0x100000000
        ) return (false, 0, 0);
        ok = true;
    }

    function _u16(uint256 base, uint256 off) private pure returns (uint256 v) {
        assembly {
            let w := calldataload(add(base, off))
            v := or(byte(0, w), shl(8, byte(1, w)))
        }
    }

    function _u32(uint256 base, uint256 off) private pure returns (uint256 v) {
        assembly {
            let w := calldataload(add(base, off))
            v := or(or(byte(0, w), shl(8, byte(1, w))), or(shl(16, byte(2, w)), shl(24, byte(3, w))))
        }
    }

    function _u64(uint256 base, uint256 off) private pure returns (uint256 v) {
        assembly {
            let w := calldataload(add(base, off))
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } { v := or(v, shl(mul(i, 8), byte(i, w))) }
        }
    }

    // ------------------------------------------------------------------ verificador

    /// @notice Verificador estático, equivalente ao `RequisiteVerifier` do solana-sbpf para V3.
    function verify(bytes calldata program) public pure returns (bool) {
        return _verify(program, false);
    }

    /// @dev V0 difere em dois pontos: não há JMP32 e o registrador do callx vem no imm.
    function _verify(bytes calldata program, bool v0) private pure returns (bool) {
        uint256 len = program.length;
        if (len == 0 || len % 8 != 0) return false;
        uint256 n = len / 8;
        uint256 base;
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
                        return false; // hor64 (0xf7) só existe sem lddw (v2)
                    } else if (op == 0x80) {
                        if (isReg) return false; // neg: só 0x84 / 0x87
                    } else if (!isReg) {
                        if ((op == 0x30 || op == 0x90) && imm == 0) return false; // div/mod por imediato 0
                        if (op == 0x60 || op == 0x70 || op == 0xc0) {
                            if (imm < 0 || imm >= (cls == 7 ? int256(64) : int256(32))) return false;
                        }
                    }
                } else if (cls == 5) {
                    // JMP64
                    if (op == 0x00) {
                        if (isReg) return false; // ja = 0x05
                        if (!_jumpOk(base, n, i, off)) return false;
                    } else if (op == 0x80) {
                        // 0x85 call (resolvido em execução), 0x8d callx (registrador alvo 0..9: dst; no v0, imm)
                        if (isReg && (v0 ? (imm < 0 || imm > 9) : dst > 9)) return false;
                    } else if (op == 0x90) {
                        if (isReg) return false; // exit = 0x95
                    } else if (op > 0xd0) {
                        return false;
                    } else {
                        if (!_jumpOk(base, n, i, off)) return false;
                    }
                } else if (cls == 6) {
                    // JMP32 (só v3): só os saltos condicionais (0x16..0x7e, 0xa6..0xde)
                    if (v0 || op == 0x00 || op == 0x80 || op == 0x90 || op > 0xd0) return false;
                    if (!_jumpOk(base, n, i, off)) return false;
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

                // registradores: src <= 10; dst <= 9, ou dst == 10 apenas em stores (sem `add64 r10` em v3)
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

    // ------------------------------------------------------------------ montagem da memória

    error TooManyRegions();
    error RegionsNotSorted();

    /// @dev Aloca o bloco da VM, as regiões (rodata, pilha, heap, input) e os buffers de logs e
    ///      return data. Regiões de input precisam vir em ordem crescente de endereço.
    function _setup(bytes calldata rodata, Region[] calldata input, Env calldata env) private pure returns (uint256 vm) {
        uint256 nreg = 3 + input.length;
        if (nreg > MAX_REGIONS) revert TooManyRegions();
        assembly ("memory-safe") {
            vm := mload(0x40)
            mstore(0x40, add(vm, VM_BYTES))
            calldatacopy(vm, calldatasize(), VM_BYTES) // zera
        }
        // só leitura: lida direto do calldata (bit 2), sem cópia para a memória
        uint256 p;
        assembly ("memory-safe") {
            p := rodata.offset
        }
        _region(vm, 0, RODATA_START, rodata.length, p, 4, rodata.length);
        _region(vm, 1, STACK_START, STACK_SIZE, 0, 3, STACK_SIZE); // esparsa: 256 KiB endereçáveis, alocados ao tocar
        _region(vm, 2, HEAP_START, HEAP_SIZE, 0, 3, HEAP_SIZE);
        uint256 prev = HEAP_START + HEAP_SIZE;
        for (uint256 i = 0; i < input.length; i++) {
            Region calldata rg = input[i];
            uint256 start = rg.vaddr;
            if (start < prev) revert RegionsNotSorted();
            uint256 len = rg.data.length;
            // só regiões graváveis crescem; o crescimento é limitado como no agave (10 MiB)
            uint256 reserved = rg.writable && rg.reserved > len ? rg.reserved : len;
            if (reserved > MAX_ACCOUNT_DATA_LEN) reserved = len > MAX_ACCOUNT_DATA_LEN ? len : MAX_ACCOUNT_DATA_LEN;
            // o espaço reservado nunca passa do começo da próxima região
            uint256 next = i + 1 < input.length ? uint256(input[i + 1].vaddr) : (1 << 64);
            if (start + reserved > next) reserved = next - start;
            if (reserved < len) revert RegionsNotSorted();
            p = _alloc(reserved + 32) + 32; // palavra anterior: tamanho (resultado sem cópia)
            bytes calldata d = rg.data;
            assembly ("memory-safe") {
                calldatacopy(p, d.offset, len)
            }
            _region(vm, 3 + i, start, len, p, rg.writable ? 1 : 0, reserved);
            prev = start + len;
        }
        uint256 logs = _alloc(LOG_CAPACITY);
        uint256 ret = _alloc(MAX_RETURN_DATA + 32) + 32; // palavra anterior: programa dono do return data
        bytes32 pid = env.programId;
        uint64 maxCu = env.maxCu;
        assembly ("memory-safe") {
            mstore(add(vm, LOGP), logs)
            mstore(add(vm, RETP), ret)
            mstore(sub(ret, 32), pid)
            mstore(add(vm, PID), pid)
            mstore(add(vm, MAXCU), maxCu)
            mstore(add(vm, NREG), nreg)
        }
    }

    /// @dev Buffer zerado de `size` bytes na memória.
    function _alloc(uint256 size) private pure returns (uint256 p) {
        assembly ("memory-safe") {
            p := mload(0x40)
            mstore(0x40, add(p, and(add(size, 31), not(31))))
            calldatacopy(p, calldatasize(), size)
        }
    }

    /// @dev Entrada da tabela de regiões. `flags`: bit0 gravável, bit1 esparsa (pilha e heap: a memória
    ///      da EVM só é alocada quando o programa toca; `flags >> 64` guarda os bytes já alocados).
    function _region(uint256 vm, uint256 i, uint256 start, uint256 len, uint256 host, uint256 flags, uint256 reserved) private pure {
        assembly ("memory-safe") {
            let e := add(add(vm, REGTAB), mul(i, 160))
            mstore(e, start)
            mstore(add(e, 32), len)
            mstore(add(e, 64), host)
            mstore(add(e, 96), flags)
            mstore(add(e, 128), reserved)
        }
    }

    /// @dev Copia um buffer (ponteiro em `vm+pOff`, tamanho em `vm+lOff`) para `bytes memory`.
    /// @dev Cópia de um buffer da VM, com `pre` bytes de antes do ponteiro (o dono do return data).
    function _take(uint256 vm, uint256 pOff, uint256 lOff, uint256 pre) private pure returns (bytes memory out) {
        assembly ("memory-safe") {
            let len := add(mload(add(vm, lOff)), pre)
            out := mload(0x40)
            mstore(0x40, add(out, and(add(len, 63), not(31))))
            mstore(out, len)
            mcopy(add(out, 32), sub(mload(add(vm, pOff)), pre), len)
        }
    }

    // ------------------------------------------------------------------ interpretador

    /// @dev Loop principal em Yul. Executa até parar ou até uma syscall
    ///      (devolve ST_SYSCALL com o imm em vm+SC; o chamador trata e volta a chamar).
    function _exec(uint256 vm, uint256 codeOff, uint256 n) private pure returns (uint256 st) {
        assembly ("memory-safe") {

            // inverte os 8 bytes de x (x < 2^64)
            function rev64(x) -> y {
                y := or(shl(8, and(x, 0x00ff00ff00ff00ff)), and(shr(8, x), 0x00ff00ff00ff00ff))
                y := or(shl(16, and(y, 0x0000ffff0000ffff)), and(shr(16, y), 0x0000ffff0000ffff))
                y := and(or(shl(32, y), shr(32, y)), MASK64)
            }
            // valor little-endian dos `size` primeiros bytes da palavra w
            function le(w, size) -> v {
                v := and(rev64(shr(192, w)), sub(shl(shl(3, size), 1), 1))
            }
            // entrada da tabela da última região com start <= vaddr (0 se nenhuma)
            function find(vm_, vaddr) -> e {
                // pilha e heap têm endereço fixo e nenhuma outra região começa dentro delas
                if lt(sub(vaddr, STACK_START), STACK_SIZE) {
                    e := add(add(vm_, REGTAB), 160)
                    leave
                }
                if lt(sub(vaddr, HEAP_START), HEAP_SIZE) {
                    e := add(add(vm_, REGTAB), 320)
                    leave
                }
                // as regiões não se sobrepõem até o espaço reservado: dentro dele, a resposta é a mesma
                e := mload(add(vm_, LASTREG))
                if e {
                    if lt(sub(vaddr, mload(e)), mload(add(e, 128))) { leave }
                    e := 0
                }
                let lo := 0
                let hi := mload(add(vm_, NREG))
                for {} lt(lo, hi) {} {
                    let mid := shr(1, add(lo, hi))
                    switch gt(mload(add(add(vm_, REGTAB), mul(mid, 160))), vaddr)
                    case 1 { hi := mid }
                    default { lo := add(mid, 1) }
                }
                if lo {
                    e := add(add(vm_, REGTAB), mul(sub(lo, 1), 160))
                    if gt(lo, 3) { mstore(add(vm_, LASTREG), e) }
                }
            }
            // região esparsa: garante que [0, end) está alocado na memória da EVM (dobra, mínimo 8 KiB)
            function touch(e, end) {
                let fl := mload(add(e, 96))
                if and(fl, 2) {
                    let cap := shr(64, fl)
                    if gt(end, cap) {
                        let ncap := shl(1, cap)
                        if lt(ncap, 8192) { ncap := 8192 }
                        if lt(ncap, end) { ncap := and(add(end, 8191), not(8191)) }
                        if gt(ncap, mload(add(e, 32))) { ncap := mload(add(e, 32)) }
                        let p := add(mload(0x40), 32) // palavra anterior: tamanho (resultado sem cópia)
                        mstore(0x40, add(p, ncap))
                        calldatacopy(p, calldatasize(), ncap)
                        mcopy(p, mload(add(e, 64)), cap)
                        mstore(add(e, 64), p)
                        mstore(add(e, 96), or(and(fl, 3), shl(64, ncap)))
                    }
                }
            }
            // em caso de falha, registram o acesso em vm+FAULT (vaddr | size << 64 | escrita << 128)
            function load(vm_, vaddr, size) -> ok, w {
                let e := find(vm_, vaddr)
                if e {
                    let off := sub(vaddr, mload(e))
                    let end := add(off, size)
                    if iszero(gt(end, mload(add(e, 32)))) {
                        ok := 1
                        let fl := mload(add(e, 96))
                        switch and(and(shr(1, fl), 1), gt(end, shr(64, fl)))
                        case 0 {
                            switch and(fl, 4)
                            case 0 { w := mload(add(mload(add(e, 64)), off)) }
                            default { w := calldataload(add(mload(add(e, 64)), off)) }
                        }
                        default {
                            // esparsa e ainda não alocada: lê zero; se cruza o alocado, aloca
                            if lt(off, shr(64, fl)) {
                                touch(e, end)
                                w := mload(add(mload(add(e, 64)), off))
                            }
                        }
                    }
                }
                if iszero(ok) { mstore(add(vm_, FAULT), or(vaddr, shl(64, size))) }
            }
            function store(vm_, vaddr, size, value) -> ok {
                let e := find(vm_, vaddr)
                if e {
                    if and(mload(add(e, 96)), 1) {
                        let off := sub(vaddr, mload(e))
                        let end := add(off, size)
                        ok := 1
                        if gt(end, mload(add(e, 32))) {
                            switch gt(end, mload(add(e, 128)))
                            case 1 { ok := 0 }
                            default { mstore(add(e, 32), mload(add(e, 128))) } // cresce até o reservado
                        }
                        if ok {
                            touch(e, end)
                            let p := add(mload(add(e, 64)), off)
                            // grava os `size` bytes little-endian de value e preserva o resto da palavra
                            let keep := shr(shl(3, size), not(0))
                            mstore(p, or(and(mload(p), keep), and(shl(192, rev64(and(value, MASK64))), not(keep))))
                        }
                    }
                }
                if iszero(ok) { mstore(add(vm_, FAULT), or(or(vaddr, shl(64, size)), shl(128, 1))) }
            }
            // salva o frame e sobe r10; falha se a profundidade chega a 64
            function push(vm_, nextpc) -> ok {
                let d := mload(add(vm_, DEPTH))
                let f := add(add(vm_, FRAMES), shl(6, d))
                mstore(f, or(or(mload(add(vm_, 192)), shl(64, mload(add(vm_, 224)))), or(shl(128, mload(add(vm_, 256))), shl(192, mload(add(vm_, 288))))))
                mstore(add(f, 32), or(mload(add(vm_, 320)), shl(64, nextpc)))
                d := add(d, 1)
                mstore(add(vm_, DEPTH), d)
                if eq(d, MAX_CALL_DEPTH) { leave }
                mstore(add(vm_, 320), and(add(mload(add(vm_, 320)), FRAME_SIZE), MASK64))
                ok := 1
            }
            function bswap(v, nbytes) -> out {
                for { let i := 0 } lt(i, nbytes) { i := add(i, 1) } { out := or(shl(8, out), and(shr(mul(8, i), v), 0xff)) }
            }
            function offset(w) -> o {
                o := signextend(1, or(byte(2, w), shl(8, byte(3, w))))
            }
            // v0: pc da função com hash `key` na tabela ordenada (not(0) se não há)
            function lookup(v0, key) -> target {
                target := not(0)
                let lo := 0
                let hi := and(shr(64, v0), 0xffffffff)
                let tab := and(v0, MASK64)
                for {} lt(lo, hi) {} {
                    let mid := shr(1, add(lo, hi))
                    let ent := shr(192, calldataload(add(tab, shl(3, mid))))
                    let k := shr(32, ent)
                    if eq(k, key) {
                        target := and(ent, 0xffffffff)
                        break
                    }
                    switch lt(k, key)
                    case 1 { lo := add(mid, 1) }
                    default { hi := mid }
                }
            }
            // and(opc, 0x18): 0x00 → 4, 0x08 → 2, 0x10 → 1, 0x18 → 8
            function memsize(opc) -> size {
                size := byte(and(shr(3, opc), 3), 0x0402010800000000000000000000000000000000000000000000000000000000)
            }

            let regs := vm
            let ip := mload(add(regs, PC))
            let cu := mload(add(regs, CU))
            st := ST_RUNNING
            // casos em ordem de frequência (programas Rust: mov, stxdw, ldxdw, add, jne/jgt/jeq, call/exit)
            for {} 1 {} {
                st := 0 // qualquer `break` abaixo é uma parada; o fim do corpo volta a RUNNING
                if iszero(lt(cu, mload(add(regs, MAXCU)))) {
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
                    let b := and(signextend(3, imm), MASK64)
                    if and(opc, 8) { b := mload(add(regs, shl(5, shr(4, byte(1, w))))) }
                    let a := mload(dstp)
                    switch and(opc, 0xf0)
                    case 0xb0 { a := b }
                    case 0x00 { a := and(add(a, b), MASK64) }
                    case 0x10 { a := and(sub(a, b), MASK64) }
                    case 0x50 { a := and(a, b) }
                    case 0x80 { a := and(sub(0, a), MASK64) }
                    case 0x70 { a := shr(and(b, 63), a) }
                    case 0x60 { a := and(shl(and(b, 63), a), MASK64) }
                    case 0x20 { a := and(mul(a, b), MASK64) }
                    case 0x40 { a := or(a, b) }
                    case 0xa0 { a := xor(a, b) }
                    case 0xc0 { a := and(sar(and(b, 63), signextend(7, a)), MASK64) }
                    case 0x30 {
                        if iszero(b) {
                            st := 2
                            break
                        }
                        a := div(a, b)
                    }
                    case 0x90 {
                        if iszero(b) {
                            st := 2
                            break
                        }
                        a := mod(a, b)
                    }
                    default {
                        st := 1
                        break
                    }
                    mstore(dstp, a)
                }
                case 3 {
                    // ---------------- STX: *(size*)(dst + off) = src
                    if iszero(store(regs, and(add(mload(dstp), offset(w)), MASK64), memsize(opc), mload(add(regs, shl(5, shr(4, byte(1, w))))))) {
                        st := 3
                        break
                    }
                }
                case 1 {
                    // ---------------- LDX: dst = *(size*)(src + off)
                    let ok, mw := load(regs, and(add(mload(add(regs, shl(5, shr(4, byte(1, w))))), offset(w)), MASK64), memsize(opc))
                    if iszero(ok) {
                        st := 3
                        break
                    }
                    mstore(dstp, le(mw, memsize(opc)))
                }
                case 5 {
                    // ---------------- JMP64 / call / callx / exit
                    // condicionais: 0x10..0x70 e 0xa0..0xd0
                    if and(shr(shr(4, opc), 0x3cfe), 1) {
                        let a := mload(dstp)
                        let b := and(signextend(3, imm), MASK64)
                        if and(opc, 8) { b := mload(add(regs, shl(5, shr(4, byte(1, w))))) }
                        switch and(opc, 0xf0)
                        case 0x50 { a := iszero(eq(a, b)) }
                        case 0x20 { a := gt(a, b) }
                        case 0x10 { a := eq(a, b) }
                        case 0x60 { a := sgt(signextend(7, a), signextend(7, b)) }
                        case 0x70 { a := iszero(slt(signextend(7, a), signextend(7, b))) }
                        case 0x30 { a := iszero(lt(a, b)) }
                        case 0x40 { a := iszero(iszero(and(a, b))) }
                        case 0xa0 { a := lt(a, b) }
                        case 0xb0 { a := iszero(gt(a, b)) }
                        case 0xc0 { a := slt(signextend(7, a), signextend(7, b)) }
                        default { a := iszero(sgt(signextend(7, a), signextend(7, b))) } // 0xd0
                        if a { ip := add(ip, offset(w)) }
                        st := ST_RUNNING
                        continue
                    }
                    switch opc
                        case 0x85 {
                            if mload(add(regs, V0)) {
                                // v0: imm é o hash de uma função (tabela ordenada) ou de uma syscall
                                let target := lookup(mload(add(regs, V0)), imm)
                                if eq(target, not(0)) {
                                    mstore(add(regs, SC), imm)
                                    st := ST_SYSCALL
                                    break
                                }
                                if iszero(push(regs, ip)) {
                                    st := 5
                                    break
                                }
                                if iszero(lt(target, n)) {
                                    st := 6
                                    break
                                }
                                ip := target
                                st := ST_RUNNING
                                continue
                            }
                            switch shr(4, byte(1, w))
                            case 0 {
                                // syscall: o Solidity resolve o hash e executa
                                mstore(add(regs, SC), imm)
                                st := ST_SYSCALL
                                break
                            }
                            case 1 {
                                // chamada interna relativa: alvo = próxima instrução + imm
                                let target := add(ip, signextend(3, imm))
                                if iszero(lt(target, n)) {
                                    st := 1
                                    break
                                }
                                if iszero(push(regs, ip)) {
                                    st := 5
                                    break
                                }
                                ip := target
                            }
                            default {
                                st := 1
                                break
                            }
                        }
                        case 0x95 {
                            let d := mload(add(regs, DEPTH))
                            if iszero(d) { break } // st = 0: Ok(r0)
                            d := sub(d, 1)
                            mstore(add(regs, DEPTH), d)
                            let f := add(add(regs, FRAMES), shl(6, d))
                            let s := mload(f)
                            mstore(add(regs, 192), and(s, MASK64))
                            mstore(add(regs, 224), and(shr(64, s), MASK64))
                            mstore(add(regs, 256), and(shr(128, s), MASK64))
                            mstore(add(regs, 288), shr(192, s))
                            s := mload(add(f, 32))
                            mstore(add(regs, 320), and(s, MASK64))
                            ip := shr(64, s)
                        }
                        case 0x05 { ip := add(ip, offset(w)) }
                        case 0x8d {
                            // callx: alvo absoluto em reg[dst] (v0: reg[imm], relativo ao endereço do texto);
                            // o frame é empilhado antes da checagem
                            let target := div(and(sub(mload(dstp), BYTECODE_START), MASK64), 8)
                            if mload(add(regs, V0)) {
                                target := div(and(sub(mload(add(regs, shl(5, and(imm, 0x0f)))), shr(128, mload(add(regs, V0)))), MASK64), 8)
                            }
                            if iszero(push(regs, ip)) {
                                st := 5
                                break
                            }
                            if iszero(lt(target, n)) {
                                st := 6
                                break
                            }
                            ip := target
                        }
                        default {
                            st := 1
                            break
                        }
                }
                case 0 {
                    // ---------------- lddw (0x18): 16 bytes, imm64 = imm | imm2 << 32
                    if iszero(eq(opc, 0x18)) {
                        st := 1
                        break
                    }
                    w := calldataload(add(codeOff, shl(3, ip)))
                    mstore(dstp, or(imm, shl(32, or(or(byte(4, w), shl(8, byte(5, w))), or(shl(16, byte(6, w)), shl(24, byte(7, w)))))))
                    ip := add(ip, 1)
                }
                case 4 {
                    // ---------------- ALU32
                    let a := and(mload(dstp), 0xffffffff)
                    let b := imm
                    if and(opc, 8) { b := and(mload(add(regs, shl(5, shr(4, byte(1, w))))), 0xffffffff) }
                    switch and(opc, 0xf0)
                    // add/sub/mul: resultado i32 estendido com sinal para 64 bits
                    case 0x00 { a := and(signextend(3, add(a, b)), MASK64) }
                    case 0x10 { a := and(signextend(3, sub(a, b)), MASK64) }
                    case 0x20 { a := and(signextend(3, mul(a, b)), MASK64) }
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
                case 6 {
                    // ---------------- JMP32: compara os 32 bits baixos
                    let a := and(mload(dstp), 0xffffffff)
                    let b := imm
                    if and(opc, 8) { b := and(mload(add(regs, shl(5, shr(4, byte(1, w))))), 0xffffffff) }
                    switch and(opc, 0xf0)
                    case 0x10 { a := eq(a, b) }
                    case 0x20 { a := gt(a, b) }
                    case 0x30 { a := iszero(lt(a, b)) }
                    case 0x40 { a := iszero(iszero(and(a, b))) }
                    case 0x50 { a := iszero(eq(a, b)) }
                    case 0x60 { a := sgt(signextend(3, a), signextend(3, b)) }
                    case 0x70 { a := iszero(slt(signextend(3, a), signextend(3, b))) }
                    case 0xa0 { a := lt(a, b) }
                    case 0xb0 { a := iszero(gt(a, b)) }
                    case 0xc0 { a := slt(signextend(3, a), signextend(3, b)) }
                    case 0xd0 { a := iszero(sgt(signextend(3, a), signextend(3, b))) }
                    default {
                        st := 1
                        break
                    }
                    if a { ip := add(ip, offset(w)) }
                }
                case 2 {
                    // ---------------- ST: *(size*)(dst + off) = imm (estendido com sinal)
                    if iszero(store(regs, and(add(mload(dstp), offset(w)), MASK64), memsize(opc), signextend(3, imm))) {
                        st := 3
                        break
                    }
                }
                st := ST_RUNNING
            }
            mstore(add(regs, PC), ip)
            mstore(add(regs, CU), cu)
        }
    }

    // ------------------------------------------------------------------ syscalls

    /// @dev Despacha a syscall pendente (hash em vm+SC). Devolve (0, 0) para continuar, ou o
    ///      status final e o código de erro.
    function _syscall(uint256 vm, Env calldata env) private view returns (uint256 st, uint64 err) {
        uint256 h;
        uint256 a1;
        uint256 a2;
        uint256 a3;
        uint256 a4;
        assembly ("memory-safe") {
            h := mload(add(vm, SC))
            a1 := mload(add(vm, 32))
            a2 := mload(add(vm, 64))
            a3 := mload(add(vm, 96))
            a4 := mload(add(vm, 128))
        }
        if (h == H_SOL_LOG) return _sysLog(vm, a1, a2);
        if (h == H_SOL_LOG_64) return _sysLog64(vm);
        if (h == H_SOL_MEMCPY) return _sysMemmove(vm, a1, a2, a3, true);
        if (h == H_SOL_MEMMOVE) return _sysMemmove(vm, a1, a2, a3, false);
        if (h == H_SOL_MEMSET) return _sysMemset(vm, a1, a2, a3);
        if (h == H_SOL_MEMCMP) return _sysMemcmp(vm, a1, a2, a3, a4);
        if (h == H_SOL_LOG_PUBKEY) return _sysLogPubkey(vm, a1);
        if (h == H_SOL_LOG_COMPUTE_UNITS) return _sysLogComputeUnits(vm);
        if (h == H_SOL_LOG_DATA) return _sysLogData(vm, a1, a2);
        if (h == H_SOL_SET_RETURN_DATA) return _sysSetReturnData(vm, a1, a2);
        if (h == H_SOL_GET_RETURN_DATA) return _sysGetReturnData(vm, a1, a2, a3);
        if (h == H_SOL_GET_STACK_HEIGHT) return _sysSimple(vm, 1);
        if (h == H_SOL_REMAINING_COMPUTE_UNITS) return _sysSimple(vm, 2);
        if (h == H_SOL_GET_CLOCK_SYSVAR) return _sysGetSysvar(vm, env, SV_CLOCK, 40, 8, a1);
        if (h == H_SOL_GET_EPOCH_SCHEDULE_SYSVAR) return _sysGetSysvar(vm, env, SV_EPOCH_SCHEDULE, 40, 8, a1);
        if (h == H_SOL_GET_RENT_SYSVAR) return _sysGetSysvar(vm, env, SV_RENT, 24, 8, a1);
        if (h == H_SOL_GET_LAST_RESTART_SLOT) return _sysGetSysvar(vm, env, SV_LAST_RESTART_SLOT, 8, 8, a1);
        if (h == H_SOL_GET_EPOCH_REWARDS_SYSVAR) return _sysGetSysvar(vm, env, SV_EPOCH_REWARDS, 96, 16, a1);
        if (h == H_SOL_GET_SYSVAR) return _sysSysvarGeneric(vm, env, a1, a2, a3, a4);
        if (h == H_SOL_SHA256) return _sysHash(vm, a1, a2, a3, false);
        if (h == H_SOL_KECCAK256) return _sysHash(vm, a1, a2, a3, true);
        if (h == H_SOL_PANIC) return _sysPanic(vm, a1, a2, a3, a4);
        if (h == H_ABORT) return (uint256(Status.SyscallError), E_ABORT);
        if (h == H_SOL_INVOKE_SIGNED_RUST) return (uint256(Status.Cpi), 1); // o runtime executa a CPI e retoma
        if (h == H_SOL_INVOKE_SIGNED_C) return (uint256(Status.Cpi), 0);
        if (h == H_SOL_CREATE_PROGRAM_ADDRESS) return _sysProgramAddress(vm, false);
        if (h == H_SOL_TRY_FIND_PROGRAM_ADDRESS) return _sysProgramAddress(vm, true);
        if (
            h == H_SOL_SECP256K1_RECOVER
                || h == H_SOL_BLAKE3 || h == H_SOL_SHA512 || h == H_SOL_CURVE_VALIDATE_POINT || h == H_SOL_CURVE_GROUP_OP
                || h == H_SOL_CURVE_MULTISCALAR_MUL || h == H_SOL_CURVE_DECOMPRESS || h == H_SOL_CURVE_PAIRING_MAP
                || h == H_SOL_GET_PROCESSED_SIBLING_INSTRUCTION
                || h == H_SOL_ALT_BN128_GROUP_OP || h == H_SOL_BIG_MOD_EXP || h == H_SOL_POSEIDON
                || h == H_SOL_ALT_BN128_COMPRESSION || h == H_SOL_GET_EPOCH_STAKE || h == H_SOL_ALLOC_FREE
        ) return (uint256(Status.SyscallError), E_UNIMPLEMENTED);
        return (uint256(Status.Invalid), 0); // hash desconhecido: UnsupportedInstruction
    }

    // --- medidor

    /// @dev `consume_checked` do agave: falha se não houver saldo (e zera o saldo).
    function _consume(uint256 vm, uint256 amount) private pure returns (bool ok) {
        assembly ("memory-safe") {
            let cu := mload(add(vm, CU))
            let maxCu := mload(add(vm, MAXCU))
            switch gt(amount, sub(maxCu, cu))
            case 1 {
                mstore(add(vm, CU), maxCu)
                mstore(add(vm, FAULT), shl(129, 1))
            }
            default {
                mstore(add(vm, CU), add(cu, amount))
                ok := 1
            }
        }
    }

    function _remaining(uint256 vm) private pure returns (uint256 rem) {
        assembly ("memory-safe") {
            rem := sub(mload(add(vm, MAXCU)), mload(add(vm, CU)))
        }
    }

    function _setR0(uint256 vm, uint256 v) private pure {
        assembly ("memory-safe") {
            mstore(vm, v)
        }
    }

    // --- tradução de endereços (mesma lógica do Yul de `_exec`)

    /// @dev Traduz [vaddr, vaddr+len) para um ponteiro de memória (0 = AccessViolation).
    ///      Escritas podem fazer a região crescer até `reserved`.
    function _map(uint256 vm, uint256 vaddr, uint256 len, bool write) private pure returns (uint256 host) {
        assembly ("memory-safe") {
            let lo := 0
            let hi := mload(add(vm, NREG))
            for {} lt(lo, hi) {} {
                let mid := shr(1, add(lo, hi))
                switch gt(mload(add(add(vm, REGTAB), mul(mid, 160))), vaddr)
                case 1 { hi := mid }
                default { lo := add(mid, 1) }
            }
            if lo {
                let e := add(add(vm, REGTAB), mul(sub(lo, 1), 160))
                let ok := 1
                if write { if iszero(and(mload(add(e, 96)), 1)) { ok := 0 } }
                let off := sub(vaddr, mload(e))
                let end := add(off, len)
                if and(ok, gt(end, mload(add(e, 32)))) {
                    switch and(write, iszero(gt(end, mload(add(e, 128)))))
                    case 1 { mstore(add(e, 32), mload(add(e, 128))) }
                    default { ok := 0 }
                }
                if ok {
                    // região esparsa (pilha/heap): aloca até `end` antes de entregar o ponteiro
                    let fl := mload(add(e, 96))
                    if and(and(shr(1, fl), 1), gt(end, shr(64, fl))) {
                        let cap := shr(64, fl)
                        let ncap := shl(1, cap)
                        if lt(ncap, 8192) { ncap := 8192 }
                        if lt(ncap, end) { ncap := and(add(end, 8191), not(8191)) }
                        if gt(ncap, mload(add(e, 32))) { ncap := mload(add(e, 32)) }
                        let p := add(mload(0x40), 32)
                        mstore(0x40, add(p, ncap))
                        calldatacopy(p, calldatasize(), ncap)
                        mcopy(p, mload(add(e, 64)), cap)
                        mstore(add(e, 64), p)
                        mstore(add(e, 96), or(and(fl, 3), shl(64, ncap)))
                    }
                    switch and(fl, 4)
                    case 0 { host := add(mload(add(e, 64)), off) }
                    default {
                        // região no calldata (só leitura): cópia do trecho pedido
                        host := mload(0x40)
                        mstore(0x40, add(host, and(add(len, 31), not(31))))
                        calldatacopy(host, add(mload(add(e, 64)), off), len)
                    }
                }
            }
            // bit 129: falha dentro de uma syscall (o agave não esgota o medidor nesse caso)
            if iszero(host) { mstore(add(vm, FAULT), or(or(vaddr, shl(64, len)), or(shl(128, write), shl(129, 1)))) }
        }
    }

    /// @dev `translate_slice`: tamanho 0 não mapeia; tamanho > isize::MAX é InvalidLength;
    ///      alinhamento conferido no endereço. Devolve (status, err, host).
    function _slice(uint256 vm, uint256 vaddr, uint256 len, uint256 align, bool write) private pure returns (uint256 st, uint64 err, uint256 host) {
        if (len == 0) return (0, 0, 1);
        if (len > 0x7fffffffffffffff) return (uint256(Status.SyscallError), E_INVALID_LENGTH, 0);
        host = _map(vm, vaddr, len, write);
        if (host == 0) return (uint256(Status.AccessViolation), 0, 0);
        if (vaddr % align != 0) return (uint256(Status.SyscallError), E_UNALIGNED_POINTER, 0);
    }

    // --- logs

    /// @dev Acrescenta uma entrada [tipo:1][tamanho:4][payload] ao buffer de logs (ignora se não couber).
    function _logEntry(uint256 vm, uint256 kind, uint256 src, uint256 len) private pure {
        assembly ("memory-safe") {
            let used := mload(add(vm, LOGL))
            if iszero(gt(add(add(used, 5), len), LOG_CAPACITY)) {
                let p := add(mload(add(vm, LOGP)), used)
                mstore8(p, kind)
                mstore8(add(p, 1), byte(28, len))
                mstore8(add(p, 2), byte(29, len))
                mstore8(add(p, 3), byte(30, len))
                mstore8(add(p, 4), byte(31, len))
                mcopy(add(p, 5), src, len)
                mstore(add(vm, LOGL), add(add(used, 5), len))
            }
        }
    }

    function _logBytes(uint256 vm, uint256 kind, bytes memory b) private pure {
        uint256 src;
        assembly ("memory-safe") {
            src := add(b, 32)
        }
        _logEntry(vm, kind, src, b.length);
    }

    /// @dev Validação UTF-8 (`core::str::from_utf8`).
    function _utf8(uint256 p, uint256 len) private pure returns (bool) {
        unchecked {
            uint256 i = 0;
            while (i < len) {
                uint8 c = _b(p + i);
                if (c < 0x80) {
                    i++;
                    continue;
                }
                uint256 need;
                uint256 lo = 0x80;
                uint256 hi = 0xbf;
                if (c >= 0xc2 && c <= 0xdf) need = 1;
                else if (c == 0xe0) {
                    need = 2;
                    lo = 0xa0;
                } else if (c >= 0xe1 && c <= 0xec) need = 2;
                else if (c == 0xed) {
                    need = 2;
                    hi = 0x9f;
                } else if (c >= 0xee && c <= 0xef) need = 2;
                else if (c == 0xf0) {
                    need = 3;
                    lo = 0x90;
                } else if (c >= 0xf1 && c <= 0xf3) need = 3;
                else if (c == 0xf4) {
                    need = 3;
                    hi = 0x8f;
                } else return false;
                if (i + need >= len) return false;
                uint8 c1 = _b(p + i + 1);
                if (c1 < lo || c1 > hi) return false;
                for (uint256 k = 2; k <= need; k++) {
                    uint8 ck = _b(p + i + k);
                    if (ck < 0x80 || ck > 0xbf) return false;
                }
                i += need + 1;
            }
            return true;
        }
    }

    function _b(uint256 p) private pure returns (uint8 v) {
        assembly ("memory-safe") {
            v := byte(0, mload(p))
        }
    }

    // sol_log_(addr, len)
    function _sysLog(uint256 vm, uint256 addr, uint256 len) private pure returns (uint256 st, uint64 err) {
        if (!_consume(vm, len > SYSCALL_BASE ? len : SYSCALL_BASE)) return (uint256(Status.CuExceeded), 0);
        uint256 host;
        (st, err, host) = _slice(vm, addr, len, 1, false);
        if (st != 0) return (st, err);
        if (!_utf8(host, len)) return (uint256(Status.SyscallError), E_INVALID_STRING);
        _logEntry(vm, 0, host, len);
        _setR0(vm, 0);
    }

    // sol_log_64_(a, b, c, d, e): "0x1, 0x2, 0x3, 0x4, 0x5"
    function _sysLog64(uint256 vm) private pure returns (uint256 st, uint64 err) {
        if (!_consume(vm, LOG_64_UNITS)) return (uint256(Status.CuExceeded), 0);
        bytes memory s;
        for (uint256 i = 1; i <= 5; i++) {
            uint256 v;
            assembly ("memory-safe") {
                v := mload(add(vm, mul(i, 32)))
            }
            s = i == 1 ? _hex(v) : bytes.concat(s, ", ", _hex(v));
        }
        _logBytes(vm, 0, s);
        _setR0(vm, 0);
    }

    // sol_log_pubkey(addr)
    function _sysLogPubkey(uint256 vm, uint256 addr) private pure returns (uint256 st, uint64 err) {
        if (!_consume(vm, LOG_PUBKEY_UNITS)) return (uint256(Status.CuExceeded), 0);
        uint256 host = _map(vm, addr, 32, false);
        if (host == 0) return (uint256(Status.AccessViolation), 0);
        _logEntry(vm, 1, host, 32);
        _setR0(vm, 0);
    }

    // sol_log_compute_units_(): "Program consumption: N units remaining"
    function _sysLogComputeUnits(uint256 vm) private pure returns (uint256 st, uint64 err) {
        if (!_consume(vm, SYSCALL_BASE)) return (uint256(Status.CuExceeded), 0);
        _logBytes(vm, 0, bytes.concat("Program consumption: ", _dec(_remaining(vm)), " units remaining"));
        _setR0(vm, 0);
    }

    // sol_log_data(addr, len): len fatias (ptr u64, len u64) → payload [u32 len][bytes]...
    function _sysLogData(uint256 vm, uint256 addr, uint256 len) private pure returns (uint256 st, uint64 err) {
        if (!_consume(vm, SYSCALL_BASE)) return (uint256(Status.CuExceeded), 0);
        if (len > uint256(0x7fffffffffffffff) / 16) return (uint256(Status.SyscallError), E_INVALID_LENGTH);
        uint256 vals;
        (st, err, vals) = _slice(vm, addr, len * 16, 8, false);
        if (st != 0) return (st, err);
        if (!_consume(vm, SYSCALL_BASE * len)) return (uint256(Status.CuExceeded), 0);
        uint256 total;
        for (uint256 i = 0; i < len; i++) {
            uint256 fl = _u64m(vals + i * 16 + 8);
            total = total + fl > MASK64 ? MASK64 : total + fl; // saturating
        }
        if (!_consume(vm, total)) return (uint256(Status.CuExceeded), 0);
        bytes memory payload;
        for (uint256 i = 0; i < len; i++) {
            uint256 fp = _u64m(vals + i * 16);
            uint256 fl = _u64m(vals + i * 16 + 8);
            uint256 host;
            (st, err, host) = _slice(vm, fp, fl, 1, false);
            if (st != 0) return (st, err);
            bytes memory field = new bytes(fl);
            assembly ("memory-safe") {
                mcopy(add(field, 32), host, fl)
            }
            payload = bytes.concat(payload, bytes4(uint32(fl)), field);
        }
        _logBytes(vm, 2, payload);
        _setR0(vm, 0);
    }

    // sol_panic_(file, len, line, column)
    function _sysPanic(uint256 vm, uint256 file, uint256 len, uint256 line, uint256 column) private pure returns (uint256 st, uint64 err) {
        if (!_consume(vm, len)) return (uint256(Status.CuExceeded), 0);
        uint256 host;
        (st, err, host) = _slice(vm, file, len, 1, false);
        if (st != 0) return (st, err);
        if (!_utf8(host, len)) return (uint256(Status.SyscallError), E_INVALID_STRING);
        bytes memory msg_ = new bytes(len);
        assembly ("memory-safe") {
            mcopy(add(msg_, 32), host, len)
        }
        _logBytes(vm, 3, bytes.concat(bytes8(uint64(line)), bytes8(uint64(column)), msg_));
        return (uint256(Status.SyscallError), E_PANIC);
    }

    // --- memória

    function _memOpConsume(uint256 vm, uint256 n) private pure returns (bool) {
        uint256 c = n / CPI_BYTES_PER_UNIT;
        return _consume(vm, c > MEM_OP_BASE ? c : MEM_OP_BASE);
    }

    // sol_memcpy_ / sol_memmove_(dst, src, n)
    function _sysMemmove(uint256 vm, uint256 dst, uint256 src, uint256 n, bool checkOverlap) private pure returns (uint256 st, uint64 err) {
        if (!_memOpConsume(vm, n)) return (uint256(Status.CuExceeded), 0);
        if (checkOverlap) {
            bool nonOverlapping = src > dst ? src - dst >= n : dst - src >= n;
            if (!nonOverlapping) return (uint256(Status.SyscallError), E_COPY_OVERLAPPING);
        }
        uint256 d;
        uint256 s;
        (st, err, d) = _slice(vm, dst, n, 1, true);
        if (st != 0) return (st, err);
        (st, err, s) = _slice(vm, src, n, 1, false);
        if (st != 0) return (st, err);
        if (n != 0) {
            assembly ("memory-safe") {
                mcopy(d, s, n) // mcopy lida com sobreposição
            }
        }
        _setR0(vm, 0);
    }

    // sol_memset_(dst, c, n)
    function _sysMemset(uint256 vm, uint256 dst, uint256 c, uint256 n) private pure returns (uint256 st, uint64 err) {
        if (!_memOpConsume(vm, n)) return (uint256(Status.CuExceeded), 0);
        uint256 d;
        (st, err, d) = _slice(vm, dst, n, 1, true);
        if (st != 0) return (st, err);
        if (n != 0) {
            assembly ("memory-safe") {
                for { let i := 0 } lt(i, n) { i := add(i, 1) } { mstore8(add(d, i), c) }
            }
        }
        _setR0(vm, 0);
    }

    // sol_memcmp_(s1, s2, n, result): escreve i32 (primeiro byte diferente: a - b)
    function _sysMemcmp(uint256 vm, uint256 s1, uint256 s2, uint256 n, uint256 resAddr) private pure returns (uint256 st, uint64 err) {
        if (!_memOpConsume(vm, n)) return (uint256(Status.CuExceeded), 0);
        uint256 a;
        uint256 b;
        (st, err, a) = _slice(vm, s1, n, 1, false);
        if (st != 0) return (st, err);
        (st, err, b) = _slice(vm, s2, n, 1, false);
        if (st != 0) return (st, err);
        int256 res;
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let x := byte(0, mload(add(a, i)))
                let y := byte(0, mload(add(b, i)))
                if iszero(eq(x, y)) {
                    res := sub(x, y)
                    break
                }
            }
        }
        uint256 host = _map(vm, resAddr, 4, true);
        if (host == 0) return (uint256(Status.AccessViolation), 0);
        if (resAddr % 4 != 0) return (uint256(Status.SyscallError), E_UNALIGNED_POINTER);
        _storeLE(host, uint256(res) & 0xffffffff, 4);
        _setR0(vm, 0);
    }

    // --- return data

    // sol_set_return_data(addr, len)
    function _sysSetReturnData(uint256 vm, uint256 addr, uint256 len) private pure returns (uint256 st, uint64 err) {
        if (!_consume(vm, len / CPI_BYTES_PER_UNIT + SYSCALL_BASE)) return (uint256(Status.CuExceeded), 0);
        if (len > MAX_RETURN_DATA) return (uint256(Status.SyscallError), E_RETURN_DATA_TOO_LARGE);
        uint256 host;
        (st, err, host) = _slice(vm, addr, len, 1, false);
        if (st != 0) return (st, err);
        assembly ("memory-safe") {
            let p := mload(add(vm, RETP))
            if len { mcopy(p, host, len) }
            mstore(add(vm, RETL), len)
            mstore(sub(p, 32), mload(add(vm, PID)))
        }
        _setR0(vm, 0);
    }

    // sol_get_return_data(addr, length, programIdAddr) → tamanho total do return data
    function _sysGetReturnData(uint256 vm, uint256 addr, uint256 length, uint256 pidAddr) private pure returns (uint256 st, uint64 err) {
        if (!_consume(vm, SYSCALL_BASE)) return (uint256(Status.CuExceeded), 0);
        uint256 retLen;
        assembly ("memory-safe") {
            retLen := mload(add(vm, RETL))
        }
        if (length > retLen) length = retLen;
        if (length != 0) {
            if (!_consume(vm, (length + 32) / CPI_BYTES_PER_UNIT)) return (uint256(Status.CuExceeded), 0);
            uint256 to = _map(vm, addr, length, true);
            if (to == 0) return (uint256(Status.AccessViolation), 0);
            uint256 pidHost = _map(vm, pidAddr, 32, true);
            if (pidHost == 0) return (uint256(Status.AccessViolation), 0);
            bool nonOverlapping = to > pidHost ? to - pidHost >= 32 : pidHost - to >= length;
            if (!nonOverlapping) return (uint256(Status.SyscallError), E_COPY_OVERLAPPING);
            assembly ("memory-safe") {
                let p := mload(add(vm, RETP))
                mcopy(to, p, length)
                mstore(pidHost, mload(sub(p, 32)))
            }
        }
        _setR0(vm, retLen);
    }

    // --- diversas

    /// @dev sol_get_stack_height (1) / sol_remaining_compute_units (2)
    function _sysSimple(uint256 vm, uint256 which) private pure returns (uint256 st, uint64 err) {
        if (!_consume(vm, SYSCALL_BASE)) return (uint256(Status.CuExceeded), 0);
        _setR0(vm, which == 1 ? 1 : _remaining(vm));
    }

    // --- sysvars

    function _findSysvar(Env calldata env, bytes32 id) private pure returns (bool found, uint256 idx) {
        for (uint256 i = 0; i < env.sysvars.length; i++) {
            if (env.sysvars[i].id == id) return (true, i);
        }
    }

    /// @dev sol_get_{clock,epoch_schedule,rent,last_restart_slot,epoch_rewards}_sysvar(var_addr):
    ///      escreve a imagem em memória da struct (`size` bytes, alinhamento `align`).
    function _sysGetSysvar(uint256 vm, Env calldata env, bytes32 id, uint256 size, uint256 align, uint256 varAddr)
        private
        pure
        returns (uint256 st, uint64 err)
    {
        if (!_consume(vm, SYSVAR_BASE + size)) return (uint256(Status.CuExceeded), 0);
        if (varAddr >= INPUT_START) return (uint256(Status.SyscallError), E_INVALID_POINTER);
        uint256 host = _map(vm, varAddr, size, true);
        if (host == 0) return (uint256(Status.AccessViolation), 0);
        if (varAddr % align != 0) return (uint256(Status.SyscallError), E_UNALIGNED_POINTER);
        (bool found, uint256 idx) = _findSysvar(env, id);
        if (!found) return (uint256(Status.SyscallError), E_UNSUPPORTED_SYSVAR);
        bytes calldata data = env.sysvars[idx].data;
        // a serialização bincode pode ser menor que a struct (Rent: 17 de 24 bytes): o resto é padding zerado
        if (data.length > size) return (uint256(Status.SyscallError), E_UNSUPPORTED_SYSVAR);
        assembly ("memory-safe") {
            calldatacopy(host, data.offset, data.length)
            calldatacopy(add(host, data.length), calldatasize(), sub(size, data.length))
        }
        _setR0(vm, 0);
    }

    /// @dev sol_get_sysvar(id_addr, var_addr, offset, length): 0 ok, 1 fora do intervalo, 2 não existe
    function _sysSysvarGeneric(uint256 vm, Env calldata env, uint256 idAddr, uint256 varAddr, uint256 offset, uint256 length)
        private
        pure
        returns (uint256 st, uint64 err)
    {
        {
            uint256 bufCost = length / CPI_BYTES_PER_UNIT;
            if (!_consume(vm, SYSVAR_BASE + 32 / CPI_BYTES_PER_UNIT + (bufCost > MEM_OP_BASE ? bufCost : MEM_OP_BASE))) {
                return (uint256(Status.CuExceeded), 0);
            }
        }
        if (varAddr >= INPUT_START) return (uint256(Status.SyscallError), E_INVALID_POINTER);
        uint256 host;
        (st, err, host) = _slice(vm, varAddr, length, 1, true);
        if (st != 0) return (st, err);
        uint256 idHost = _map(vm, idAddr, 32, false);
        if (idHost == 0) return (uint256(Status.AccessViolation), 0);
        if (offset + length > MASK64 || varAddr + length > MASK64) return (uint256(Status.SyscallError), E_ARITHMETIC_OVERFLOW);
        bytes32 id;
        assembly ("memory-safe") {
            id := mload(idHost)
        }
        (bool found, uint256 idx) = _findSysvar(env, id);
        if (!found) {
            _setR0(vm, 2);
            return (0, 0);
        }
        bytes calldata data = env.sysvars[idx].data;
        if (offset + length > data.length) {
            _setR0(vm, 1);
            return (0, 0);
        }
        if (length != 0) {
            uint256 src;
            assembly ("memory-safe") {
                src := add(data.offset, offset)
                calldatacopy(host, src, length)
            }
        }
        _setR0(vm, 0);
    }

    // --- hashes

    /// @dev sol_sha256 / sol_keccak256(vals, nvals, result): vals = fatias (ptr, len)
    function _sysHash(uint256 vm, uint256 valsAddr, uint256 valsLen, uint256 resultAddr, bool keccak) private pure returns (uint256 st, uint64 err) {
        if (valsLen > SHA256_MAX_SLICES) return (uint256(Status.SyscallError), E_TOO_MANY_SLICES);
        if (!_consume(vm, SHA256_BASE)) return (uint256(Status.CuExceeded), 0);
        uint256 res = _map(vm, resultAddr, 32, true);
        if (res == 0) return (uint256(Status.AccessViolation), 0);
        bytes memory buf;
        if (valsLen > 0) {
            uint256 vals;
            (st, err, vals) = _slice(vm, valsAddr, valsLen * 16, 8, false);
            if (st != 0) return (st, err);
            for (uint256 i = 0; i < valsLen; i++) {
                uint256 fp = _u64m(vals + i * 16);
                uint256 fl = _u64m(vals + i * 16 + 8);
                uint256 host;
                (st, err, host) = _slice(vm, fp, fl, 1, false);
                if (st != 0) return (st, err);
                uint256 c = SHA256_BYTE * (fl / 2);
                if (!_consume(vm, c > MEM_OP_BASE ? c : MEM_OP_BASE)) return (uint256(Status.CuExceeded), 0);
                bytes memory part = new bytes(fl);
                assembly ("memory-safe") {
                    mcopy(add(part, 32), host, fl)
                }
                buf = bytes.concat(buf, part);
            }
        }
        bytes32 hsh = keccak ? keccak256(buf) : sha256(buf);
        assembly ("memory-safe") {
            mstore(res, hsh)
        }
        _setR0(vm, 0);
    }

    // --- utilidades

    function _u64m(uint256 p) private pure returns (uint256 v) {
        assembly ("memory-safe") {
            let w := mload(p)
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } { v := or(v, shl(mul(i, 8), byte(i, w))) }
        }
    }

    function _storeLE(uint256 p, uint256 value, uint256 size) private pure {
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, size) { i := add(i, 1) } { mstore8(add(p, i), byte(sub(31, i), value)) }
        }
    }

    /// @dev "0x" + hexadecimal minúsculo sem zeros à esquerda (formato `{:#x}` do Rust).
    function _hex(uint256 v) private pure returns (bytes memory s) {
        bytes16 digits = "0123456789abcdef";
        uint256 n = 1;
        for (uint256 t = v; t >= 16; t /= 16) n++;
        s = new bytes(2 + n);
        s[0] = "0";
        s[1] = "x";
        for (uint256 i = 0; i < n; i++) {
            s[1 + n - i] = digits[v & 15];
            v >>= 4;
        }
    }

    function _dec(uint256 v) private pure returns (bytes memory s) {
        uint256 n = 1;
        for (uint256 t = v; t >= 10; t /= 10) n++;
        s = new bytes(n);
        for (uint256 i = 0; i < n; i++) {
            s[n - 1 - i] = bytes1(uint8(48 + v % 10));
            v /= 10;
        }
    }
    // ------------------------------------------------------------------ PDAs
    //
    // sol_create_program_address / sol_try_find_program_address (agave 4.3). A CPI em si
    // (sol_invoke_signed_*) suspende a VM: o SolanaRuntime executa a instrução chamada com o
    // SolanaCpi e retoma a execução com `resumeElfVerified`.

    uint256 private constant CREATE_PROGRAM_ADDRESS_UNITS = 1500;
    uint256 private constant MAX_SEEDS = 16;
    uint256 private constant MAX_SEED_LEN = 32;
    uint256 private constant ED_P = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
    uint256 private constant ED_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555;

    function _cpiErr(uint256 sub, uint256 n) private pure returns (uint256 st, uint64 err) {
        return (uint256(Status.SyscallError), uint64(uint256(E_CPI) | (sub << 8) | ((n & 0xffffffff) << 32)));
    }

    function _b32m(uint256 p) private pure returns (bytes32 v) {
        assembly ("memory-safe") {
            v := mload(p)
        }
    }

    // --- derivação de endereços (PDA)

    /// @dev sha256(seeds || programId || "ProgramDerivedAddress"); ok = fora da curva ed25519.
    function _pda(bytes memory seeds, bytes32 programId) private view returns (bool ok, bytes32 h) {
        h = sha256(bytes.concat(seeds, programId, "ProgramDerivedAddress"));
        ok = !_onCurve(h);
    }

    /// @dev `CompressedEdwardsY::decompress().is_some()`: y = bytes LE sem o bit de sinal;
    ///      u = y²−1, v = d·y²+1; válido se u = 0, ou v ≠ 0 e u/v é resíduo quadrático.
    function _onCurve(bytes32 h) private view returns (bool) {
        uint256 y;
        for (uint256 i = 0; i < 32; i++) y |= uint256(uint8(h[i])) << (8 * i);
        y = (y & ((1 << 255) - 1)) % ED_P;
        uint256 yy = mulmod(y, y, ED_P);
        uint256 u = addmod(yy, ED_P - 1, ED_P);
        uint256 v = addmod(mulmod(ED_D, yy, ED_P), 1, ED_P);
        if (u == 0) return true;
        if (v == 0) return false;
        return _modexp(mulmod(u, v, ED_P), (ED_P - 1) / 2, ED_P) == 1;
    }

    function _modexp(uint256 b, uint256 e, uint256 m) private view returns (uint256 r) {
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, 32)
            mstore(add(p, 32), 32)
            mstore(add(p, 64), 32)
            mstore(add(p, 96), b)
            mstore(add(p, 128), e)
            mstore(add(p, 160), m)
            if iszero(staticcall(gas(), 5, p, 192, p, 32)) { revert(0, 0) }
            r := mload(p)
        }
    }

    /// @dev Lê `n` VmSlices (ptr, len) em `addr` e devolve as fatias concatenadas; `maxLen` por fatia
    ///      (0 = sem limite). Erros: tradução, e `tooLong` quando alguma passa de maxLen.
    function _seedBytes(uint256 vm, uint256 addr, uint256 n, uint256 maxLen) private pure returns (uint256 st, uint64 err, bytes memory out, bool tooLong) {
        uint256 vals;
        (st, err, vals) = _slice(vm, addr, n * 16, 8, false);
        if (st != 0) return (st, err, out, false);
        for (uint256 i = 0; i < n; i++) {
            uint256 fl = _u64m(vals + i * 16 + 8);
            if (maxLen != 0 && fl > maxLen) return (0, 0, out, true);
            uint256 host;
            (st, err, host) = _slice(vm, _u64m(vals + i * 16), fl, 1, false);
            if (st != 0) return (st, err, out, false);
            bytes memory part = new bytes(fl);
            assembly ("memory-safe") {
                mcopy(add(part, 32), host, fl)
            }
            out = bytes.concat(out, part);
        }
    }

    // sol_create_program_address(seeds, n, programId, address) / sol_try_find_program_address(..., bump)
    function _sysProgramAddress(uint256 vm, bool tryFind) private view returns (uint256 st, uint64 err) {
        if (!_consume(vm, CREATE_PROGRAM_ADDRESS_UNITS)) return (uint256(Status.CuExceeded), 0);
        uint256 n;
        uint256 a1;
        assembly ("memory-safe") {
            a1 := mload(add(vm, 32))
            n := mload(add(vm, 64))
        }
        if (n > MAX_SEEDS) return _cpiErr(3, 0);
        bytes memory seeds;
        bool tooLong;
        (st, err, seeds, tooLong) = _seedBytes(vm, a1, n, MAX_SEED_LEN);
        if (st != 0) return (st, err);
        if (tooLong) return _cpiErr(3, 0);
        uint256 pidHost;
        assembly ("memory-safe") {
            a1 := mload(add(vm, 96))
        }
        (st, err, pidHost) = _slice(vm, a1, 32, 1, false);
        if (st != 0) return (st, err);
        return tryFind ? _findPda(vm, seeds, _b32m(pidHost)) : _createPda(vm, seeds, _b32m(pidHost));
    }

    function _createPda(uint256 vm, bytes memory seeds, bytes32 pid) private view returns (uint256 st, uint64 err) {
        (bool ok, bytes32 h) = _pda(seeds, pid);
        if (!ok) {
            _setR0(vm, 1);
            return (0, 0);
        }
        uint256 addr;
        assembly ("memory-safe") {
            addr := mload(add(vm, 128))
        }
        uint256 out = _map(vm, addr, 32, true);
        if (out == 0) return (uint256(Status.AccessViolation), 0);
        assembly ("memory-safe") {
            mstore(out, h)
        }
        _setR0(vm, 0);
    }

    function _findPda(uint256 vm, bytes memory seeds, bytes32 pid) private view returns (uint256 st, uint64 err) {
        uint256 bump = 255;
        for (uint256 i = 0; i < 255; i++) {
            (bool ok, bytes32 h) = _pda(bytes.concat(seeds, bytes1(uint8(bump))), pid);
            if (ok) return _writePda(vm, h, bump);
            if (bump > 0) bump--;
            if (!_consume(vm, CREATE_PROGRAM_ADDRESS_UNITS)) return (uint256(Status.CuExceeded), 0);
        }
        _setR0(vm, 1);
    }

    function _writePda(uint256 vm, bytes32 h, uint256 bump) private pure returns (uint256 st, uint64 err) {
        uint256 addr;
        uint256 bumpAddr;
        assembly ("memory-safe") {
            addr := mload(add(vm, 128))
            bumpAddr := mload(add(vm, 160))
        }
        uint256 bumpHost = _map(vm, bumpAddr, 1, true);
        if (bumpHost == 0) return (uint256(Status.AccessViolation), 0);
        uint256 out = _map(vm, addr, 32, true);
        if (out == 0) return (uint256(Status.AccessViolation), 0);
        bool nonOverlapping = out > bumpHost ? out - bumpHost >= 1 : bumpHost - out >= 32;
        if (!nonOverlapping) return (uint256(Status.SyscallError), E_COPY_OVERLAPPING);
        assembly ("memory-safe") {
            mstore8(bumpHost, bump)
            mstore(out, h)
        }
        _setR0(vm, 0);
    }

}
