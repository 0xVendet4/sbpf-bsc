// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title SbpfVM — interpretador sBPF (Solana BPF) escrito em Solidity
/// @notice Executa bytecode sBPF dentro da EVM (BSC). Semântica de ALU baseada no
///         sBPF v1 do rbpf (add32/sub32/mul32 com extensão de sinal), chamadas
///         internas e callx no estilo SBPFv2+ (call src=1 relativo ao ip, callx usa `src`).
/// @dev    Mapa de memória igual ao do Solana:
///         0x1_0000_0000 programa (somente leitura: .text + rodata)
///         0x2_0000_0000 pilha (FRAME_SIZE por frame, MAX_DEPTH frames)
///         0x3_0000_0000 heap
///         0x4_0000_0000 input (leitura e escrita; devolvido no resultado)
library SbpfVM {
    uint256 internal constant MM_PROGRAM = 0x100000000;
    uint256 internal constant MM_STACK = 0x200000000;
    uint256 internal constant MM_HEAP = 0x300000000;
    uint256 internal constant MM_INPUT = 0x400000000;

    uint256 internal constant FRAME_SIZE = 4096;
    uint256 internal constant MAX_DEPTH = 4;
    uint256 internal constant HEAP_SIZE = 4096;
    uint256 internal constant MAX_LOGS = 32;

    uint256 private constant U64 = 0xffffffffffffffff;
    uint256 private constant U32 = 0xffffffff;

    // Hashes murmur3_32 dos nomes das syscalls (iguais aos do Solana)
    uint256 private constant SYS_ABORT = 0xb6fc1a11;
    uint256 private constant SYS_PANIC = 0x686093bb;
    uint256 private constant SYS_LOG = 0x207559bd;
    uint256 private constant SYS_LOG64 = 0x5c2a3178;
    uint256 private constant SYS_LOG_CU = 0x52ba5096;
    uint256 private constant SYS_KECCAK = 0xd7793abb;
    uint256 private constant SYS_MEMCPY = 0x717cc4a3;
    uint256 private constant SYS_MEMMOVE = 0x434371f8;
    uint256 private constant SYS_MEMSET = 0x3770fb22;
    uint256 private constant SYS_MEMCMP = 0x5fdcde31;

    uint256 private constant SYSCALL_COST = 100;

    error ComputeBudgetExceeded(uint256 budget);
    error PcOutOfBounds(uint256 ip);
    error InvalidInstruction(uint256 ip, uint256 opcode);
    error InvalidRegister(uint256 ip, uint256 reg);
    error AccessViolation(uint256 ip, uint256 vaddr, uint256 len, bool write);
    error DivisionByZero(uint256 ip);
    error CallDepthExceeded(uint256 ip);
    error InvalidCallTarget(uint256 ip, uint256 target);
    error UnknownSyscall(uint256 ip, uint256 hash);
    error ProgramAborted(uint256 ip);
    error ProgramPanicked(uint256 ip, bytes file, uint64 line, uint64 column);

    /// @dev kind 0 = sol_log_ (texto), 1 = sol_log_64_ (5 x u64), 2 = sol_log_compute_units_
    struct Log {
        uint8 kind;
        bytes data;
        uint64[5] values;
    }

    struct Result {
        uint64 r0; // valor de retorno (0 = sucesso, convenção Solana)
        uint256 steps; // compute units consumidas
        bytes input; // região de input após a execução (escritas do programa)
        Log[] logs;
    }

    struct VM {
        uint256[11] r;
        bytes prog;
        bytes stack;
        bytes heap;
        bytes input;
        uint256 ip;
        uint256 depth;
        uint256[25] frames; // MAX_DEPTH * (r6..r9 + ip) + folga
        uint256 steps;
        uint256 budget;
        Log[] logs;
        uint256 nlogs;
    }

    /// @notice Executa `prog` com `input` mapeado em MM_INPUT. r1 = MM_INPUT, r10 = topo do frame 0.
    function run(bytes memory prog, bytes memory input, uint256 budget) internal pure returns (Result memory res) {
        VM memory vm;
        vm.prog = prog;
        vm.stack = new bytes(FRAME_SIZE * MAX_DEPTH);
        vm.heap = new bytes(HEAP_SIZE);
        vm.input = input;
        vm.budget = budget;
        vm.logs = new Log[](MAX_LOGS);
        vm.r[1] = MM_INPUT;
        vm.r[10] = MM_STACK + FRAME_SIZE;

        _execute(vm);

        res.r0 = uint64(vm.r[0]);
        res.steps = vm.steps;
        res.input = vm.input;
        Log[] memory logs = vm.logs;
        uint256 n = vm.nlogs;
        assembly {
            mstore(logs, n) // encurta o array para o número real de logs
        }
        res.logs = logs;
    }

    // ------------------------------------------------------------------ loop principal

    function _execute(VM memory vm) private pure {
        bytes memory prog = vm.prog;
        uint256 n = prog.length / 8;
        uint256[11] memory r = vm.r;

        unchecked {
            while (true) {
                if (vm.steps >= vm.budget) revert ComputeBudgetExceeded(vm.budget);
                vm.steps++;
                uint256 ip = vm.ip;
                if (ip >= n) revert PcOutOfBounds(ip);

                uint256 opc;
                uint256 dst;
                uint256 src;
                uint256 off; // int16 estendido para 64 bits
                uint256 imm; // int32 cru (32 bits)
                assembly {
                    let w := mload(add(add(prog, 32), mul(ip, 8)))
                    opc := byte(0, w)
                    let regs := byte(1, w)
                    dst := and(regs, 0x0f)
                    src := shr(4, regs)
                    off := or(byte(2, w), shl(8, byte(3, w)))
                    imm := or(or(byte(4, w), shl(8, byte(5, w))), or(shl(16, byte(6, w)), shl(24, byte(7, w))))
                }
                if (off & 0x8000 != 0) off |= 0xffffffffffff0000;
                if (dst > 10) revert InvalidRegister(ip, dst);
                if (src > 10) revert InvalidRegister(ip, src);
                vm.ip = ip + 1;

                uint256 cls = opc & 7;
                if (cls == 7 || cls == 4) {
                    if (dst == 10) revert InvalidRegister(ip, dst);
                    r[dst] = _alu(ip, opc, r[dst], (opc & 8 != 0) ? r[src] : imm, opc & 8 != 0, imm);
                } else if (cls == 5) {
                    if (_jmp(vm, r, ip, opc, dst, src, off, imm)) return;
                } else if (cls == 1) {
                    // LDX dst = *(size*)(src + off)
                    if (dst == 10) revert InvalidRegister(ip, dst);
                    uint256 sz = _size(ip, opc, 0x61);
                    (bytes memory m, uint256 o) = _region(vm, ip, (r[src] + off) & U64, sz, false);
                    r[dst] = _load(m, o, sz);
                } else if (cls == 2) {
                    // ST *(size*)(dst + off) = imm
                    uint256 sz = _size(ip, opc, 0x62);
                    (bytes memory m, uint256 o) = _region(vm, ip, (r[dst] + off) & U64, sz, true);
                    _store(m, o, sz, _sext32(imm));
                } else if (cls == 3) {
                    // STX *(size*)(dst + off) = src
                    uint256 sz = _size(ip, opc, 0x63);
                    (bytes memory m, uint256 o) = _region(vm, ip, (r[dst] + off) & U64, sz, true);
                    _store(m, o, sz, r[src]);
                } else if (opc == 0x18) {
                    // LDDW: instrução de 16 bytes, imm64 = imm | (imm_seguinte << 32)
                    if (dst == 10) revert InvalidRegister(ip, dst);
                    if (ip + 1 >= n) revert PcOutOfBounds(ip + 1);
                    uint256 hi;
                    assembly {
                        let w := mload(add(add(prog, 32), mul(add(ip, 1), 8)))
                        hi := or(or(byte(4, w), shl(8, byte(5, w))), or(shl(16, byte(6, w)), shl(24, byte(7, w))))
                    }
                    r[dst] = imm | (hi << 32);
                    vm.ip = ip + 2;
                } else {
                    revert InvalidInstruction(ip, opc);
                }
            }
        }
    }

    // ------------------------------------------------------------------ ALU

    function _alu(uint256 ip, uint256 opc, uint256 a, uint256 b, bool isReg, uint256 imm)
        private
        pure
        returns (uint256)
    {
        uint256 op = opc & 0xf0;
        unchecked {
            if (opc & 7 == 7) {
                // ALU64
                if (!isReg) b = _sext32(b);
                if (op == 0x00) return (a + b) & U64;
                if (op == 0x10) return (a + (1 << 64) - b) & U64;
                if (op == 0x20) return (a * b) & U64;
                if (op == 0x30) {
                    if (b == 0) revert DivisionByZero(ip);
                    return a / b;
                }
                if (op == 0x40) return a | b;
                if (op == 0x50) return a & b;
                if (op == 0x60) return (a << (b & 63)) & U64;
                if (op == 0x70) return a >> (b & 63);
                if (op == 0x80) {
                    if (isReg) revert InvalidInstruction(ip, opc);
                    return ((1 << 64) - a) & U64;
                }
                if (op == 0x90) {
                    if (b == 0) revert DivisionByZero(ip);
                    return a % b;
                }
                if (op == 0xa0) return a ^ b;
                if (op == 0xb0) return b;
                if (op == 0xc0) return uint256(uint64(int64(uint64(a)) >> (b & 63)));
                revert InvalidInstruction(ip, opc);
            } else {
                // ALU32
                uint256 a32 = a & U32;
                uint256 b32 = b & U32;
                if (op == 0x00) return _sext32((a32 + b32) & U32);
                if (op == 0x10) return _sext32((a32 + (1 << 32) - b32) & U32);
                if (op == 0x20) return _sext32((a32 * b32) & U32);
                if (op == 0x30) {
                    if (b32 == 0) revert DivisionByZero(ip);
                    return a32 / b32;
                }
                if (op == 0x40) return a32 | b32;
                if (op == 0x50) return a32 & b32;
                if (op == 0x60) return (a32 << (b32 & 31)) & U32;
                if (op == 0x70) return a32 >> (b32 & 31);
                if (op == 0x80) {
                    if (isReg) revert InvalidInstruction(ip, opc);
                    return ((1 << 32) - a32) & U32;
                }
                if (op == 0x90) {
                    if (b32 == 0) revert DivisionByZero(ip);
                    return a32 % b32;
                }
                if (op == 0xa0) return a32 ^ b32;
                if (op == 0xb0) return b32;
                if (op == 0xc0) return uint256(uint32(int32(uint32(a32)) >> (b32 & 31)));
                if (op == 0xd0) {
                    // 0xd4 = le, 0xdc = be; imm = 16 | 32 | 64
                    if (imm != 16 && imm != 32 && imm != 64) revert InvalidInstruction(ip, opc);
                    uint256 mask = imm == 64 ? U64 : ((1 << imm) - 1);
                    if (!isReg) return a & mask; // le: só trunca (host little-endian)
                    return _bswap(a, imm / 8);
                }
                revert InvalidInstruction(ip, opc);
            }
        }
    }

    function _bswap(uint256 v, uint256 nbytes) private pure returns (uint256 out) {
        unchecked {
            for (uint256 i = 0; i < nbytes; i++) {
                out = (out << 8) | ((v >> (8 * i)) & 0xff);
            }
        }
    }

    // ------------------------------------------------------------------ JMP / CALL / EXIT

    /// @return halted true quando o programa terminou (exit no frame 0)
    function _jmp(
        VM memory vm,
        uint256[11] memory r,
        uint256 ip,
        uint256 opc,
        uint256 dst,
        uint256 src,
        uint256 off,
        uint256 imm
    ) private pure returns (bool halted) {
        unchecked {
            if (opc == 0x05) {
                vm.ip = (ip + 1 + off) & U64;
                return false;
            }
            if (opc == 0x95) {
                if (vm.depth == 0) return true;
                vm.depth--;
                uint256 base = vm.depth * 5;
                r[6] = vm.frames[base];
                r[7] = vm.frames[base + 1];
                r[8] = vm.frames[base + 2];
                r[9] = vm.frames[base + 3];
                vm.ip = vm.frames[base + 4];
                r[10] -= FRAME_SIZE;
                return false;
            }
            if (opc == 0x85) {
                if (src == 0) {
                    _syscall(vm, r, ip, imm);
                    return false;
                }
                if (src != 1) revert InvalidInstruction(ip, opc);
                _pushFrame(vm, r, ip, (ip + 1 + _sext32(imm)) & U64);
                return false;
            }
            if (opc == 0x8d) {
                uint256 t = r[src];
                if (t < MM_PROGRAM || (t - MM_PROGRAM) % 8 != 0) revert InvalidCallTarget(ip, t);
                _pushFrame(vm, r, ip, (t - MM_PROGRAM) / 8);
                return false;
            }

            uint256 a = r[dst];
            uint256 b = (opc & 8 != 0) ? r[src] : _sext32(imm);
            uint256 op = opc & 0xf0;
            if (opc & 7 != 5 || op == 0x80 || op == 0x90) revert InvalidInstruction(ip, opc);
            bool taken;
            if (op == 0x10) taken = a == b;
            else if (op == 0x20) taken = a > b;
            else if (op == 0x30) taken = a >= b;
            else if (op == 0x40) taken = (a & b) != 0;
            else if (op == 0x50) taken = a != b;
            else if (op == 0x60) taken = int64(uint64(a)) > int64(uint64(b));
            else if (op == 0x70) taken = int64(uint64(a)) >= int64(uint64(b));
            else if (op == 0xa0) taken = a < b;
            else if (op == 0xb0) taken = a <= b;
            else if (op == 0xc0) taken = int64(uint64(a)) < int64(uint64(b));
            else if (op == 0xd0) taken = int64(uint64(a)) <= int64(uint64(b));
            else revert InvalidInstruction(ip, opc);
            if (taken) vm.ip = (ip + 1 + off) & U64;
            return false;
        }
    }

    function _pushFrame(VM memory vm, uint256[11] memory r, uint256 ip, uint256 target) private pure {
        if (vm.depth + 1 >= MAX_DEPTH) revert CallDepthExceeded(ip);
        if (target >= vm.prog.length / 8) revert InvalidCallTarget(ip, target);
        uint256 base = vm.depth * 5;
        vm.frames[base] = r[6];
        vm.frames[base + 1] = r[7];
        vm.frames[base + 2] = r[8];
        vm.frames[base + 3] = r[9];
        vm.frames[base + 4] = vm.ip;
        vm.depth++;
        r[10] += FRAME_SIZE;
        vm.ip = target;
    }

    // ------------------------------------------------------------------ syscalls

    function _charge(VM memory vm, uint256 cu) private pure {
        unchecked {
            vm.steps += cu;
            if (vm.steps > vm.budget) revert ComputeBudgetExceeded(vm.budget);
        }
    }

    function _pushLog(VM memory vm, Log memory l) private pure {
        if (vm.nlogs < MAX_LOGS) {
            vm.logs[vm.nlogs] = l;
            vm.nlogs++;
        }
    }

    function _syscall(VM memory vm, uint256[11] memory r, uint256 ip, uint256 h) private pure {
        _charge(vm, SYSCALL_COST);
        if (h == SYS_LOG) {
            Log memory l;
            l.data = _readBytes(vm, ip, r[1], r[2]);
            _pushLog(vm, l);
        } else if (h == SYS_LOG64) {
            Log memory l;
            l.kind = 1;
            l.values = [uint64(r[1]), uint64(r[2]), uint64(r[3]), uint64(r[4]), uint64(r[5])];
            _pushLog(vm, l);
        } else if (h == SYS_LOG_CU) {
            Log memory l;
            l.kind = 2;
            l.values[0] = uint64(vm.budget - vm.steps);
            _pushLog(vm, l);
        } else if (h == SYS_KECCAK) {
            // r1 = ponteiro p/ array de slices {u64 ptr, u64 len}, r2 = nº de slices, r3 = saída (32 bytes)
            // keccak256 nativo da EVM: a ponte "precompile" Solana -> EVM
            (bytes memory sm, uint256 so) = _region(vm, ip, r[1], r[2] * 16, false);
            bytes memory buf;
            for (uint256 i = 0; i < r[2]; i++) {
                uint256 p = _load(sm, so + i * 16, 8);
                uint256 len = _load(sm, so + i * 16 + 8, 8);
                _charge(vm, len / 2);
                buf = bytes.concat(buf, _readBytes(vm, ip, p, len));
            }
            (bytes memory om, uint256 oo) = _region(vm, ip, r[3], 32, true);
            bytes32 hsh = keccak256(buf);
            assembly {
                mstore(add(add(om, 32), oo), hsh)
            }
        } else if (h == SYS_MEMCPY || h == SYS_MEMMOVE) {
            _charge(vm, r[3] / 250);
            (bytes memory sm, uint256 so) = _region(vm, ip, r[2], r[3], false);
            (bytes memory dm, uint256 dOff) = _region(vm, ip, r[1], r[3], true);
            uint256 len = r[3];
            assembly {
                mcopy(add(add(dm, 32), dOff), add(add(sm, 32), so), len)
            }
        } else if (h == SYS_MEMSET) {
            _charge(vm, r[3] / 250);
            (bytes memory dm, uint256 dOff) = _region(vm, ip, r[1], r[3], true);
            bytes1 c = bytes1(uint8(r[2]));
            for (uint256 i = 0; i < r[3]; i++) dm[dOff + i] = c;
        } else if (h == SYS_MEMCMP) {
            // r1 = a, r2 = b, r3 = n, r4 = ponteiro p/ i32 resultado
            _charge(vm, r[3] / 250);
            (bytes memory am, uint256 ao) = _region(vm, ip, r[1], r[3], false);
            (bytes memory bm, uint256 bo) = _region(vm, ip, r[2], r[3], false);
            uint256 res;
            for (uint256 i = 0; i < r[3]; i++) {
                uint8 x = uint8(am[ao + i]);
                uint8 y = uint8(bm[bo + i]);
                if (x != y) {
                    res = uint256(uint32(int32(int256(uint256(x)) - int256(uint256(y)))));
                    break;
                }
            }
            (bytes memory rm, uint256 ro) = _region(vm, ip, r[4], 4, true);
            _store(rm, ro, 4, res);
        } else if (h == SYS_ABORT) {
            revert ProgramAborted(ip);
        } else if (h == SYS_PANIC) {
            revert ProgramPanicked(ip, _readBytes(vm, ip, r[1], r[2]), uint64(r[3]), uint64(r[4]));
        } else {
            revert UnknownSyscall(ip, h);
        }
        r[0] = 0;
    }

    // ------------------------------------------------------------------ memória

    function _size(uint256 ip, uint256 opc, uint256 base) private pure returns (uint256) {
        if (opc == base) return 4; // W
        if (opc == base + 0x08) return 2; // H
        if (opc == base + 0x10) return 1; // B
        if (opc == base + 0x18) return 8; // DW
        revert InvalidInstruction(ip, opc);
    }

    function _region(VM memory vm, uint256 ip, uint256 vaddr, uint256 len, bool write)
        private
        pure
        returns (bytes memory m, uint256 o)
    {
        uint256 reg = vaddr >> 32;
        o = vaddr & U32;
        if (reg == 1 && !write) m = vm.prog;
        else if (reg == 2) m = vm.stack;
        else if (reg == 3) m = vm.heap;
        else if (reg == 4) m = vm.input;
        else revert AccessViolation(ip, vaddr, len, write);
        if (len > U32 || o + len > m.length) revert AccessViolation(ip, vaddr, len, write);
    }

    function _readBytes(VM memory vm, uint256 ip, uint256 vaddr, uint256 len) private pure returns (bytes memory out) {
        (bytes memory m, uint256 o) = _region(vm, ip, vaddr, len, false);
        out = new bytes(len);
        assembly {
            mcopy(add(out, 32), add(add(m, 32), o), len)
        }
    }

    /// @dev lê `n` bytes little-endian
    function _load(bytes memory m, uint256 o, uint256 n) private pure returns (uint256 v) {
        assembly {
            let w := mload(add(add(m, 32), o))
            for { let i := 0 } lt(i, n) { i := add(i, 1) } { v := or(v, shl(mul(i, 8), byte(i, w))) }
        }
    }

    /// @dev escreve `n` bytes little-endian
    function _store(bytes memory m, uint256 o, uint256 n, uint256 v) private pure {
        assembly {
            let p := add(add(m, 32), o)
            for { let i := 0 } lt(i, n) { i := add(i, 1) } { mstore8(add(p, i), and(shr(mul(i, 8), v), 0xff)) }
        }
    }

    function _sext32(uint256 x) private pure returns (uint256) {
        return (x & 0x80000000 != 0) ? (x | 0xffffffff00000000) : x;
    }
}
