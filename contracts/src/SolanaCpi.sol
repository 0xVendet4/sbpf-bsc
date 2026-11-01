// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SolanaVM} from "./SolanaVM.sol";

/// @title SolanaCpi — `sol_invoke_signed_{rust,c}` do agave 4.3 (program-runtime/src/cpi.rs)
/// @notice A VM suspende-se na syscall e devolve a memória (regiões) e os registos; este contrato
///         traduz a instrução, as contas e os signatários a partir dessa memória, aplica as regras
///         de privilégios, executa o programa chamado e escreve o resultado de volta na memória,
///         que o `SolanaRuntime` devolve à VM com `resumeElfVerified`.
///
/// @dev Features do agave consideradas: syscall_parameter_address_restrictions,
///      virtual_address_space_adjustments, account_data_direct_mapping. Só o system program
///      (builtin) pode ser chamado por enquanto: CreateAccount, Assign, Transfer e Allocate
///      (system_processor.rs). Programas sBPF chamados por CPI ainda não são suportados
///      (E_CPI subcódigo 10). Os códigos de status/erro são os do `SolanaVM`.
contract SolanaCpi {
    /// @notice Conta da instrução do chamador (uma por chave; repetidas usam a primeira).
    struct Acc {
        bytes32 key;
        bytes32 owner; // estado "da transação" (muda com a CPI)
        uint64 lamports;
        uint64 len;
        uint64 preLen; // tamanho ao serializar
        uint64 metaAddr; // endereço virtual do marcador 0xff do registro da conta
        uint32 dataRegion; // índice da região dos dados em `regions`
        uint8 flags; // bit0 signer, bit1 writable, bit2 executable
    }

    struct Input {
        bool rust;
        bytes32 programId; // programa chamador
        uint64 maxCu;
        uint64 cu; // consumidas até à syscall
        uint64[5] args; // r1..r5
        Acc[] accounts;
        SolanaVM.Region[] regions; // 0 rodata, 1 pilha, 2 heap, 3.. input; ordem crescente de endereço
    }

    struct Output {
        uint8 status; // SolanaVM.Status (0 = a CPI deu certo)
        uint64 err;
        uint256 fault; // como em SolanaVM.Result.fault
        uint64 cu;
        bytes logs; // entradas no formato do log da VM (tipos 4, 5 e 6)
        bool returnDataCleared; // o programa chamado começou (set_return_data(program_id, []))
        Acc[] accounts;
        SolanaVM.Region[] regions;
    }

    // status do SolanaVM
    uint256 private constant ST_ACCESS_VIOLATION = 3;
    uint256 private constant ST_CU_EXCEEDED = 4;
    uint256 private constant ST_SYSCALL_ERROR = 7;
    uint64 private constant E_COPY_OVERLAPPING = 4;
    uint64 private constant E_UNALIGNED_POINTER = 7;
    uint64 private constant E_INVALID_LENGTH = 8;
    uint64 private constant E_INSTRUCTION = 13;
    uint64 private constant E_CPI = 14;

    uint64 private constant STACK_START = 0x200000000;
    uint64 private constant INPUT_START = 0x400000000;
    uint256 private constant MASK64 = 0xffffffffffffffff;

    bytes32 private constant NATIVE_LOADER = 0x058784bf148ba4282fb012574888a9f153a07dadf765c0455c9a970380000000;
    uint256 private constant INVOKE_UNITS = 946; // DEFAULT_INVOCATION_COST
    uint256 private constant SYSTEM_PROGRAM_UNITS = 150;
    uint256 private constant CPI_BYTES_PER_UNIT = 250;
    uint256 private constant MAX_CPI_ACCOUNTS = 255;
    uint256 private constant MAX_CPI_DATA_LEN = 10 * 1024;
    uint256 private constant MAX_SIGNERS = 16;
    uint256 private constant MAX_SEEDS = 16;
    uint256 private constant MAX_SEED_LEN = 32;
    uint256 private constant MAX_PERMITTED_DATA_INCREASE = 10240;
    uint256 private constant MAX_ACCOUNT_DATA_LEN = 10 * 1024 * 1024;
    uint256 private constant MAX_ACCOUNT_DATA_GROWTH = 2 * MAX_ACCOUNT_DATA_LEN;
    uint256 private constant ED_P = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
    uint256 private constant ED_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555;

    // índices do InstructionError (ordem do enum do agave)
    uint256 private constant IE_INVALID_ARGUMENT = 1;
    uint256 private constant IE_INVALID_INSTRUCTION_DATA = 2;
    uint256 private constant IE_MISSING_REQUIRED_SIGNATURE = 7;
    uint256 private constant IE_MODIFIED_PROGRAM_ID = 11;
    uint256 private constant IE_EXTERNAL_LAMPORT_SPEND = 12;
    uint256 private constant IE_EXTERNAL_DATA_MODIFIED = 13;
    uint256 private constant IE_READONLY_LAMPORT_CHANGE = 14;
    uint256 private constant IE_READONLY_DATA_MODIFIED = 15;
    uint256 private constant IE_NOT_ENOUGH_ACCOUNT_KEYS = 19;
    uint256 private constant IE_CUSTOM = 25;
    uint256 private constant IE_UNSUPPORTED_PROGRAM_ID = 30;
    uint256 private constant IE_MISSING_ACCOUNT = 32;
    uint256 private constant IE_MAX_SEED_LENGTH_EXCEEDED = 34;
    uint256 private constant IE_INVALID_REALLOC = 36;
    uint256 private constant IE_COMPUTATIONAL_BUDGET_EXCEEDED = 37;
    uint256 private constant IE_PRIVILEGE_ESCALATION = 38;
    uint256 private constant IE_ARITHMETIC_OVERFLOW = 47;
    uint256 private constant IE_MAX_ACCOUNTS_DATA_ALLOCATIONS_EXCEEDED = 50;

    // tipos de entrada de log: 4 mensagem com chave [template:1][key:32], 5 falha do programa
    // chamado [ie:4][custom:4], 6 texto cru (sem "Program log: ")
    uint256 private constant LOG_KEYMSG = 4;
    uint256 private constant LOG_INNER_FAIL = 5;
    uint256 private constant LOG_RAW = 6;

    /// @dev Estado da syscall em curso.
    struct Ctx {
        bool rust;
        bytes32 programId;
        uint256 cu;
        uint256 maxCu;
        uint256 fault;
        int256 resizeDelta;
        bool returnDataCleared;
        bytes logs;
        Acc[] accounts;
        SolanaVM.Region[] regions;
    }

    /// @dev Instrução chamada.
    struct Cpi {
        bytes32 program;
        uint256 n; // número de metas
        bytes metas; // AccountMeta (34 bytes) ou SolAccountMeta (16 bytes) por meta
        bytes data;
        bytes32[] keys;
        uint256[] flags; // bit0 signer, bit1 writable (fundidos entre ocorrências da mesma chave)
        uint256[] caller; // índice em accounts
        uint256[] first; // índice da primeira meta com a mesma chave
        uint256[] lenAddr; // endereço vm do campo len do AccountInfo (0 = não traduzida)
        uint256[] sync; // bit0 atualizar lamports/owner/len no chamador; bit1 atualizar a região
        bytes32[] signers; // PDAs que assinam
        bytes infos; // array de AccountInfo
        uint256 infosAddr;
    }

    /// @notice Executa a CPI pendente de uma VM suspensa.
    function invoke(Input calldata in_) external view returns (Output memory o) {
        Ctx memory x;
        x.rust = in_.rust;
        x.programId = in_.programId;
        x.cu = in_.cu;
        x.maxCu = in_.maxCu;
        x.accounts = in_.accounts;
        x.regions = in_.regions;
        (uint256 st, uint64 err) = _invoke(x, in_.args);
        o.status = uint8(st);
        o.err = err;
        o.fault = x.fault;
        o.cu = uint64(x.cu);
        o.logs = x.logs;
        o.returnDataCleared = x.returnDataCleared;
        o.accounts = x.accounts;
        o.regions = x.regions;
    }

    function _invoke(Ctx memory x, uint64[5] calldata a) private view returns (uint256 st, uint64 err) {
        if (!_consume(x, INVOKE_UNITS)) return (ST_CU_EXCEEDED, 0);
        Cpi memory c;
        (st, err) = _cpiHeader(x, c, a[0]);
        if (st != 0) return (st, err);
        (st, err) = _cpiMetas(x, c);
        if (st != 0) return (st, err);
        (st, err) = _cpiSigners(x, c, a[3], a[4]);
        if (st != 0) return (st, err);
        if (c.program != bytes32(0)) return _cpiErr(10, 0); // só o system program por enquanto
        (st, err) = _cpiPrepare(x, c);
        if (st != 0) return (st, err);
        (st, err) = _cpiAccounts(x, c, a[1], a[2]);
        if (st != 0) return (st, err);
        (st, err) = _cpiSystem(x, c);
        if (st != 0) return (st, err);
        return _cpiFinish(x, c);
    }

    // ------------------------------------------------------------------ memória da VM

    /// @dev `_map` do SolanaVM sobre as regiões em memória: devolve o índice da região + 1 e o
    ///      offset, ou 0 (e guarda o fault). Regiões esparsas (pilha/heap) crescem ao tocar;
    ///      regiões de input graváveis esticam até `reserved` numa escrita além do fim.
    function _map(Ctx memory x, uint256 vaddr, uint256 len, bool write) private pure returns (uint256 ri, uint256 off) {
        SolanaVM.Region[] memory rg = x.regions;
        uint256 lo;
        uint256 hi = rg.length;
        while (lo < hi) {
            uint256 mid = (lo + hi) >> 1;
            if (rg[mid].vaddr > vaddr) hi = mid;
            else lo = mid + 1;
        }
        if (lo != 0) {
            SolanaVM.Region memory e = rg[lo - 1];
            off = vaddr - e.vaddr;
            uint256 end = off + len;
            bool sparse = lo == 2 || lo == 3;
            bool ok = !write || e.writable;
            if (ok && end > (sparse ? e.reserved : e.data.length)) {
                if (write && !sparse && end <= e.reserved) e.data = _resize(e.data, e.reserved);
                else ok = false;
            }
            if (ok) {
                if (sparse && end > e.data.length) e.data = _resize(e.data, end);
                ri = lo;
            }
        }
        // bit 129: falha dentro de uma syscall (o agave não esgota o medidor nesse caso)
        if (ri == 0) x.fault = vaddr | (len << 64) | ((write ? 1 : 0) << 128) | (1 << 129);
    }

    /// @dev `translate_slice`: devolve uma cópia de `len` bytes em `vaddr`.
    function _rd(Ctx memory x, uint256 vaddr, uint256 len, uint256 align, bool write) private pure returns (uint256 st, uint64 err, bytes memory out) {
        if (len == 0) return (0, 0, out);
        if (len > 0x7fffffffffffffff) return (ST_SYSCALL_ERROR, E_INVALID_LENGTH, out);
        (uint256 ri, uint256 off) = _map(x, vaddr, len, write);
        if (ri == 0) return (ST_ACCESS_VIOLATION, 0, out);
        if (vaddr % align != 0) return (ST_SYSCALL_ERROR, E_UNALIGNED_POINTER, out);
        out = new bytes(len);
        bytes memory src = x.regions[ri - 1].data;
        assembly ("memory-safe") {
            mcopy(add(out, 32), add(add(src, 32), off), len)
        }
    }

    /// @dev Escreve `val` em `vaddr` (a região tem de ser gravável).
    function _wr(Ctx memory x, uint256 vaddr, bytes memory val) private pure returns (bool ok) {
        (uint256 ri, uint256 off) = _map(x, vaddr, val.length, true);
        if (ri == 0) return false;
        bytes memory dst = x.regions[ri - 1].data;
        assembly ("memory-safe") {
            mcopy(add(add(dst, 32), off), add(val, 32), mload(val))
        }
        return true;
    }

    function _u64(bytes memory b, uint256 off) private pure returns (uint256 v) {
        for (uint256 i = 0; i < 8; i++) v |= uint256(uint8(b[off + i])) << (8 * i);
    }

    function _u32(bytes memory b, uint256 off) private pure returns (uint256 v) {
        for (uint256 i = 0; i < 4; i++) v |= uint256(uint8(b[off + i])) << (8 * i);
    }

    function _b32(bytes memory b, uint256 off) private pure returns (bytes32 v) {
        assembly ("memory-safe") {
            v := mload(add(add(b, 32), off))
        }
    }

    function _le(uint256 v) private pure returns (bytes memory out) {
        out = new bytes(8);
        for (uint256 i = 0; i < 8; i++) out[i] = bytes1(uint8(v >> (8 * i)));
    }

    /// @dev Bytes com o novo tamanho (zeros além do que havia).
    function _resize(bytes memory b, uint256 len) private pure returns (bytes memory out) {
        if (b.length == len) return b;
        out = new bytes(len);
        uint256 n = len < b.length ? len : b.length;
        assembly ("memory-safe") {
            mcopy(add(out, 32), add(b, 32), n)
        }
    }

    // ------------------------------------------------------------------ medidor, erros e log

    function _consume(Ctx memory x, uint256 amount) private pure returns (bool ok) {
        if (amount > x.maxCu - x.cu) {
            x.cu = x.maxCu;
            return false;
        }
        x.cu += amount;
        return true;
    }

    function _ie(uint256 index, uint256 custom) private pure returns (uint256 st, uint64 err) {
        return (ST_SYSCALL_ERROR, uint64(uint256(E_INSTRUCTION) | (index << 8) | (custom << 32)));
    }

    function _cpiErr(uint256 sub, uint256 n) private pure returns (uint256 st, uint64 err) {
        return (ST_SYSCALL_ERROR, uint64(uint256(E_CPI) | (sub << 8) | ((n & 0xffffffff) << 32)));
    }

    function _log(Ctx memory x, uint256 kind, bytes memory payload) private pure {
        x.logs = bytes.concat(x.logs, bytes1(uint8(kind)), bytes4(uint32(payload.length)), payload);
    }

    function _logKey(Ctx memory x, uint8 template, bytes32 key) private pure {
        _log(x, LOG_KEYMSG, bytes.concat(bytes1(template), key));
    }

    function _findAccount(Ctx memory x, bytes32 key) private pure returns (bool found, uint256 idx) {
        for (uint256 i = 0; i < x.accounts.length; i++) {
            if (x.accounts[i].key == key) return (true, i);
        }
    }

    // ------------------------------------------------------------------ tradução da instrução

    /// @dev translate_instruction_{rust,c}: cabeçalho (programa, metas, dados).
    function _cpiHeader(Ctx memory x, Cpi memory c, uint256 addr) private pure returns (uint256 st, uint64 err) {
        bytes memory ix;
        uint256 metasAddr;
        uint256 dataAddr;
        uint256 dlen;
        if (x.rust) {
            // StableInstruction { accounts: StableVec (addr, cap, len), data: StableVec, program_id }
            (st, err, ix) = _rd(x, addr, 80, 8, false);
            if (st != 0) return (st, err);
            metasAddr = _u64(ix, 0);
            c.n = _u64(ix, 16);
            dataAddr = _u64(ix, 24);
            dlen = _u64(ix, 40);
            c.program = _b32(ix, 48);
        } else {
            // SolInstruction { program_id_addr, accounts_addr, accounts_len, data_addr, data_len }
            (st, err, ix) = _rd(x, addr, 40, 8, false);
            if (st != 0) return (st, err);
            bytes memory pid;
            (st, err, pid) = _rd(x, _u64(ix, 0), 32, 1, false);
            if (st != 0) return (st, err);
            c.program = _b32(pid, 0);
            metasAddr = _u64(ix, 8);
            c.n = _u64(ix, 16);
            dataAddr = _u64(ix, 24);
            dlen = _u64(ix, 32);
        }
        (st, err, c.metas) = _rd(x, metasAddr, c.n * (x.rust ? 34 : 16), x.rust ? 1 : 8, false);
        if (st != 0) return (st, err);
        (st, err, c.data) = _rd(x, dataAddr, dlen, 1, false);
        if (st != 0) return (st, err);
        if (c.n > MAX_CPI_ACCOUNTS) return _cpiErr(6, c.n);
        if (dlen > MAX_CPI_DATA_LEN) return _cpiErr(7, dlen);
        if (!_consume(x, dlen / CPI_BYTES_PER_UNIT + (c.n * 34) / CPI_BYTES_PER_UNIT)) return (ST_CU_EXCEEDED, 0);
    }

    function _cpiMetas(Ctx memory x, Cpi memory c) private pure returns (uint256 st, uint64 err) {
        uint256 n = c.n;
        c.keys = new bytes32[](n);
        c.flags = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            uint256 sg;
            uint256 wr;
            if (x.rust) {
                uint256 e = i * 34; // AccountMeta { pubkey, is_signer, is_writable }
                sg = uint8(c.metas[e + 32]);
                wr = uint8(c.metas[e + 33]);
                if (sg > 1 || wr > 1) return _ie(IE_INVALID_ARGUMENT, 0);
                c.keys[i] = _b32(c.metas, e);
            } else {
                uint256 e = i * 16; // SolAccountMeta { pubkey_addr, is_writable, is_signer }
                wr = uint8(c.metas[e + 8]);
                sg = uint8(c.metas[e + 9]);
                if (sg > 1 || wr > 1) return _ie(IE_INVALID_ARGUMENT, 0);
                bytes memory k;
                (st, err, k) = _rd(x, _u64(c.metas, e), 32, 1, false);
                if (st != 0) return (st, err);
                c.keys[i] = _b32(k, 0);
            }
            c.flags[i] = sg | (wr << 1);
        }
    }

    /// @dev translate_signers: cada conjunto de seeds vira um PDA do programa chamador.
    function _cpiSigners(Ctx memory x, Cpi memory c, uint256 addr, uint256 n) private view returns (uint256 st, uint64 err) {
        if (n == 0) return (0, 0);
        bytes memory outer;
        (st, err, outer) = _rd(x, addr, n * 16, 8, false);
        if (st != 0) return (st, err);
        if (n > MAX_SIGNERS) return _cpiErr(2, 0);
        c.signers = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            uint256 sn = _u64(outer, i * 16 + 8);
            bytes memory vals;
            (st, err, vals) = _rd(x, _u64(outer, i * 16), sn * 16, 8, false);
            if (st != 0) return (st, err);
            if (sn > MAX_SEEDS) return _ie(IE_MAX_SEED_LENGTH_EXCEEDED, 0);
            bytes memory seeds;
            bool tooLong;
            (st, err, seeds, tooLong) = _seedBytes(x, vals, sn);
            if (st != 0) return (st, err);
            if (tooLong) return _cpiErr(3, 0); // create_program_address: seed > 32 bytes
            (bool ok, bytes32 h) = _pda(seeds, x.programId);
            if (!ok) return _cpiErr(4, 0);
            c.signers[i] = h;
        }
    }

    /// @dev Traduz `n` VmSlices (ptr, len) e devolve as fatias concatenadas.
    function _seedBytes(Ctx memory x, bytes memory vals, uint256 n) private pure returns (uint256 st, uint64 err, bytes memory out, bool tooLong) {
        for (uint256 i = 0; i < n; i++) {
            uint256 fl = _u64(vals, i * 16 + 8);
            bytes memory part;
            (st, err, part) = _rd(x, _u64(vals, i * 16), fl, 1, false);
            if (st != 0) return (st, err, out, false);
            if (fl > MAX_SEED_LEN) tooLong = true;
            out = bytes.concat(out, part);
        }
    }

    function _isSigner(Cpi memory c, bytes32 key) private pure returns (bool) {
        for (uint256 i = 0; i < c.signers.length; i++) {
            if (c.signers[i] == key) return true;
        }
        return false;
    }

    /// @dev prepare_next_cpi_instruction: contas da instrução chamada, privilégios e programa.
    function _cpiPrepare(Ctx memory x, Cpi memory c) private pure returns (uint256 st, uint64 err) {
        uint256 n = c.keys.length;
        c.caller = new uint256[](n);
        c.first = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            (bool found, uint256 idx) = _findAccount(x, c.keys[i]);
            if (!found) {
                _logKey(x, 1, c.keys[i]);
                return _ie(IE_MISSING_ACCOUNT, 0);
            }
            c.caller[i] = idx;
            uint256 f = i;
            for (uint256 j = 0; j < i; j++) {
                if (c.keys[j] == c.keys[i]) {
                    f = j;
                    break;
                }
            }
            c.first[i] = f;
            if (f != i) c.flags[f] |= c.flags[i];
        }
        for (uint256 i = 0; i < n; i++) {
            if (c.first[i] != i) {
                c.flags[i] = c.flags[c.first[i]]; // repetida: herda os privilégios fundidos
                continue;
            }
            uint256 cf = x.accounts[c.caller[i]].flags;
            if (c.flags[i] & 2 != 0 && cf & 2 == 0) {
                _logKey(x, 2, c.keys[i]);
                return _ie(IE_PRIVILEGE_ESCALATION, 0);
            }
            if (c.flags[i] & 1 != 0 && cf & 1 == 0 && !_isSigner(c, c.keys[i])) {
                _logKey(x, 3, c.keys[i]);
                return _ie(IE_PRIVILEGE_ESCALATION, 0);
            }
        }
        (bool pf, ) = _findAccount(x, c.program);
        if (!pf) {
            _logKey(x, 4, c.program);
            return _ie(IE_MISSING_ACCOUNT, 0);
        }
    }

    // ------------------------------------------------------------------ tradução das contas

    /// @dev translate_account_infos: valida o array de AccountInfo e recolhe as chaves.
    function _cpiInfos(Ctx memory x, Cpi memory c, uint256 infosAddr, uint256 infosLen) private pure returns (uint256 st, uint64 err, bytes32[] memory infoKeys) {
        uint256 size = x.rust ? 48 : 56;
        if (infosAddr + infosLen * size >= INPUT_START) {
            (st, err) = _cpiErr(1, 0);
            return (st, err, infoKeys);
        }
        (st, err, c.infos) = _rd(x, infosAddr, infosLen * size, 8, false);
        if (st != 0) return (st, err, infoKeys);
        if (infosLen > MAX_CPI_ACCOUNTS) {
            (st, err) = _cpiErr(8, infosLen);
            return (st, err, infoKeys);
        }
        if (!_consume(x, (infosLen * 80) / CPI_BYTES_PER_UNIT)) return (ST_CU_EXCEEDED, 0, infoKeys);
        c.infosAddr = infosAddr;
        infoKeys = new bytes32[](infosLen);
        for (uint256 j = 0; j < infosLen; j++) {
            bytes memory k;
            (st, err, k) = _rd(x, _u64(c.infos, j * size), 32, 1, false);
            if (st != 0) return (st, err, infoKeys);
            infoKeys[j] = _b32(k, 0);
        }
    }

    /// @dev translate_accounts + update_callee_account
    function _cpiAccounts(Ctx memory x, Cpi memory c, uint256 infosAddr, uint256 infosLen) private pure returns (uint256 st, uint64 err) {
        bytes32[] memory infoKeys;
        (st, err, infoKeys) = _cpiInfos(x, c, infosAddr, infosLen);
        if (st != 0) return (st, err);
        uint256 n = c.keys.length;
        c.lenAddr = new uint256[](n);
        c.sync = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            if (c.first[i] != i) continue;
            Acc memory a = x.accounts[c.caller[i]];
            if (a.flags & 4 != 0) {
                // executável: conta conhecida, só cobra os bytes
                if (!_consume(x, uint256(a.len) / CPI_BYTES_PER_UNIT)) return (ST_CU_EXCEEDED, 0);
                continue;
            }
            uint256 j;
            while (j < infoKeys.length && infoKeys[j] != c.keys[i]) j++;
            if (j == infoKeys.length) {
                _logKey(x, 1, c.keys[i]);
                return _ie(IE_MISSING_ACCOUNT, 0);
            }
            (st, err) = _cpiTranslate(x, c, i, a, j);
            if (st != 0) return (st, err);
        }
        for (uint256 i = 0; i < n; i++) {
            if (c.first[i] != i || c.lenAddr[i] == 0) continue;
            bool must;
            (st, err, must) = _cpiSyncIn(x, c, i);
            if (st != 0) return (st, err);
            bool w = c.flags[i] & 2 != 0;
            c.sync[i] = (w ? 1 : 0) | ((w || must) ? 2 : 0);
        }
    }

    /// @dev Confere que `len` bytes em `vaddr` são mapeáveis (e graváveis, se `write`).
    function _chk(Ctx memory x, uint256 vaddr, uint256 len, uint256 align, bool write) private pure returns (uint256 st, uint64 err) {
        (st, err, ) = _rd(x, vaddr, len, align, write);
    }

    /// @dev CallerAccount::from_(sol_)account_info: confere os ponteiros do AccountInfo contra a
    ///      serialização e guarda onde está o campo len.
    function _cpiTranslate(Ctx memory x, Cpi memory c, uint256 i, Acc memory a, uint256 j) private pure returns (uint256 st, uint64 err) {
        uint256 m = a.metaAddr;
        uint256 lenAddr;
        uint256 h = j * (x.rust ? 48 : 56); // offset do AccountInfo em c.infos
        if (x.rust) {
            // AccountInfo { key: &Pubkey, lamports: Rc<RefCell<&mut u64>>, data: Rc<RefCell<&mut [u8]>>, owner, .. }
            if (_u64(c.infos, h) != m + 8) return _cpiErr(1, 0);
            if (_u64(c.infos, h + 24) != m + 40) return _cpiErr(1, 0);
            uint256 cell = (_u64(c.infos, h + 8) + 24) & MASK64; // RefCell::as_ptr() dentro do RcBox
            bytes memory ph;
            (st, err, ph) = _rd(x, cell, 8, 8, false);
            if (st != 0) return (st, err);
            if (cell >= INPUT_START) return _cpiErr(1, 0);
            if (_u64(ph, 0) != m + 72) return _cpiErr(1, 0);
            (st, err) = _chk(x, m + 72, 8, 8, true);
            if (st != 0) return (st, err);
            (st, err) = _chk(x, m + 40, 32, 1, true);
            if (st != 0) return (st, err);
            uint256 dcell = (_u64(c.infos, h + 16) + 24) & MASK64;
            if (dcell >= INPUT_START) return _cpiErr(1, 0);
            (st, err, ph) = _rd(x, dcell, 16, 8, false);
            if (st != 0) return (st, err);
            if (_u64(ph, 0) != m + 88) return _cpiErr(1, 0);
            lenAddr = (dcell + 8) & MASK64;
            if (lenAddr >= INPUT_START) return _cpiErr(1, 0);
        } else {
            // SolAccountInfo { key_addr, lamports_addr, data_len, data_addr, owner_addr, rent_epoch, flags }
            if (_u64(c.infos, h) != m + 8 || _u64(c.infos, h + 32) != m + 40 || _u64(c.infos, h + 8) != m + 72 || _u64(c.infos, h + 24) != m + 88) {
                return _cpiErr(1, 0);
            }
            (st, err) = _chk(x, m + 72, 8, 8, true);
            if (st != 0) return (st, err);
            (st, err) = _chk(x, m + 40, 32, 1, true);
            if (st != 0) return (st, err);
            lenAddr = (c.infosAddr + h + 16) & MASK64;
            if (lenAddr >= INPUT_START) return _cpiErr(1, 0);
        }
        bytes memory lh;
        (st, err, lh) = _rd(x, lenAddr, 8, 1, true);
        if (st != 0) return (st, err);
        uint256 len = _u64(lh, 0);
        if (len > uint256(a.preLen) + MAX_PERMITTED_DATA_INCREASE) return _ie(IE_INVALID_REALLOC, 0);
        if (!_consume(x, len / CPI_BYTES_PER_UNIT)) return (ST_CU_EXCEEDED, 0);
        c.lenAddr[i] = lenAddr;
    }

    /// @dev update_callee_account: o que o chamador mudou na memória passa para a conta.
    function _cpiSyncIn(Ctx memory x, Cpi memory c, uint256 i) private pure returns (uint256 st, uint64 err, bool must) {
        uint256 idx = c.caller[i];
        Acc memory a = x.accounts[idx];
        bytes memory meta;
        (st, err, meta) = _rd(x, a.metaAddr, 88, 1, false);
        if (st != 0) return (st, err, false);
        bool owned = a.owner == x.programId;
        uint256 memLam = _u64(meta, 72);
        if (memLam != a.lamports) {
            (st, err) = _setLamports(a, owned, a.flags & 2 != 0, memLam);
            if (st != 0) return (st, err, false);
        }
        (st, err, must) = _syncLen(x, c.lenAddr[i], idx, owned);
        if (st != 0) return (st, err, false);
        bytes32 memOwner = _b32(meta, 40);
        if (memOwner != a.owner) {
            (st, err) = _setOwner(x, idx, owned, a.flags & 2 != 0, memOwner);
            if (st != 0) return (st, err, false);
            must = true;
        }
    }

    /// @dev Tamanho: o len do AccountInfo contra o da conta (que, com direct mapping, acompanha a
    ///      região de dados, que cresce com stores além do fim).
    function _syncLen(Ctx memory x, uint256 lenAddr, uint256 idx, bool owned) private pure returns (uint256 st, uint64 err, bool changed) {
        Acc memory a = x.accounts[idx];
        uint256 rl = x.regions[a.dataRegion].data.length;
        if (rl > a.len) a.len = uint64(rl);
        bytes memory lh;
        (st, err, lh) = _rd(x, lenAddr, 8, 1, false);
        if (st != 0) return (st, err, false);
        uint256 post = _u64(lh, 0);
        if (post == a.len) return (0, 0, false);
        (st, err) = _setDataLength(x, idx, owned, a.flags & 2 != 0, post);
        return (st, err, st == 0);
    }

    // ------------------------------------------------------------------ regras do BorrowedInstructionAccount

    function _setLamports(Acc memory a, bool owned, bool writable, uint256 lamports) private pure returns (uint256 st, uint64 err) {
        if (!owned && lamports < a.lamports) return _ie(IE_EXTERNAL_LAMPORT_SPEND, 0);
        if (!writable) return _ie(IE_READONLY_LAMPORT_CHANGE, 0);
        a.lamports = uint64(lamports);
    }

    function _setOwner(Ctx memory x, uint256 idx, bool owned, bool writable, bytes32 owner) private pure returns (uint256 st, uint64 err) {
        if (!owned || !writable || !_zeroed(x, idx)) return _ie(IE_MODIFIED_PROGRAM_ID, 0);
        x.accounts[idx].owner = owner;
    }

    /// @dev `set_data_length`: muda o tamanho da conta; o que cresce fica a zero na região (direct mapping).
    function _setDataLength(Ctx memory x, uint256 idx, bool owned, bool writable, uint256 newLen) private pure returns (uint256 st, uint64 err) {
        Acc memory a = x.accounts[idx];
        uint256 old = a.len;
        // can_data_be_resized
        if (newLen > MAX_ACCOUNT_DATA_LEN) return _ie(IE_INVALID_REALLOC, 0);
        int256 delta = int256(newLen) - int256(old);
        if (x.resizeDelta + delta > int256(MAX_ACCOUNT_DATA_GROWTH)) return _ie(IE_MAX_ACCOUNTS_DATA_ALLOCATIONS_EXCEEDED, 0);
        // can_data_be_changed
        if (!writable) return _ie(IE_READONLY_DATA_MODIFIED, 0);
        if (!owned) return _ie(IE_EXTERNAL_DATA_MODIFIED, 0);
        if (newLen == old) return (0, 0);
        x.resizeDelta += delta;
        a.len = uint64(newLen);
        SolanaVM.Region memory e = x.regions[a.dataRegion];
        bytes memory d = e.data;
        // zera o que cresceu (resize(new, 0)) dentro do que a região já tem
        uint256 top = newLen < d.length ? newLen : d.length;
        if (top > old) {
            assembly ("memory-safe") {
                calldatacopy(add(add(d, 32), old), calldatasize(), sub(top, old))
            }
        }
        if (newLen <= e.reserved) e.data = _resize(d, newLen);
    }

    function _zeroed(Ctx memory x, uint256 idx) private pure returns (bool z) {
        Acc memory a = x.accounts[idx];
        bytes memory d = x.regions[a.dataRegion].data;
        uint256 len = a.len;
        if (len > d.length) len = d.length;
        z = true;
        assembly ("memory-safe") {
            let p := add(d, 32)
            for { let i := 0 } lt(i, len) { i := add(i, 32) } {
                let w := mload(add(p, i))
                let rest := sub(len, i)
                if lt(rest, 32) { w := and(w, not(shr(mul(8, rest), not(0)))) }
                if w { z := 0 }
            }
        }
    }

    // ------------------------------------------------------------------ PDA

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

    // ------------------------------------------------------------------ system program

    /// @dev process_instruction do system program: log de invoke, 150 CU, instrução, log de saída.
    function _cpiSystem(Ctx memory x, Cpi memory c) private pure returns (uint256 st, uint64 err) {
        (, uint256 pidx) = _findAccount(x, c.program);
        if (x.accounts[pidx].owner != NATIVE_LOADER) return _ie(IE_UNSUPPORTED_PROGRAM_ID, 0);
        _log(x, LOG_RAW, "Program 11111111111111111111111111111111 invoke [2]");
        x.returnDataCleared = true;
        (st, err) = _system(x, c);
        if (st == 0) {
            _log(x, LOG_RAW, "Program 11111111111111111111111111111111 success");
            return (0, 0);
        }
        if (st == ST_SYSCALL_ERROR && err & 0xff == E_INSTRUCTION) {
            _log(x, LOG_INNER_FAIL, bytes.concat(bytes4(uint32((err >> 8) & 0xffffff)), bytes4(uint32(err >> 32))));
        }
    }

    function _acc(Ctx memory x, Cpi memory c, uint256 k) private pure returns (Acc memory) {
        return x.accounts[c.caller[k]];
    }

    function _system(Ctx memory x, Cpi memory c) private pure returns (uint256 st, uint64 err) {
        if (!_consume(x, SYSTEM_PROGRAM_UNITS)) return _ie(IE_COMPUTATIONAL_BUDGET_EXCEEDED, 0);
        bytes memory d = c.data;
        if (d.length < 4) return _ie(IE_INVALID_INSTRUCTION_DATA, 0);
        uint256 tag = _u32(d, 0);
        if (tag == 0) {
            // CreateAccount { lamports, space, owner }
            if (d.length < 52) return _ie(IE_INVALID_INSTRUCTION_DATA, 0);
            if (c.keys.length < 2) return _ie(IE_NOT_ENOUGH_ACCOUNT_KEYS, 0);
            if (_acc(x, c, 1).lamports > 0) {
                _logKey(x, 6, c.keys[1]);
                return _ie(IE_CUSTOM, 0); // SystemError::AccountAlreadyInUse
            }
            (st, err) = _allocate(x, c, 1, _u64(d, 12));
            if (st != 0) return (st, err);
            (st, err) = _assign(x, c, 1, _b32(d, 20));
            if (st != 0) return (st, err);
            return _transfer(x, c, _u64(d, 4));
        }
        if (tag == 1) {
            // Assign { owner }
            if (d.length < 36) return _ie(IE_INVALID_INSTRUCTION_DATA, 0);
            if (c.keys.length < 1) return _ie(IE_NOT_ENOUGH_ACCOUNT_KEYS, 0);
            return _assign(x, c, 0, _b32(d, 4));
        }
        if (tag == 2) {
            // Transfer { lamports }
            if (d.length < 12) return _ie(IE_INVALID_INSTRUCTION_DATA, 0);
            if (c.keys.length < 2) return _ie(IE_NOT_ENOUGH_ACCOUNT_KEYS, 0);
            return _transfer(x, c, _u64(d, 4));
        }
        if (tag == 8) {
            // Allocate { space }
            if (d.length < 12) return _ie(IE_INVALID_INSTRUCTION_DATA, 0);
            if (c.keys.length < 1) return _ie(IE_NOT_ENOUGH_ACCOUNT_KEYS, 0);
            return _allocate(x, c, 0, _u64(d, 4));
        }
        if (tag <= 12) return _cpiErr(11, tag); // variante do system program ainda não suportada
        return _ie(IE_INVALID_INSTRUCTION_DATA, 0);
    }

    function _transfer(Ctx memory x, Cpi memory c, uint256 lamports) private pure returns (uint256 st, uint64 err) {
        if (c.flags[0] & 1 == 0) {
            _logKey(x, 5, c.keys[0]);
            return _ie(IE_MISSING_REQUIRED_SIGNATURE, 0);
        }
        Acc memory from = _acc(x, c, 0);
        if (from.len != 0) {
            _log(x, LOG_RAW, "Transfer: `from` must not carry data");
            return _ie(IE_INVALID_ARGUMENT, 0);
        }
        uint256 have = from.lamports;
        if (lamports > have) {
            _log(x, LOG_RAW, bytes.concat("Transfer: insufficient lamports ", _dec(have), ", need ", _dec(lamports)));
            return _ie(IE_CUSTOM, 1); // SystemError::ResultWithNegativeLamports
        }
        (st, err) = _setLamports(from, from.owner == bytes32(0), c.flags[0] & 2 != 0, have - lamports);
        if (st != 0) return (st, err);
        Acc memory to = _acc(x, c, 1);
        uint256 v = uint256(to.lamports) + lamports;
        if (v > MASK64) return _ie(IE_ARITHMETIC_OVERFLOW, 0);
        return _setLamports(to, to.owner == bytes32(0), c.flags[1] & 2 != 0, v);
    }

    function _allocate(Ctx memory x, Cpi memory c, uint256 k, uint256 space) private pure returns (uint256 st, uint64 err) {
        if (c.flags[k] & 1 == 0) {
            _logKey(x, 7, c.keys[k]);
            return _ie(IE_MISSING_REQUIRED_SIGNATURE, 0);
        }
        Acc memory a = _acc(x, c, k);
        if (a.len != 0 || a.owner != bytes32(0)) {
            _logKey(x, 8, c.keys[k]);
            return _ie(IE_CUSTOM, 0);
        }
        if (space > MAX_ACCOUNT_DATA_LEN) {
            _log(x, LOG_RAW, bytes.concat("Allocate: requested ", _dec(space), ", max allowed ", _dec(MAX_ACCOUNT_DATA_LEN)));
            return _ie(IE_CUSTOM, 3); // SystemError::InvalidAccountDataLength
        }
        return _setDataLength(x, c.caller[k], true, c.flags[k] & 2 != 0, space);
    }

    function _assign(Ctx memory x, Cpi memory c, uint256 k, bytes32 owner) private pure returns (uint256 st, uint64 err) {
        bytes32 cur = _acc(x, c, k).owner;
        if (cur == owner) return (0, 0);
        if (c.flags[k] & 1 == 0) {
            _logKey(x, 9, c.keys[k]);
            return _ie(IE_MISSING_REQUIRED_SIGNATURE, 0);
        }
        return _setOwner(x, c.caller[k], cur == bytes32(0), c.flags[k] & 2 != 0, owner);
    }

    // ------------------------------------------------------------------ resultado de volta à memória

    /// @dev update_caller_account + update_caller_account_region: o resultado volta para a memória.
    function _cpiFinish(Ctx memory x, Cpi memory c) private pure returns (uint256 st, uint64 err) {
        for (uint256 i = 0; i < c.keys.length; i++) {
            if (c.first[i] != i || c.lenAddr[i] == 0) continue;
            Acc memory a = x.accounts[c.caller[i]];
            uint256 post = a.len;
            if (c.sync[i] & 1 != 0) {
                if (!_wr(x, uint256(a.metaAddr) + 40, abi.encodePacked(a.owner))) return (ST_ACCESS_VIOLATION, 0);
                if (!_wr(x, uint256(a.metaAddr) + 72, _le(a.lamports))) return (ST_ACCESS_VIOLATION, 0);
                if (post > uint256(a.preLen) + MAX_PERMITTED_DATA_INCREASE) {
                    _log(x, LOG_RAW, "Account data size realloc limited to 10240 in inner instructions");
                    return _ie(IE_INVALID_REALLOC, 0);
                }
                bytes memory lh;
                (st, err, lh) = _rd(x, c.lenAddr[i], 8, 1, true);
                if (st != 0) return (st, err);
                if (_u64(lh, 0) != post) {
                    if (!_wr(x, c.lenAddr[i], _le(post))) return (ST_ACCESS_VIOLATION, 0);
                    if (!_wr(x, uint256(a.metaAddr) + 80, _le(post))) return (ST_ACCESS_VIOLATION, 0);
                }
            }
            if (c.sync[i] & 2 != 0) {
                SolanaVM.Region memory e = x.regions[a.dataRegion];
                if (post <= e.reserved) e.data = _resize(e.data, post);
                e.writable = a.flags & 2 != 0 && a.owner == x.programId;
            }
        }
    }

    function _dec(uint256 v) private pure returns (bytes memory b) {
        uint256 n = 1;
        for (uint256 t = v; t >= 10; t /= 10) n++;
        b = new bytes(n);
        for (uint256 i = 0; i < n; i++) {
            b[n - 1 - i] = bytes1(uint8(48 + v % 10));
            v /= 10;
        }
    }
}
