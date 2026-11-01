// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SolanaVM} from "./SolanaVM.sol";
import {SolanaCpi} from "./SolanaCpi.sol";
import {SolanaLog, IE} from "./SolanaLog.sol";

/// @title SolanaRuntime — a camada de contas do runtime Solana (loader v3 / ABIv1) em Solidity
/// @notice Recebe uma instrução como o agave recebe (programa, contas, metas, dados), serializa as
///         contas no formato que o programa espera (`serialize_parameters`, agave 4.3, com
///         direct mapping e ponteiros diretos), roda o programa no `SolanaVM` e aplica as regras
///         de desserialização (`deserialize_parameters`: lamports, realloc, owner, saldo) para
///         produzir o `InstructionError`, as contas finais e o log no formato do agave.
///
/// @dev Semântica: `solana-program-runtime` 4.3 (`serialization.rs`, `vm.rs`) e
///      `solana-transaction-context` 4.3 (`instruction_accounts.rs`). Conferida pelos fixtures do
///      Mollusk em `fixtures/solana/programs.json`. Uma CPI (`sol_invoke_signed_*`) suspende a VM;
///      o runtime executa a instrução chamada no `SolanaCpi` e retoma a VM. O texto do log é
///      montado pelo `SolanaLog`.
contract SolanaRuntime {
    SolanaVM public immutable vm;
    SolanaCpi public immutable cpi;
    SolanaLog public immutable log;

    struct Account {
        bytes32 key;
        bytes32 owner;
        uint64 lamports;
        bool executable;
        bytes data;
    }

    /// @notice Conta da instrução: índice em `Call.accounts` + privilégios.
    struct Meta {
        uint8 account;
        bool isSigner;
        bool isWritable;
    }

    struct Call {
        bytes32 programId;
        uint64 maxCu;
        Account[] accounts;
        Meta[] metas;
        bytes data;
        SolanaVM.Sysvar[] sysvars;
    }

    struct Outcome {
        uint32 err; // 0 = sucesso; senão uint32(InstructionError) + 1
        uint32 custom; // código de `Custom(n)`
        uint64 cu; // compute units cobradas (esgota em falhas da VM, como no agave)
        bytes returnData;
        string logs; // linhas no formato do agave, separadas por "\n"
        Account[] accounts; // estado final (igual ao inicial se falhou)
    }

    uint256 public constant MAX_PERMITTED_DATA_INCREASE = 10240;
    // códigos de erro de syscall do SolanaVM (SolanaVM.E_*)
    uint64 private constant E_ARITHMETIC_OVERFLOW = 10;
    uint64 private constant E_UNSUPPORTED_SYSVAR = 12;
    uint64 private constant E_INSTRUCTION = 13; // InstructionError vindo de uma syscall (CPI)
    uint256 public constant MAX_ACCOUNT_DATA_LEN = 10 * 1024 * 1024;
    uint256 public constant MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION = 2 * MAX_ACCOUNT_DATA_LEN;
    uint256 public constant MAX_ACCOUNTS_PER_INSTRUCTION = 255;
    uint64 private constant INPUT_START = 0x400000000;
    uint64 private constant STACK_START = 0x200000000;
    uint64 private constant HEAP_START = 0x300000000;
    uint64 private constant STACK_SIZE = 64 * 4096;
    uint64 private constant HEAP_SIZE = 32 * 1024;

    error BadMeta();

    constructor(SolanaVM vm_, SolanaCpi cpi_, SolanaLog log_) {
        vm = vm_;
        cpi = cpi_;
        log = log_;
    }

    // ------------------------------------------------------------------ serialização

    /// @dev Conta da instrução já posicionada na serialização.
    struct Slot {
        uint8 account; // índice em Call.accounts
        bool dup;
        uint8 dupOf; // índice do meta original (se dup)
        bool isSigner;
        bool isWritable;
        uint256 metaRegion; // região com o cabeçalho (marker, flags, key, owner, lamports, data_len)
        uint256 metaOff; // offset do marker dentro da região
        uint256 dataRegion; // região dos dados
        uint256 preLen;
        uint64 markerAddr; // endereço virtual do marker (entra na tabela de ponteiros)
    }

    struct Ser {
        SolanaVM.Region[] regions;
        Slot[] slots;
        uint64 ixDataAddr;
    }

    /// @notice Serializa as contas da instrução (`serialize_parameters_for_abiv1` do agave com
    ///         `virtual_address_space_adjustments`, `account_data_direct_mapping` e
    ///         `direct_account_pointers_in_program_input`).
    function serialize(Call calldata c) public pure returns (Ser memory s) {
        uint256 n = c.metas.length;
        if (n > MAX_ACCOUNTS_PER_INSTRUCTION) revert BadMeta();
        s.slots = new Slot[](n);
        uint256 nonDup;
        for (uint256 i = 0; i < n; i++) {
            if (c.metas[i].account >= c.accounts.length) revert BadMeta();
            bool dup;
            for (uint256 j = 0; j < i; j++) {
                if (c.metas[j].account == c.metas[i].account) {
                    dup = true;
                    s.slots[i].dup = true;
                    s.slots[i].dupOf = uint8(j);
                    break;
                }
            }
            if (!dup) nonDup++;
            s.slots[i].account = c.metas[i].account;
            s.slots[i].isSigner = c.metas[i].isSigner;
            s.slots[i].isWritable = c.metas[i].isWritable;
        }
        s.regions = new SolanaVM.Region[](1 + 2 * nonDup);
        uint256 ri; // próxima região
        uint64 vaddr = INPUT_START; // começo da região em construção
        bytes memory cur = abi.encodePacked(_le(uint64(n)));
        for (uint256 i = 0; i < n; i++) {
            Slot memory sl = s.slots[i];
            sl.markerAddr = vaddr + uint64(cur.length);
            if (sl.dup) {
                cur = bytes.concat(cur, bytes1(sl.dupOf), bytes7(0));
                continue;
            }
            Account calldata a = c.accounts[sl.account];
            cur = bytes.concat(
                cur, bytes1(0xff), bytes1(sl.isSigner ? 1 : 0), bytes1(sl.isWritable ? 1 : 0), bytes1(a.executable ? 1 : 0), bytes4(0),
                a.key, a.owner, _le(a.lamports), _le(uint64(a.data.length))
            );
            sl.metaRegion = ri;
            sl.metaOff = cur.length - 88;
            sl.preLen = a.data.length;
            s.regions[ri++] = SolanaVM.Region(vaddr, true, 0, cur);
            vaddr += uint64(cur.length);
            // região dos dados: gravável só se a conta for gravável e do programa; cresce até +10240
            bool w = sl.isWritable && a.owner == c.programId;
            sl.dataRegion = ri;
            s.regions[ri++] = SolanaVM.Region(vaddr, w, uint64(a.data.length + MAX_PERMITTED_DATA_INCREASE), a.data);
            vaddr += uint64(a.data.length + MAX_PERMITTED_DATA_INCREASE);
            // a região seguinte começa com o alinhamento a 8 dos dados e o rent_epoch
            cur = bytes.concat(new bytes((8 - a.data.length % 8) % 8), bytes8(0xffffffffffffffff));
        }
        cur = bytes.concat(cur, _le(uint64(c.data.length)));
        s.ixDataAddr = vaddr + uint64(cur.length);
        cur = bytes.concat(cur, c.data, c.programId);
        // tabela de ponteiros (SIMD-0449), alinhada a 8
        cur = bytes.concat(cur, new bytes((8 - (vaddr + cur.length) % 8) % 8));
        for (uint256 i = 0; i < n; i++) {
            Slot memory sl = s.slots[i];
            cur = bytes.concat(cur, _le(sl.dup ? s.slots[sl.dupOf].markerAddr : sl.markerAddr));
        }
        s.regions[ri] = SolanaVM.Region(vaddr, true, 0, cur);
    }

    // ------------------------------------------------------------------ execução

    /// @notice Processa uma instrução do programa `elf` como o loader do agave faria.
    function invoke(bytes calldata elf, Call calldata c) external view returns (Outcome memory o) {
        return _invoke(elf, c, true);
    }

    /// @notice Como `invoke`, para um ELF já verificado com `SolanaVM.verifyElf` (poupa o verificador).
    function invokeVerified(bytes calldata elf, Call calldata c) external view returns (Outcome memory o) {
        return _invoke(elf, c, false);
    }

    function _invoke(bytes calldata elf, Call calldata c, bool check) private view returns (Outcome memory o) {
        Ser memory s = serialize(c);
        SolanaVM.Env memory env = SolanaVM.Env(c.programId, c.maxCu, s.ixDataAddr, c.sysvars);
        SolanaVM.Result memory r = check ? vm.runElf(elf, s.regions, env) : vm.runElfVerified(elf, s.regions, env);
        SolanaCpi.Acc[] memory accts = _accounts(c, s);
        bytes memory logs = r.logs;
        while (r.status == SolanaVM.Status.Cpi) {
            SolanaCpi.Output memory co = cpi.invoke(_cpiInput(elf, c, s, r, accts));
            logs = bytes.concat(logs, co.logs);
            accts = co.accounts;
            if (co.returnDataCleared) r.returnData = "";
            if (co.status != 0) {
                r.status = SolanaVM.Status(co.status);
                r.err = co.err;
                r.fault = co.fault;
                r.cu = co.cu;
                break;
            }
            r = _resume(elf, s, env, r.suspended, co);
            logs = bytes.concat(logs, r.logs);
        }
        r.logs = logs;
        o.accounts = c.accounts;
        o.returnData = r.returnData;
        o.cu = r.cu;
        SolanaLog.Failure memory f = _finish(c, r, s, o.accounts, accts);
        if (f.kind != 0) {
            o.err = uint32(f.ie) + 1;
            o.custom = f.custom;
            o.accounts = c.accounts; // nada muda em caso de erro
            if (r.status != SolanaVM.Status.Ok && r.status != SolanaVM.Status.SyscallError && !_inSyscall(r)) o.cu = c.maxCu;
        }
        o.logs = log.render(c.programId, logs, r.cu, c.maxCu, r.returnData, f); // o log mostra o que a VM contou
    }

    /// @dev Estado das contas como a CPI precisa (uma entrada por meta; repetidas copiam a original).
    function _accounts(Call calldata c, Ser memory s) private pure returns (SolanaCpi.Acc[] memory out) {
        out = new SolanaCpi.Acc[](s.slots.length);
        for (uint256 i = 0; i < s.slots.length; i++) {
            Slot memory sl = s.slots[i];
            Slot memory orig = sl.dup ? s.slots[sl.dupOf] : sl;
            Account calldata a = c.accounts[sl.account];
            uint8 flags = (sl.isSigner ? 1 : 0) | (sl.isWritable ? 2 : 0) | (a.executable ? 4 : 0);
            out[i] = SolanaCpi.Acc(
                a.key, a.owner, a.lamports, uint64(a.data.length), uint64(orig.preLen), orig.markerAddr, uint32(3 + orig.dataRegion), flags
            );
        }
    }

    /// @dev Memória da VM suspensa (rodata, pilha, heap, input) + registos para o SolanaCpi.
    function _cpiInput(bytes calldata elf, Call calldata c, Ser memory s, SolanaVM.Result memory r, SolanaCpi.Acc[] memory accts)
        private
        view
        returns (SolanaCpi.Input memory in_)
    {
        in_.rust = r.err == 1;
        in_.programId = c.programId;
        in_.maxCu = c.maxCu;
        in_.cu = r.cu;
        for (uint256 k = 0; k < 5; k++) in_.args[k] = r.suspended.regs[k + 1];
        in_.accounts = accts;
        in_.regions = new SolanaVM.Region[](3 + s.regions.length);
        (, , , uint256 roOff, uint256 roLen, ) = vm.parseElf(elf);
        in_.regions[0] = SolanaVM.Region(0, false, uint64(roLen), elf[roOff:roOff + roLen]);
        in_.regions[1] = SolanaVM.Region(STACK_START, true, STACK_SIZE, r.suspended.stack);
        in_.regions[2] = SolanaVM.Region(HEAP_START, true, HEAP_SIZE, r.suspended.heap);
        for (uint256 i = 0; i < s.regions.length; i++) {
            SolanaVM.Region memory rg = s.regions[i];
            in_.regions[3 + i] = SolanaVM.Region(rg.vaddr, rg.writable, rg.reserved, r.regions[i]);
        }
    }

    /// @dev Retoma a VM depois de uma CPI bem-sucedida (r0 = 0, return data vazio).
    function _resume(bytes calldata elf, Ser memory s, SolanaVM.Env memory env, SolanaVM.Suspended memory sp, SolanaCpi.Output memory co)
        private
        view
        returns (SolanaVM.Result memory)
    {
        sp.regs[0] = 0;
        sp.cu = co.cu;
        sp.stack = co.regions[1].data;
        sp.heap = co.regions[2].data;
        sp.returnData = "";
        for (uint256 i = 0; i < s.regions.length; i++) {
            s.regions[i].data = co.regions[3 + i].data;
            s.regions[i].writable = co.regions[3 + i].writable;
        }
        return vm.resumeElfVerified(elf, s.regions, env, sp);
    }

    function _inSyscall(SolanaVM.Result memory r) private pure returns (bool) {
        return (r.fault >> 129) & 1 == 1;
    }

    function _fail(IE err, uint32 custom) private pure returns (SolanaLog.Failure memory f) {
        f.kind = 1;
        f.ie = uint8(err);
        f.custom = custom;
    }

    function _failMsg(uint8 kind, uint64 sysErr) private pure returns (SolanaLog.Failure memory f) {
        f.kind = kind;
        f.ie = uint8(IE.ProgramFailedToComplete);
        f.sysErr = sysErr;
    }

    /// @dev `execute` + `deserialize_parameters` do agave: devolve a falha (kind 0 = sucesso) e atualiza `accounts`.
    function _finish(Call calldata c, SolanaVM.Result memory r, Ser memory s, Account[] memory accounts, SolanaCpi.Acc[] memory accts)
        private
        pure
        returns (SolanaLog.Failure memory f)
    {
        if (r.status == SolanaVM.Status.Ok) {
            if (r.r0 != 0) {
                (IE e, uint32 custom) = _fromU64(r.r0);
                return _fail(e, custom);
            }
            (bool failed, IE err) = _deserialize(c, r, s, accounts, accts);
            if (failed) f = _fail(err, 0);
            return f;
        }
        if (r.status == SolanaVM.Status.CuExceeded) return _fail(IE.ComputationalBudgetExceeded, 0);
        if (r.status == SolanaVM.Status.SyscallError) {
            if (r.err == E_UNSUPPORTED_SYSVAR) return _fail(IE.UnsupportedSysvar, 0);
            if (r.err == E_ARITHMETIC_OVERFLOW) return _fail(IE.ArithmeticOverflow, 0);
            // a syscall devolveu um InstructionError (CPI): o loader propaga-o tal qual
            if (r.err & 0xff == E_INSTRUCTION) return _fail(IE(uint8(r.err >> 8)), uint32(r.err >> 32));
            return _failMsg(2, r.err);
        }
        if (r.status == SolanaVM.Status.AccessViolation) return _accessViolation(c.programId, s, accts, r.fault);
        if (r.status == SolanaVM.Status.DivideByZero) return _failMsg(4, 0);
        if (r.status == SolanaVM.Status.CallDepthExceeded) return _failMsg(5, 0);
        if (r.status == SolanaVM.Status.CallOutsideTextSegment) return _failMsg(6, 0);
        return _failMsg(7, 0);
    }

    /// @dev Acesso inválido: dentro do espaço reservado de uma conta vira um erro de conta (agave `execute`).
    function _accessViolation(bytes32 programId, Ser memory s, SolanaCpi.Acc[] memory accts, uint256 fault) private pure returns (SolanaLog.Failure memory f) {
        uint64 vaddr = uint64(fault);
        uint64 len = uint64(fault >> 64);
        for (uint256 i = 0; i < s.slots.length; i++) {
            uint256 k = s.slots[i].dup ? s.slots[i].dupOf : i;
            Slot memory sl = s.slots[k];
            uint64 start = s.regions[sl.dataRegion].vaddr;
            uint64 end = start + uint64(sl.preLen + MAX_PERMITTED_DATA_INCREASE);
            if (vaddr >= start && vaddr < end) {
                if (vaddr + len <= end) {
                    // can_data_be_changed com o estado atual da conta (a CPI pode ter mudado o dono)
                    IE e = !sl.isWritable ? IE.ReadonlyDataModified : IE.ExternalAccountDataModified;
                    bool bad = !sl.isWritable || accts[k].owner != programId;
                    bool store = (fault >> 128) & 1 == 1;
                    return _fail(store ? (bad ? e : IE.InvalidRealloc) : (bad ? IE.AccountDataTooSmall : IE.InvalidRealloc), 0);
                }
                break;
            }
        }
        f.kind = 3;
        f.ie = uint8(IE.ProgramFailedToComplete);
        f.vaddr = vaddr;
        f.len = len;
    }

    /// @dev `deserialize_parameters_for_abiv1`: lamports, tamanho dos dados, dados e owner de cada conta.
    function _deserialize(Call calldata c, SolanaVM.Result memory r, Ser memory s, Account[] memory accounts, SolanaCpi.Acc[] memory accts)
        private
        pure
        returns (bool failed, IE err)
    {
        int256[2] memory delta; // [lamports, bytes realocados] acumulados na instrução
        for (uint256 i = 0; i < s.slots.length; i++) {
            Slot memory sl = s.slots[i];
            if (sl.dup) continue;
            (failed, err) = _deserializeOne(c.programId, r, sl, accts[i], accounts[sl.account], delta);
            if (failed) return (failed, err);
        }
        if (delta[0] != 0) return (true, IE.UnbalancedInstruction);
    }

    function _deserializeOne(bytes32 programId, SolanaVM.Result memory r, Slot memory sl, SolanaCpi.Acc memory pre, Account memory a, int256[2] memory delta)
        private
        pure
        returns (bool failed, IE err)
    {
        // o que a transação já sabe da conta (muda com CPI): lamports e owner "comprometidos"
        bool owned = pre.owner == programId;
        bytes memory meta = r.regions[sl.metaRegion];
        {
            uint64 lamports = _u64(meta, sl.metaOff + 72);
            if (lamports != pre.lamports) {
                // set_lamports
                if (!owned && lamports < pre.lamports) return (true, IE.ExternalAccountLamportSpend);
                if (!sl.isWritable) return (true, IE.ReadonlyLamportChange);
            }
            delta[0] += int256(uint256(lamports)) - int256(uint256(a.lamports));
            a.lamports = lamports;
        }
        uint256 postLen = _u64(meta, sl.metaOff + 80);
        if (postLen - (postLen > sl.preLen ? sl.preLen : postLen) > MAX_PERMITTED_DATA_INCREASE || postLen > MAX_ACCOUNT_DATA_LEN) {
            return (true, IE.InvalidRealloc);
        }
        bytes memory data = r.regions[sl.dataRegion];
        if (data.length != postLen) {
            // set_data_length: can_data_be_resized + can_data_be_changed
            if (delta[1] + int256(postLen) - int256(data.length) > int256(MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION)) {
                return (true, IE.MaxAccountsDataAllocationsExceeded);
            }
            if (!sl.isWritable) return (true, IE.ReadonlyDataModified);
            if (!owned) return (true, IE.ExternalAccountDataModified);
            delta[1] += int256(postLen) - int256(data.length);
        }
        a.data = _resize(data, postLen);
        bytes32 owner = _b32(meta, sl.metaOff + 40);
        if (owner != pre.owner) {
            // set_owner: só o dono, só se gravável, só com dados zerados
            if (!owned || !sl.isWritable || !_zeroed(a.data)) return (true, IE.ModifiedProgramId);
        }
        a.owner = owner;
    }

    // ------------------------------------------------------------------ erros e log

    /// @dev `InstructionError::from(u64)` para o código devolvido pelo programa.
    function _fromU64(uint64 code) private pure returns (IE err, uint32 custom) {
        uint64 hi = code >> 32;
        if (hi == 0) return (IE.Custom, uint32(code));
        if (code != hi << 32) return (IE.InvalidError, 0);
        if (hi == 1) return (IE.Custom, 0);
        if (hi == 2) return (IE.InvalidArgument, 0);
        if (hi == 3) return (IE.InvalidInstructionData, 0);
        if (hi == 4) return (IE.InvalidAccountData, 0);
        if (hi == 5) return (IE.AccountDataTooSmall, 0);
        if (hi == 6) return (IE.InsufficientFunds, 0);
        if (hi == 7) return (IE.IncorrectProgramId, 0);
        if (hi == 8) return (IE.MissingRequiredSignature, 0);
        if (hi == 9) return (IE.AccountAlreadyInitialized, 0);
        if (hi == 10) return (IE.UninitializedAccount, 0);
        if (hi == 11) return (IE.NotEnoughAccountKeys, 0);
        if (hi == 12) return (IE.AccountBorrowFailed, 0);
        if (hi == 13) return (IE.MaxSeedLengthExceeded, 0);
        if (hi == 14) return (IE.InvalidSeeds, 0);
        if (hi == 15) return (IE.BorshIoError, 0);
        if (hi == 16) return (IE.AccountNotRentExempt, 0);
        if (hi == 17) return (IE.UnsupportedSysvar, 0);
        if (hi == 18) return (IE.IllegalOwner, 0);
        if (hi == 19) return (IE.MaxAccountsDataAllocationsExceeded, 0);
        if (hi == 20) return (IE.InvalidRealloc, 0);
        if (hi == 21) return (IE.MaxInstructionTraceLengthExceeded, 0);
        if (hi == 22) return (IE.BuiltinProgramsMustConsumeComputeUnits, 0);
        if (hi == 23) return (IE.InvalidAccountOwner, 0);
        if (hi == 24) return (IE.ArithmeticOverflow, 0);
        if (hi == 25) return (IE.Immutable, 0);
        if (hi == 26) return (IE.IncorrectAuthority, 0);
        return (IE.InvalidError, 0);
    }

    // ------------------------------------------------------------------ utilidades

    function _le(uint64 v) private pure returns (bytes8 out) {
        for (uint256 i = 0; i < 8; i++) out |= bytes8(bytes1(uint8(v >> (8 * i)))) >> (8 * i);
    }

    function _u64(bytes memory b, uint256 off) private pure returns (uint64 v) {
        for (uint256 i = 0; i < 8; i++) v |= uint64(uint8(b[off + i])) << uint64(8 * i);
    }

    function _b32(bytes memory b, uint256 off) private pure returns (bytes32 v) {
        assembly ("memory-safe") {
            v := mload(add(add(b, 32), off))
        }
    }

    /// @dev Dados com o novo tamanho (zeros além do que a VM devolveu).
    function _resize(bytes memory b, uint256 len) private pure returns (bytes memory out) {
        if (b.length == len) return b;
        out = new bytes(len);
        assembly ("memory-safe") {
            mcopy(add(out, 32), add(b, 32), len)
        }
        if (len < b.length) return out;
        // mcopy acima copiou lixo além de b: zera
        assembly ("memory-safe") {
            let p := add(add(out, 32), mload(b))
            calldatacopy(p, calldatasize(), sub(len, mload(b)))
        }
    }

    function _zeroed(bytes memory b) private pure returns (bool) {
        for (uint256 i = 0; i < b.length; i++) if (b[i] != 0) return false;
        return true;
    }
}
