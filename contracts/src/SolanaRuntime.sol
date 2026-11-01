// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SolanaVM} from "./SolanaVM.sol";

/// @title SolanaRuntime — a camada de contas do runtime Solana (loader v3 / ABIv1) em Solidity
/// @notice Recebe uma instrução como o agave recebe (programa, contas, metas, dados), serializa as
///         contas no formato que o programa espera (`serialize_parameters`, agave 4.3, com
///         direct mapping e ponteiros diretos), roda o programa no `SolanaVM` e aplica as regras
///         de desserialização (`deserialize_parameters`: lamports, realloc, owner, saldo) para
///         produzir o `InstructionError`, as contas finais e o log no formato do agave.
///
/// @dev Semântica: `solana-program-runtime` 4.3 (`serialization.rs`, `vm.rs`) e
///      `solana-transaction-context` 4.3 (`instruction_accounts.rs`). Conferida pelos fixtures do
///      Mollusk em `fixtures/solana/programs.json`.
contract SolanaRuntime {
    SolanaVM public immutable vm;

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

    /// @notice `InstructionError` do agave, na ordem do enum (Custom leva o código em `custom`).
    enum IE {
        GenericError, InvalidArgument, InvalidInstructionData, InvalidAccountData, AccountDataTooSmall, InsufficientFunds,
        IncorrectProgramId, MissingRequiredSignature, AccountAlreadyInitialized, UninitializedAccount, UnbalancedInstruction,
        ModifiedProgramId, ExternalAccountLamportSpend, ExternalAccountDataModified, ReadonlyLamportChange, ReadonlyDataModified,
        DuplicateAccountIndex, ExecutableModified, RentEpochModified, NotEnoughAccountKeys, AccountDataSizeChanged,
        AccountNotExecutable, AccountBorrowFailed, AccountBorrowOutstanding, DuplicateAccountOutOfSync, Custom, InvalidError,
        ExecutableDataModified, ExecutableLamportChange, ExecutableAccountNotRentExempt, UnsupportedProgramId, CallDepth,
        MissingAccount, ReentrancyNotAllowed, MaxSeedLengthExceeded, InvalidSeeds, InvalidRealloc, ComputationalBudgetExceeded,
        PrivilegeEscalation, ProgramEnvironmentSetupFailure, ProgramFailedToComplete, ProgramFailedToCompile, Immutable,
        IncorrectAuthority, BorshIoError, AccountNotRentExempt, InvalidAccountOwner, ArithmeticOverflow, UnsupportedSysvar,
        IllegalOwner, MaxAccountsDataAllocationsExceeded, MaxAccountsExceeded, MaxInstructionTraceLengthExceeded,
        BuiltinProgramsMustConsumeComputeUnits, BailOut
    }

    uint256 public constant MAX_PERMITTED_DATA_INCREASE = 10240;
    // códigos de erro de syscall do SolanaVM (SolanaVM.E_*)
    uint64 private constant E_ABORT = 1;
    uint64 private constant E_PANIC = 2;
    uint64 private constant E_INVALID_STRING = 3;
    uint64 private constant E_COPY_OVERLAPPING = 4;
    uint64 private constant E_INVALID_POINTER = 5;
    uint64 private constant E_RETURN_DATA_TOO_LARGE = 6;
    uint64 private constant E_UNALIGNED_POINTER = 7;
    uint64 private constant E_INVALID_LENGTH = 8;
    uint64 private constant E_UNIMPLEMENTED = 9;
    uint64 private constant E_ARITHMETIC_OVERFLOW = 10;
    uint64 private constant E_TOO_MANY_SLICES = 11;
    uint64 private constant E_UNSUPPORTED_SYSVAR = 12;
    uint256 public constant MAX_ACCOUNT_DATA_LEN = 10 * 1024 * 1024;
    uint256 public constant MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION = 2 * MAX_ACCOUNT_DATA_LEN;
    uint256 public constant MAX_ACCOUNTS_PER_INSTRUCTION = 255;
    uint64 private constant INPUT_START = 0x400000000;
    uint64 private constant MASK64 = 0xffffffffffffffff;

    error BadMeta();

    constructor(SolanaVM vm_) {
        vm = vm_;
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
        o.accounts = c.accounts;
        o.returnData = r.returnData;
        o.cu = r.cu;
        (bool failed, IE err, uint32 custom, string memory failure) = _finish(c, r, s, o.accounts);
        if (failed) {
            o.err = uint32(err) + 1;
            o.custom = custom;
            o.accounts = c.accounts; // nada muda em caso de erro
            if (r.status != SolanaVM.Status.Ok && r.status != SolanaVM.Status.SyscallError && !_inSyscall(r)) o.cu = c.maxCu;
        }
        o.logs = _logs(c.programId, r, c.maxCu, failed, failure);
    }

    function _inSyscall(SolanaVM.Result memory r) private pure returns (bool) {
        return (r.fault >> 129) & 1 == 1;
    }

    /// @dev `execute` + `deserialize_parameters` do agave: devolve o erro e atualiza `accounts`.
    function _finish(Call calldata c, SolanaVM.Result memory r, Ser memory s, Account[] memory accounts)
        private
        pure
        returns (bool failed, IE err, uint32 custom, string memory failure)
    {
        if (r.status == SolanaVM.Status.Ok) {
            if (r.r0 != 0) {
                (err, custom) = _fromU64(r.r0);
                return (true, err, custom, _display(err, custom));
            }
            (failed, err) = _deserialize(c, r, s, accounts);
            return (failed, err, 0, failed ? _display(err, 0) : "");
        }
        if (r.status == SolanaVM.Status.CuExceeded) return (true, IE.ComputationalBudgetExceeded, 0, _display(IE.ComputationalBudgetExceeded, 0));
        if (r.status == SolanaVM.Status.SyscallError) {
            if (r.err == E_UNSUPPORTED_SYSVAR) return (true, IE.UnsupportedSysvar, 0, _display(IE.UnsupportedSysvar, 0));
            if (r.err == E_ARITHMETIC_OVERFLOW) return (true, IE.ArithmeticOverflow, 0, _display(IE.ArithmeticOverflow, 0));
            return (true, IE.ProgramFailedToComplete, 0, _syscallMessage(r));
        }
        if (r.status == SolanaVM.Status.AccessViolation) {
            (err, failure) = _accessViolation(c, s, r.fault);
            return (true, err, 0, failure);
        }
        if (r.status == SolanaVM.Status.DivideByZero) return (true, IE.ProgramFailedToComplete, 0, "Divide by zero");
        if (r.status == SolanaVM.Status.CallDepthExceeded) return (true, IE.ProgramFailedToComplete, 0, "Exceeded max BPF to BPF call depth");
        if (r.status == SolanaVM.Status.CallOutsideTextSegment) return (true, IE.ProgramFailedToComplete, 0, "Attempted to call outside of the text segment");
        return (true, IE.ProgramFailedToComplete, 0, "Unsupported instruction");
    }

    /// @dev Acesso inválido: dentro do espaço reservado de uma conta vira um erro de conta (agave `execute`).
    function _accessViolation(Call calldata c, Ser memory s, uint256 fault) private pure returns (IE err, string memory failure) {
        uint64 vaddr = uint64(fault);
        uint64 len = uint64(fault >> 64);
        for (uint256 i = 0; i < s.slots.length; i++) {
            Slot memory sl = s.slots[i].dup ? s.slots[s.slots[i].dupOf] : s.slots[i];
            uint64 start = s.regions[sl.dataRegion].vaddr;
            uint64 end = start + uint64(sl.preLen + MAX_PERMITTED_DATA_INCREASE);
            if (vaddr >= start && vaddr < end) {
                if (vaddr + len <= end) {
                    (bool bad, IE e) = _canDataBeChanged(c, sl);
                    bool store = (fault >> 128) & 1 == 1;
                    err = store ? (bad ? e : IE.InvalidRealloc) : (bad ? IE.AccountDataTooSmall : IE.InvalidRealloc);
                    return (err, _display(err, 0));
                }
                break;
            }
        }
        return (IE.ProgramFailedToComplete, string.concat("Access violation in unknown section at address 0x", _hex(vaddr), " of size ", _dec(len)));
    }

    function _canDataBeChanged(Call calldata c, Slot memory sl) private pure returns (bool bad, IE e) {
        if (!sl.isWritable) return (true, IE.ReadonlyDataModified);
        if (c.accounts[sl.account].owner != c.programId) return (true, IE.ExternalAccountDataModified);
    }

    /// @dev `deserialize_parameters_for_abiv1`: lamports, tamanho dos dados, dados e owner de cada conta.
    function _deserialize(Call calldata c, SolanaVM.Result memory r, Ser memory s, Account[] memory accounts)
        private
        pure
        returns (bool failed, IE err)
    {
        int256 lamportsDelta;
        int256 resizeDelta;
        for (uint256 i = 0; i < s.slots.length; i++) {
            Slot memory sl = s.slots[i];
            if (sl.dup) continue;
            Account memory a = accounts[sl.account];
            bool owned = a.owner == c.programId;
            bytes memory meta = r.regions[sl.metaRegion];
            bytes32 owner = _b32(meta, sl.metaOff + 40);
            uint64 lamports = _u64(meta, sl.metaOff + 72);
            if (lamports != a.lamports) {
                // set_lamports
                if (!owned && lamports < a.lamports) return (true, IE.ExternalAccountLamportSpend);
                if (!sl.isWritable) return (true, IE.ReadonlyLamportChange);
                lamportsDelta += int256(uint256(lamports)) - int256(uint256(a.lamports));
                a.lamports = lamports;
            }
            uint256 postLen = _u64(meta, sl.metaOff + 80);
            if (postLen - (postLen > sl.preLen ? sl.preLen : postLen) > MAX_PERMITTED_DATA_INCREASE || postLen > MAX_ACCOUNT_DATA_LEN) {
                return (true, IE.InvalidRealloc);
            }
            bytes memory data = r.regions[sl.dataRegion];
            if (data.length != postLen) {
                // set_data_length: can_data_be_resized + can_data_be_changed
                if (resizeDelta + int256(postLen) - int256(data.length) > int256(MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION)) {
                    return (true, IE.MaxAccountsDataAllocationsExceeded);
                }
                if (!sl.isWritable) return (true, IE.ReadonlyDataModified);
                if (!owned) return (true, IE.ExternalAccountDataModified);
                resizeDelta += int256(postLen) - int256(data.length);
            }
            a.data = _resize(data, postLen);
            if (owner != a.owner) {
                // set_owner: só o dono, só se gravável, só com dados zerados
                if (!owned || !sl.isWritable || !_zeroed(a.data)) return (true, IE.ModifiedProgramId);
                a.owner = owner;
            }
        }
        if (lamportsDelta != 0) return (true, IE.UnbalancedInstruction);
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

    /// @dev `Display` do InstructionError (texto da linha "Program ... failed: ...").
    function _display(IE e, uint32 custom) private pure returns (string memory) {
        if (e == IE.Custom) return string.concat("custom program error: 0x", _hex(custom));
        if (e == IE.InvalidArgument) return "invalid program argument";
        if (e == IE.InvalidInstructionData) return "invalid instruction data";
        if (e == IE.InvalidAccountData) return "invalid account data for instruction";
        if (e == IE.AccountDataTooSmall) return "account data too small for instruction";
        if (e == IE.InsufficientFunds) return "insufficient funds for instruction";
        if (e == IE.IncorrectProgramId) return "incorrect program id for instruction";
        if (e == IE.MissingRequiredSignature) return "missing required signature for instruction";
        if (e == IE.AccountAlreadyInitialized) return "instruction requires an uninitialized account";
        if (e == IE.UninitializedAccount) return "instruction requires an initialized account";
        if (e == IE.UnbalancedInstruction) return "sum of account balances before and after instruction do not match";
        if (e == IE.ModifiedProgramId) return "instruction illegally modified the program id of an account";
        if (e == IE.ExternalAccountLamportSpend) return "instruction spent from the balance of an account it does not own";
        if (e == IE.ExternalAccountDataModified) return "instruction modified data of an account it does not own";
        if (e == IE.ReadonlyLamportChange) return "instruction changed the balance of a read-only account";
        if (e == IE.ReadonlyDataModified) return "instruction modified data of a read-only account";
        if (e == IE.DuplicateAccountIndex) return "instruction contains duplicate accounts";
        if (e == IE.ExecutableModified) return "instruction changed executable bit of an account";
        if (e == IE.RentEpochModified) return "instruction modified rent epoch of an account";
        if (e == IE.NotEnoughAccountKeys) return "insufficient account keys for instruction";
        if (e == IE.AccountDataSizeChanged) return "program other than the account's owner changed the size of the account data";
        if (e == IE.AccountNotExecutable) return "instruction expected an executable account";
        if (e == IE.AccountBorrowFailed) return "instruction tries to borrow reference for an account which is already borrowed";
        if (e == IE.AccountBorrowOutstanding) return "instruction left account with an outstanding borrowed reference";
        if (e == IE.DuplicateAccountOutOfSync) return "instruction modifications of multiply-passed account differ";
        if (e == IE.InvalidError) return "program returned invalid error code";
        if (e == IE.ExecutableDataModified) return "instruction changed executable accounts data";
        if (e == IE.ExecutableLamportChange) return "instruction changed the balance of an executable account";
        if (e == IE.ExecutableAccountNotRentExempt) return "executable accounts must be rent exempt";
        if (e == IE.UnsupportedProgramId) return "Unsupported program id";
        if (e == IE.CallDepth) return "Cross-program invocation call depth too deep";
        if (e == IE.MissingAccount) return "An account required by the instruction is missing";
        if (e == IE.ReentrancyNotAllowed) return "Cross-program invocation reentrancy not allowed for this instruction";
        if (e == IE.MaxSeedLengthExceeded) return "Length of the seed is too long for address generation";
        if (e == IE.InvalidSeeds) return "Provided seeds do not result in a valid address";
        if (e == IE.InvalidRealloc) return "Failed to reallocate account data";
        if (e == IE.ComputationalBudgetExceeded) return "Computational budget exceeded";
        if (e == IE.PrivilegeEscalation) return "Cross-program invocation with unauthorized signer or writable account";
        if (e == IE.ProgramEnvironmentSetupFailure) return "Failed to create program execution environment";
        if (e == IE.ProgramFailedToComplete) return "Program failed to complete";
        if (e == IE.ProgramFailedToCompile) return "Program failed to compile";
        if (e == IE.Immutable) return "Account is immutable";
        if (e == IE.IncorrectAuthority) return "Incorrect authority provided";
        if (e == IE.BorshIoError) return "Failed to serialize or deserialize account data";
        if (e == IE.AccountNotRentExempt) return "An account does not have enough lamports to be rent-exempt";
        if (e == IE.InvalidAccountOwner) return "Invalid account owner";
        if (e == IE.ArithmeticOverflow) return "Program arithmetic overflowed";
        if (e == IE.UnsupportedSysvar) return "Unsupported sysvar";
        if (e == IE.IllegalOwner) return "Provided owner is not allowed";
        if (e == IE.MaxAccountsDataAllocationsExceeded) return "Accounts data allocations exceeded the maximum allowed per transaction";
        if (e == IE.MaxAccountsExceeded) return "Max accounts exceeded";
        if (e == IE.MaxInstructionTraceLengthExceeded) return "Max instruction trace length exceeded";
        if (e == IE.BuiltinProgramsMustConsumeComputeUnits) return "Builtin programs must consume compute units";
        if (e == IE.BailOut) return "Block production bailed out";
        return "generic instruction error";
    }

    /// @dev Mensagem (`Display` do SyscallError) de uma falha dentro de uma syscall.
    function _syscallMessage(SolanaVM.Result memory r) private pure returns (string memory) {
        uint64 e = r.err;
        if (e == E_ABORT) return "SBF program panicked";
        if (e == E_PANIC) {
            (uint256 line, uint256 column, bytes memory file) = _panicEntry(r.logs);
            return string.concat("SBF program Panicked in ", string(file), " at ", _dec(line), ":", _dec(column));
        }
        if (e == E_INVALID_STRING) return "invalid utf-8 sequence";
        if (e == E_COPY_OVERLAPPING) return "Overlapping copy";
        if (e == E_INVALID_POINTER) return "Invalid pointer";
        if (e == E_RETURN_DATA_TOO_LARGE) return "Return data too large";
        if (e == E_UNALIGNED_POINTER) return "Unaligned pointer";
        if (e == E_INVALID_LENGTH) return "InvalidLength";
        if (e == E_TOO_MANY_SLICES) return "Hashing too many sequences";
        if (e == E_UNIMPLEMENTED) return "syscall not implemented in SolanaVM";
        return "syscall error";
    }

    /// @dev Log no formato do agave: invoke, linhas do programa, consumo, return data, sucesso/falha.
    function _logs(bytes32 programId, SolanaVM.Result memory r, uint64 maxCu, bool failed, string memory failure) private pure returns (string memory out) {
        string memory pid = _b58(programId);
        out = string.concat("Program ", pid, " invoke [1]");
        bytes memory logs = r.logs;
        uint256 i;
        while (i + 5 <= logs.length) {
            uint8 kind = uint8(logs[i]);
            uint256 len = (uint256(uint8(logs[i + 1])) << 24) | (uint256(uint8(logs[i + 2])) << 16) | (uint256(uint8(logs[i + 3])) << 8) | uint256(uint8(logs[i + 4]));
            bytes memory payload = _slice(logs, i + 5, len);
            i += 5 + len;
            if (kind == 0) out = string.concat(out, "\nProgram log: ", string(payload));
            else if (kind == 1) out = string.concat(out, "\nProgram log: ", _b58(bytes32(payload)));
            else if (kind == 2) out = string.concat(out, "\nProgram data: ", _dataFields(payload));
        }
        out = string.concat(out, "\nProgram ", pid, " consumed ", _dec(r.cu), " of ", _dec(maxCu), " compute units");
        if (r.returnData.length != 0) out = string.concat(out, "\nProgram return: ", pid, " ", _b64(r.returnData));
        out = failed ? string.concat(out, "\nProgram ", pid, " failed: ", failure) : string.concat(out, "\nProgram ", pid, " success");
    }

    function _dataFields(bytes memory payload) private pure returns (string memory out) {
        uint256 j;
        bool first = true;
        while (j + 4 <= payload.length) {
            uint256 fl = (uint256(uint8(payload[j])) << 24) | (uint256(uint8(payload[j + 1])) << 16) | (uint256(uint8(payload[j + 2])) << 8) | uint256(uint8(payload[j + 3]));
            out = string.concat(out, first ? "" : " ", _b64(_slice(payload, j + 4, fl)));
            first = false;
            j += 4 + fl;
        }
    }

    function _panicEntry(bytes memory logs) private pure returns (uint256 line, uint256 column, bytes memory file) {
        uint256 i;
        while (i + 5 <= logs.length) {
            uint8 kind = uint8(logs[i]);
            uint256 len = (uint256(uint8(logs[i + 1])) << 24) | (uint256(uint8(logs[i + 2])) << 16) | (uint256(uint8(logs[i + 3])) << 8) | uint256(uint8(logs[i + 4]));
            if (kind == 3) {
                line = uint64(bytes8(_slice(logs, i + 5, 8)));
                column = uint64(bytes8(_slice(logs, i + 13, 8)));
                file = _slice(logs, i + 21, len - 16);
            }
            i += 5 + len;
        }
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

    function _slice(bytes memory b, uint256 off, uint256 len) private pure returns (bytes memory out) {
        out = new bytes(len);
        assembly ("memory-safe") {
            mcopy(add(out, 32), add(add(b, 32), off), len)
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

    function _hex(uint256 v) private pure returns (string memory s) {
        bytes16 digits = "0123456789abcdef";
        uint256 n = 1;
        for (uint256 t = v; t >= 16; t /= 16) n++;
        bytes memory b = new bytes(n);
        for (uint256 i = 0; i < n; i++) {
            b[n - 1 - i] = digits[v & 15];
            v >>= 4;
        }
        return string(b);
    }

    function _dec(uint256 v) private pure returns (string memory s) {
        uint256 n = 1;
        for (uint256 t = v; t >= 10; t /= 10) n++;
        bytes memory b = new bytes(n);
        for (uint256 i = 0; i < n; i++) {
            b[n - 1 - i] = bytes1(uint8(48 + v % 10));
            v /= 10;
        }
        return string(b);
    }

    bytes private constant B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    function _b58(bytes32 k) private pure returns (string memory) {
        uint256 zeros;
        while (zeros < 32 && k[zeros] == 0) zeros++;
        bytes memory tmp = new bytes(45);
        uint256 n = uint256(k);
        uint256 len;
        while (n > 0) {
            tmp[len++] = B58[n % 58];
            n /= 58;
        }
        bytes memory out = new bytes(zeros + len);
        for (uint256 i = 0; i < zeros; i++) out[i] = "1";
        for (uint256 i = 0; i < len; i++) out[zeros + i] = tmp[len - 1 - i];
        return string(out);
    }

    bytes private constant B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    function _b64(bytes memory data) private pure returns (string memory) {
        if (data.length == 0) return "";
        bytes memory out = new bytes(4 * ((data.length + 2) / 3));
        uint256 j;
        for (uint256 i = 0; i < data.length; i += 3) {
            uint256 a = uint8(data[i]);
            uint256 b = i + 1 < data.length ? uint8(data[i + 1]) : 0;
            uint256 c = i + 2 < data.length ? uint8(data[i + 2]) : 0;
            uint256 triple = (a << 16) | (b << 8) | c;
            out[j++] = B64[(triple >> 18) & 63];
            out[j++] = B64[(triple >> 12) & 63];
            out[j++] = i + 1 < data.length ? B64[(triple >> 6) & 63] : bytes1("=");
            out[j++] = i + 2 < data.length ? B64[triple & 63] : bytes1("=");
        }
        return string(out);
    }
}
