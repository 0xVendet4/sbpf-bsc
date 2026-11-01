// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

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


/// @title SolanaLog — o log de uma instrução no formato do agave
/// @notice Converte o buffer de log da VM e da CPI ([tipo:1][tamanho:4][payload]) nas linhas que o
///         agave escreve (invoke, "Program log:", "Program data:", consumo, return data e
///         sucesso/falha com o `Display` do erro). Separado do `SolanaRuntime` para caber no
///         limite de 24 KB de bytecode da EVM.
contract SolanaLog {
    /// @notice Como a instrução terminou. kind: 0 sucesso, 1 `Display` do InstructionError
    ///         (ie, custom), 2 SyscallError (sysErr), 3 acesso inválido fora das contas (vaddr, len),
    ///         4 divisão por zero, 5 profundidade de chamadas, 6 chamada fora do texto, 7 instrução não suportada.
    struct Failure {
        uint8 kind;
        uint8 ie;
        uint32 custom;
        uint64 sysErr;
        uint64 vaddr;
        uint64 len;
    }

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
    uint64 private constant E_INSTRUCTION = 13;
    uint64 private constant E_CPI = 14;

    /// @dev Log no formato do agave: invoke, linhas do programa, consumo, return data, sucesso/falha.
    function render(bytes32 programId, bytes memory logs, uint64 cu, uint64 maxCu, bytes memory returnData, Failure memory f)
        external
        pure
        returns (string memory out)
    {
        string memory pid = _b58(programId);
        out = string.concat("Program ", pid, " invoke [1]");
        uint256 i;
        while (i + 5 <= logs.length) {
            uint8 kind = uint8(logs[i]);
            uint256 len = (uint256(uint8(logs[i + 1])) << 24) | (uint256(uint8(logs[i + 2])) << 16) | (uint256(uint8(logs[i + 3])) << 8) | uint256(uint8(logs[i + 4]));
            bytes memory payload = _slice(logs, i + 5, len);
            i += 5 + len;
            if (kind == 0) out = string.concat(out, "\nProgram log: ", string(payload));
            else if (kind == 1) out = string.concat(out, "\nProgram log: ", _b58(bytes32(payload)));
            else if (kind == 2) out = string.concat(out, "\nProgram data: ", _dataFields(payload));
            else if (kind == 4) out = string.concat(out, "\n", _keyMessage(uint8(payload[0]), _b32(payload, 1)));
            else if (kind == 5) {
                IE ie = IE(uint32(bytes4(_slice(payload, 0, 4))));
                out = string.concat(out, "\nProgram 11111111111111111111111111111111 failed: ", _display(ie, uint32(bytes4(_slice(payload, 4, 4)))));
            } else if (kind == 6) out = string.concat(out, "\n", string(payload));
        }
        out = string.concat(out, "\nProgram ", pid, " consumed ", _dec(cu), " of ", _dec(maxCu), " compute units");
        if (returnData.length != 0) out = string.concat(out, "\nProgram return: ", pid, " ", _b64(returnData));
        out = f.kind == 0
            ? string.concat(out, "\nProgram ", pid, " success")
            : string.concat(out, "\nProgram ", pid, " failed: ", _failure(f, logs));
    }

    /// @dev Texto da falha (o que vem depois de "failed: ").
    function _failure(Failure memory f, bytes memory logs) private pure returns (string memory) {
        if (f.kind == 1) return _display(IE(f.ie), f.custom);
        if (f.kind == 2) return _syscallMessage(f.sysErr, logs);
        if (f.kind == 3) return string.concat("Access violation in unknown section at address 0x", _hex(f.vaddr), " of size ", _dec(f.len));
        if (f.kind == 4) return "Divide by zero";
        if (f.kind == 5) return "Exceeded max BPF to BPF call depth";
        if (f.kind == 6) return "Attempted to call outside of the text segment";
        return "Unsupported instruction";
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
    function _syscallMessage(uint64 e, bytes memory logs) private pure returns (string memory) {
        if (e == E_ABORT) return "SBF program panicked";
        if (e == E_PANIC) {
            (uint256 line, uint256 column, bytes memory file) = _panicEntry(logs);
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
        if (e & 0xff == E_CPI) return _cpiMessage((e >> 8) & 0xffffff, e >> 32);
        return "syscall error";
    }

    /// @dev `Display` do CpiError / SyscallError::BadSeeds.
    function _cpiMessage(uint256 sub, uint256 n) private pure returns (string memory) {
        if (sub == 1) return "Invalid pointer";
        if (sub == 2) return "Too many signers";
        if (sub == 3) return "Could not create program address with signer seeds: Length of the seed is too long for address generation";
        if (sub == 4) return "Could not create program address with signer seeds: Provided seeds do not result in a valid address";
        if (sub == 5) return "InvalidLength";
        if (sub == 6) return string.concat("Invoked an instruction with too many accounts (", _dec(n), " > 255)");
        if (sub == 7) return string.concat("Invoked an instruction with data that is too large (", _dec(n), " > 10240)");
        if (sub == 8) return string.concat("Invoked an instruction with too many account info's (", _dec(n), " > 255)");
        if (sub == 10) return "CPI to sBPF programs is not supported by SolanaVM yet";
        if (sub == 11) return string.concat("system program instruction ", _dec(n), " is not supported by SolanaVM yet");
        return "CPI error";
    }

    /// @dev Mensagens do agave que levam uma chave (ic_msg!, sem prefixo "Program log: ").
    function _keyMessage(uint8 template, bytes32 key) private pure returns (string memory) {
        string memory k = _b58(key);
        if (template == 1) return string.concat("Instruction references an unknown account ", k);
        if (template == 2) return string.concat(k, "'s writable privilege escalated");
        if (template == 3) return string.concat(k, "'s signer privilege escalated");
        if (template == 4) return string.concat("Unknown program ", k);
        if (template == 5) return string.concat("Transfer: `from` account ", k, " must sign");
        if (template == 6) return string.concat("Create Account: account Address { address: ", k, ", base: None } already in use");
        if (template == 7) return string.concat("Allocate: 'to' account Address { address: ", k, ", base: None } must sign");
        if (template == 8) return string.concat("Allocate: account Address { address: ", k, ", base: None } already in use");
        if (template == 9) return string.concat("Assign: account Address { address: ", k, ", base: None } must sign");
        return k;
    }

    // ------------------------------------------------------------------ utilidades

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
