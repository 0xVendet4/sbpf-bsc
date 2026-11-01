// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {SbpfVM} from "./SbpfVM.sol";
import {CodeStore} from "./CodeStore.sol";

/// @title SolanaRuntime — "Solana dentro da BSC"
/// @notice Faça deploy de bytecode sBPF e invoque como num cluster Solana. Cada programa
///         tem uma conta de dados persistente, serializada na região de input:
///
///         [u64 len_dados][dados da conta][u64 len_ix][instruction data][32 bytes caller][32 bytes programId]
///
///         Se o programa retornar r0 == 0 as escritas na conta são gravadas; senão a tx reverte.
contract SolanaRuntime {
    struct Program {
        address code;
        address authority;
        uint32 dataSize;
    }

    uint256 public constant MAX_DATA_SIZE = 10_240;

    mapping(bytes32 => Program) public programs;
    mapping(bytes32 => bytes) internal _accountData;

    event ProgramDeployed(bytes32 indexed programId, address indexed authority, address code, uint32 dataSize);
    event ProgramLog(bytes32 indexed programId, string message);
    event ProgramData(bytes32 indexed programId, uint64[5] values);
    event ComputeUnits(bytes32 indexed programId, uint64 remaining);
    event ProgramInvoked(bytes32 indexed programId, address indexed caller, uint256 computeUnits);

    error ProgramExists(bytes32 programId);
    error ProgramNotFound(bytes32 programId);
    error DataTooLarge();
    error ProgramFailed(bytes32 programId, uint64 code);

    function deploy(bytes calldata code, uint32 dataSize, bytes32 salt) external returns (bytes32 programId) {
        if (dataSize > MAX_DATA_SIZE) revert DataTooLarge();
        programId = keccak256(abi.encode(msg.sender, salt));
        if (programs[programId].code != address(0)) revert ProgramExists(programId);
        address ptr = CodeStore.write(code);
        programs[programId] = Program(ptr, msg.sender, dataSize);
        _accountData[programId] = new bytes(dataSize);
        emit ProgramDeployed(programId, msg.sender, ptr, dataSize);
    }

    function accountData(bytes32 programId) external view returns (bytes memory) {
        return _accountData[programId];
    }

    function programCode(bytes32 programId) external view returns (bytes memory) {
        return CodeStore.read(programs[programId].code);
    }

    /// @notice Executa e persiste o estado. Reverte se r0 != 0 (como uma tx Solana que falha).
    function invoke(bytes32 programId, bytes calldata ix, uint256 computeBudget)
        external
        returns (uint64 r0, uint256 computeUnits)
    {
        (SbpfVM.Result memory res, uint256 ds) = _run(programId, ix, msg.sender, computeBudget);
        if (res.r0 != 0) revert ProgramFailed(programId, res.r0);

        bytes memory data = new bytes(ds);
        bytes memory out = res.input;
        assembly {
            mcopy(add(data, 32), add(out, 40), ds)
        }
        _accountData[programId] = data;

        for (uint256 i = 0; i < res.logs.length; i++) {
            SbpfVM.Log memory l = res.logs[i];
            if (l.kind == 0) emit ProgramLog(programId, string(l.data));
            else if (l.kind == 1) emit ProgramData(programId, l.values);
            else emit ComputeUnits(programId, l.values[0]);
        }
        emit ProgramInvoked(programId, msg.sender, res.steps);
        return (res.r0, res.steps);
    }

    /// @notice Simula (eth_call) sem gravar nada; devolve logs e input final.
    function simulate(bytes32 programId, bytes calldata ix, address caller, uint256 computeBudget)
        external
        view
        returns (SbpfVM.Result memory res)
    {
        (res,) = _run(programId, ix, caller, computeBudget);
    }

    /// @notice Executa bytecode arbitrário sem deploy (playground).
    function execute(bytes calldata code, bytes calldata input, uint256 computeBudget)
        external
        pure
        returns (SbpfVM.Result memory)
    {
        return SbpfVM.run(code, input, computeBudget);
    }

    function _run(bytes32 programId, bytes calldata ix, address caller, uint256 budget)
        internal
        view
        returns (SbpfVM.Result memory res, uint256 ds)
    {
        Program memory p = programs[programId];
        if (p.code == address(0)) revert ProgramNotFound(programId);
        ds = p.dataSize;
        bytes memory input = abi.encodePacked(
            _le64(ds), _accountData[programId], _le64(ix.length), ix, bytes32(uint256(uint160(caller))), programId
        );
        res = SbpfVM.run(CodeStore.read(p.code), input, budget);
    }

    function _le64(uint256 v) internal pure returns (bytes8) {
        uint64 x = uint64(v);
        x = ((x & 0x00000000ffffffff) << 32) | (x >> 32);
        x = ((x & 0x0000ffff0000ffff) << 16) | ((x >> 16) & 0x0000ffff0000ffff);
        x = ((x & 0x00ff00ff00ff00ff) << 8) | ((x >> 8) & 0x00ff00ff00ff00ff);
        return bytes8(x);
    }
}
