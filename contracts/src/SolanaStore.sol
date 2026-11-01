// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SolanaVM} from "./SolanaVM.sol";
import {SolanaRuntime} from "./SolanaRuntime.sol";

/// @title SolanaStore — programas e contas Solana vivendo dentro da BSC
/// @notice O "ledger" Solana on-chain: guarda programas (ELF .so, em código de contrato) e contas
///         (owner, lamports, dados) no storage da EVM, e processa instruções por transação, como um
///         validador Solana processaria: carrega as contas, roda o programa no `SolanaRuntime` e
///         grava o estado final. Inclui um system program mínimo (criar conta, transferir, alocar,
///         atribuir) para o fluxo normal de um cliente Solana.
///
/// @dev Assinaturas: uma chave (32 bytes) é "assinada" pela transação quando os seus 20 últimos
///      bytes são o `msg.sender`. Cada endereço da BSC controla assim 2^96 chaves Solana
///      (`key = prefixo12 || endereço`). Lamports são lastreados 1:1 em wei: `deposit` credita
///      `msg.value` lamports numa chave e `withdraw` devolve os wei. Programas e contas usam os
///      mesmos ids de sempre: system program 111...1 (zero), loader BPFLoaderUpgradeab1e...
///      Aluguel (rent) não é cobrado.
contract SolanaStore {
    SolanaRuntime public immutable runtime;
    SolanaVM public immutable vm;

    bytes32 public constant SYSTEM_PROGRAM = bytes32(0);
    /// @notice BPFLoaderUpgradeab1e11111111111111111111111 (owner das contas de programa)
    bytes32 public constant BPF_LOADER = 0x02a8f6914e88a1b0e210153ef763ae2b00c2b93d16c124d2c0537a1004800000;
    /// @notice NativeLoader1111111111111111111111111111111 (owner dos programas builtin)
    bytes32 public constant NATIVE_LOADER = 0x058784bf148ba4282fb012574888a9f153a07dadf765c0455c9a970380000000;
    bytes32 private constant SV_CLOCK = 0x06a7d51718c774c928566398691d5eb68b5eb8a39b4b6d5c73555b2100000000;
    bytes32 private constant SV_RENT = 0x06a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a00000000;
    uint64 public constant DEFAULT_COMPUTE_UNIT_LIMIT = 200_000;
    uint64 public constant MAX_COMPUTE_UNIT_LIMIT = 1_400_000;
    uint256 public constant MAX_ACCOUNT_DATA_LEN = 10 * 1024 * 1024;
    uint256 public constant SLOTS_PER_EPOCH = 432_000;
    uint256 private constant CHUNK = 24_575; // EIP-170 menos o byte STOP

    struct Stored {
        bytes32 owner;
        uint64 lamports;
        bool executable;
        bytes data;
    }

    /// @notice Conta de uma instrução, como num `AccountMeta` do Solana.
    struct AccountMeta {
        bytes32 key;
        bool isSigner;
        bool isWritable;
    }

    mapping(bytes32 => Stored) private accounts_;
    mapping(bytes32 => address[]) private chunks_; // ELF guardado como código de contratos (SSTORE2)
    mapping(bytes32 => uint256) public elfLength;

    event ProgramDeployed(bytes32 indexed programId, address indexed deployer, uint256 size);
    event Invoked(bytes32 indexed programId, address indexed caller, uint64 cu, bytes returnData, string logs);
    event Deposited(bytes32 indexed key, address indexed from, uint64 lamports);
    event Withdrawn(bytes32 indexed key, address indexed to, uint64 lamports);
    event AccountCreated(bytes32 indexed key, bytes32 indexed owner, uint64 lamports, uint64 space);
    event Transferred(bytes32 indexed from, bytes32 indexed to, uint64 lamports);

    error NotSigner(bytes32 key);
    error AlreadyDeployed(bytes32 programId);
    error InvalidElf();
    error UnknownProgram(bytes32 programId);
    error ProgramFailed(uint32 err, uint32 custom, string logs);
    error AccountInUse(bytes32 key);
    error NotSystemOwned(bytes32 key);
    error InsufficientLamports(bytes32 key, uint64 have, uint64 need);
    error LamportsOverflow();
    error TooMuchData();
    error ComputeLimitTooHigh();
    error TransferFailed();

    constructor(SolanaRuntime runtime_) {
        runtime = runtime_;
        vm = runtime_.vm();
    }

    // ------------------------------------------------------------------ leitura

    /// @notice Uma chave é assinada por `who` quando os seus 20 últimos bytes são o endereço.
    function signs(bytes32 key, address who) public pure returns (bool) {
        return address(uint160(uint256(key))) == who;
    }

    /// @notice A chave "principal" de um endereço: 12 bytes zero + endereço.
    function keyOf(address who) public pure returns (bytes32) {
        return bytes32(uint256(uint160(who)));
    }

    function account(bytes32 key) external view returns (SolanaRuntime.Account memory) {
        return _load(key);
    }

    /// @notice O ELF de um programa, remontado a partir dos pedaços guardados como código.
    function elf(bytes32 programId) public view returns (bytes memory out) {
        address[] storage cs = chunks_[programId];
        if (cs.length == 0) revert UnknownProgram(programId);
        out = new bytes(elfLength[programId]);
        uint256 off;
        for (uint256 i = 0; i < cs.length; i++) {
            address c = cs[i];
            uint256 n = c.code.length - 1;
            assembly ("memory-safe") {
                extcodecopy(c, add(add(out, 32), off), 1, n)
            }
            off += n;
        }
    }

    // ------------------------------------------------------------------ programas

    /// @notice Publica um programa (ELF sBPF v3) numa chave assinada pelo remetente.
    function deployProgram(bytes32 programId, bytes calldata elf_) external {
        if (!signs(programId, msg.sender)) revert NotSigner(programId);
        if (chunks_[programId].length != 0) revert AlreadyDeployed(programId);
        if (!vm.verifyElf(elf_)) revert InvalidElf(); // carregador + verificador, uma vez só (como no Solana)
        Stored storage s = accounts_[programId];
        if (s.lamports != 0 || s.data.length != 0 || s.owner != SYSTEM_PROGRAM) revert AccountInUse(programId);
        for (uint256 off = 0; off < elf_.length; off += CHUNK) {
            uint256 n = elf_.length - off < CHUNK ? elf_.length - off : CHUNK;
            chunks_[programId].push(_store(elf_[off:off + n]));
        }
        elfLength[programId] = elf_.length;
        s.owner = BPF_LOADER;
        s.executable = true;
        emit ProgramDeployed(programId, msg.sender, elf_.length);
    }

    /// @dev SSTORE2: cria um contrato cujo código é `00 || data` e devolve o endereço.
    function _store(bytes calldata data) private returns (address c) {
        bytes memory code = bytes.concat(hex"600B5981380380925939F3_00", data);
        assembly ("memory-safe") {
            c := create(0, add(code, 32), mload(code))
        }
        if (c == address(0)) revert InvalidElf();
    }

    // ------------------------------------------------------------------ system program

    /// @notice Credita `msg.value` wei como lamports na chave (qualquer um pode financiar qualquer chave).
    function deposit(bytes32 key) external payable {
        if (msg.value >= 1 << 64) revert LamportsOverflow();
        Stored storage s = accounts_[key];
        uint256 total = uint256(s.lamports) + msg.value;
        if (total >= 1 << 64) revert LamportsOverflow();
        s.lamports = uint64(total);
        emit Deposited(key, msg.sender, uint64(msg.value));
    }

    /// @notice Devolve lamports de uma conta do system program como wei para `to`.
    function withdraw(bytes32 key, uint64 lamports, address payable to) external {
        _debit(key, lamports, msg.sender);
        (bool ok, ) = to.call{value: lamports}("");
        if (!ok) revert TransferFailed();
        emit Withdrawn(key, to, lamports);
    }

    /// @notice SystemInstruction::Transfer — `from` tem de ser assinada e pertencer ao system program.
    function transfer(bytes32 from, bytes32 to, uint64 lamports) external {
        _debit(from, lamports, msg.sender);
        accounts_[to].lamports += lamports; // não transborda: a soma de lamports é limitada pelo saldo em wei
        emit Transferred(from, to, lamports);
    }

    /// @notice SystemInstruction::CreateAccount — cria `newKey` (assinada) com `space` bytes zerados e `owner`.
    function createAccount(bytes32 from, bytes32 newKey, uint64 lamports, uint64 space, bytes32 owner) external {
        if (!signs(newKey, msg.sender)) revert NotSigner(newKey);
        Stored storage n = accounts_[newKey];
        if (n.lamports != 0 || n.data.length != 0 || n.owner != SYSTEM_PROGRAM) revert AccountInUse(newKey);
        if (space > MAX_ACCOUNT_DATA_LEN) revert TooMuchData();
        if (lamports != 0) _debit(from, lamports, msg.sender);
        n.lamports = lamports;
        n.owner = owner;
        n.data = new bytes(space);
        emit AccountCreated(newKey, owner, lamports, space);
    }

    /// @notice SystemInstruction::Allocate — reserva `space` bytes zerados numa conta assinada do system program.
    function allocate(bytes32 key, uint64 space) external {
        if (!signs(key, msg.sender)) revert NotSigner(key);
        Stored storage s = accounts_[key];
        if (s.owner != SYSTEM_PROGRAM) revert NotSystemOwned(key);
        if (s.data.length != 0) revert AccountInUse(key);
        if (space > MAX_ACCOUNT_DATA_LEN) revert TooMuchData();
        s.data = new bytes(space);
    }

    /// @notice SystemInstruction::Assign — muda o owner de uma conta assinada do system program.
    function assign(bytes32 key, bytes32 owner) external {
        if (!signs(key, msg.sender)) revert NotSigner(key);
        Stored storage s = accounts_[key];
        if (s.owner != SYSTEM_PROGRAM) revert NotSystemOwned(key);
        s.owner = owner;
    }

    function _debit(bytes32 key, uint64 lamports, address who) private {
        if (!signs(key, who)) revert NotSigner(key);
        Stored storage s = accounts_[key];
        if (s.owner != SYSTEM_PROGRAM) revert NotSystemOwned(key);
        if (s.lamports < lamports) revert InsufficientLamports(key, s.lamports, lamports);
        s.lamports -= lamports;
    }

    // ------------------------------------------------------------------ instruções

    /// @notice Processa uma instrução do programa `programId` e grava o estado final das contas.
    ///         Reverte com `ProgramFailed` (erro + log) se a instrução falhar, como uma transação
    ///         Solana falhada não muda nada.
    function invoke(bytes32 programId, AccountMeta[] calldata metas, bytes calldata data, uint64 computeUnitLimit)
        external
        returns (SolanaRuntime.Outcome memory o)
    {
        (bytes memory elf_, SolanaRuntime.Call memory c, bytes32[] memory keys) = _prepare(programId, metas, data, computeUnitLimit, msg.sender);
        o = runtime.invokeVerified(elf_, c);
        if (o.err != 0) revert ProgramFailed(o.err, o.custom, o.logs);
        for (uint256 i = 0; i < keys.length; i++) _save(keys[i], c.accounts[i], o.accounts[i]);
        emit Invoked(programId, msg.sender, o.cu, o.returnData, o.logs);
    }

    /// @notice Simula uma instrução (sem gravar nada): devolve erro, CU, log, return data e contas finais.
    function simulate(bytes32 programId, AccountMeta[] calldata metas, bytes calldata data, uint64 computeUnitLimit, address signer)
        external
        view
        returns (SolanaRuntime.Outcome memory)
    {
        (bytes memory elf_, SolanaRuntime.Call memory c, ) = _prepare(programId, metas, data, computeUnitLimit, signer);
        return runtime.invokeVerified(elf_, c);
    }

    /// @dev Carrega o programa e as contas (sem repetição) e confere as assinaturas.
    function _prepare(bytes32 programId, AccountMeta[] calldata metas, bytes calldata data, uint64 limit, address signer)
        private
        view
        returns (bytes memory elf_, SolanaRuntime.Call memory c, bytes32[] memory keys)
    {
        elf_ = elf(programId);
        if (limit == 0) limit = DEFAULT_COMPUTE_UNIT_LIMIT;
        if (limit > MAX_COMPUTE_UNIT_LIMIT) revert ComputeLimitTooHigh();
        keys = new bytes32[](metas.length);
        uint256 n;
        c.metas = new SolanaRuntime.Meta[](metas.length);
        for (uint256 i = 0; i < metas.length; i++) {
            if (metas[i].isSigner && !signs(metas[i].key, signer)) revert NotSigner(metas[i].key);
            uint256 j;
            while (j < n && keys[j] != metas[i].key) j++;
            if (j == n) keys[n++] = metas[i].key;
            c.metas[i] = SolanaRuntime.Meta(uint8(j), metas[i].isSigner, metas[i].isWritable);
        }
        assembly ("memory-safe") {
            mstore(keys, n)
        }
        c.accounts = new SolanaRuntime.Account[](n);
        for (uint256 i = 0; i < n; i++) c.accounts[i] = _load(keys[i]);
        c.programId = programId;
        c.maxCu = limit;
        c.data = data;
        c.sysvars = _sysvars();
    }

    function _load(bytes32 key) private view returns (SolanaRuntime.Account memory a) {
        // o system program é um builtin: conta executável do native loader (como no agave)
        if (key == SYSTEM_PROGRAM) return SolanaRuntime.Account(key, NATIVE_LOADER, 1, true, "system_program");
        Stored storage s = accounts_[key];
        a = SolanaRuntime.Account(key, s.owner, s.lamports, s.executable, s.data);
    }

    function _save(bytes32 key, SolanaRuntime.Account memory before, SolanaRuntime.Account memory after_) private {
        Stored storage s = accounts_[key];
        if (after_.lamports != before.lamports) s.lamports = after_.lamports;
        if (after_.owner != before.owner) s.owner = after_.owner;
        if (keccak256(after_.data) != keccak256(before.data)) s.data = after_.data;
    }

    /// @dev Clock (slot = bloco, unix_timestamp = timestamp) e Rent (valores padrão do Solana).
    function _sysvars() private view returns (SolanaVM.Sysvar[] memory sv) {
        sv = new SolanaVM.Sysvar[](2);
        uint64 slot = uint64(block.number);
        uint64 epoch = uint64(block.number / SLOTS_PER_EPOCH);
        uint64 ts = uint64(block.timestamp);
        sv[0] = SolanaVM.Sysvar(SV_CLOCK, bytes.concat(_le(slot), _le(ts), _le(epoch), _le(epoch), _le(ts)));
        // Rent { lamports_per_byte_year: 3480, exemption_threshold: 2.0 (f64), burn_percent: 50 } + padding
        sv[1] = SolanaVM.Sysvar(SV_RENT, bytes.concat(_le(3480), hex"0000000000000040", bytes1(uint8(50)), bytes7(0)));
    }

    function _le(uint64 v) private pure returns (bytes8 out) {
        for (uint256 i = 0; i < 8; i++) out |= bytes8(bytes1(uint8(v >> (8 * i)))) >> (8 * i);
    }
}
