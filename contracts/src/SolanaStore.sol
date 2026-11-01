// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SolanaVM} from "./SolanaVM.sol";
import {SolanaRuntime} from "./SolanaRuntime.sol";
import {SolanaLoader, SolanaImage} from "./SolanaLoader.sol";

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
    SolanaLoader public immutable loader;
    /// @notice Pode publicar programas em ids que não são chaves suas (como os programas da gênese de
    ///         um validador: SPL Token em Tokenkeg...). Só em ids ainda sem conta.
    address public immutable genesis;

    bytes32 public constant SYSTEM_PROGRAM = bytes32(0);
    /// @notice BPFLoaderUpgradeab1e11111111111111111111111 (owner das contas de programa)
    bytes32 public constant BPF_LOADER = 0x02a8f6914e88a1b0e210153ef763ae2b00c2b93d16c124d2c0537a1004800000;
    /// @notice BPFLoader2111111111111111111111111111111111 (owner dos programas sBPF v0, como o SPL Token)
    bytes32 public constant BPF_LOADER_2 = 0x02a8f6914e88a16e395ae128948ffa695693376818dd47435221f3c600000000;
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
    mapping(bytes32 => address) private layout_; // programas v0: layout do SolanaLoader (SSTORE2)
    mapping(bytes32 => address) public uploader; // publicação em várias transações ainda aberta
    mapping(bytes32 => address[]) private image_; // programas v0: imagem pronta (SSTORE2), opcional
    mapping(bytes32 => bool) public imageReady; // imagem conferida contra SolanaImage.build

    event ProgramDeployed(bytes32 indexed programId, address indexed deployer, uint256 size);
    event ImageCached(bytes32 indexed programId, uint256 size);
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

    error UploadNotOpen(bytes32 programId);
    error ChunkTooBig();

    constructor(SolanaRuntime runtime_, SolanaLoader loader_) {
        runtime = runtime_;
        vm = runtime_.vm();
        loader = loader_;
        genesis = msg.sender;
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

    /// @notice Publica um programa (ELF sBPF v3 ou v0) numa chave assinada pelo remetente, numa transação.
    function deployProgram(bytes32 programId, bytes calldata elf_) external {
        _open(programId);
        for (uint256 off = 0; off < elf_.length; off += CHUNK) {
            uint256 n = elf_.length - off < CHUNK ? elf_.length - off : CHUNK;
            chunks_[programId].push(_store(elf_[off:off + n]));
        }
        elfLength[programId] = elf_.length;
        if (_finalize(programId)) _verifyV0(programId);
    }

    /// @notice Programa grande (o limite de gás por transação da BSC é 16,7M): manda o ELF em pedaços
    ///         de até 24.575 bytes, na ordem, e depois chama `finalizeProgram`.
    function writeProgram(bytes32 programId, bytes calldata chunk) external {
        if (uploader[programId] == address(0)) _open(programId);
        else if (uploader[programId] != msg.sender || layout_[programId] != address(0)) revert UploadNotOpen(programId);
        if (chunk.length == 0 || chunk.length > CHUNK) revert ChunkTooBig();
        chunks_[programId].push(_store(chunk));
        elfLength[programId] += chunk.length;
    }

    /// @notice Carrega, verifica e ativa um programa enviado com `writeProgram` (como o loader do
    ///         Solana faz uma vez, ao publicar). ELF v0: só carrega (as relocações do SolanaLoader ficam
    ///         guardadas); o verificador vai numa segunda transação, `verifyProgram` (os dois juntos
    ///         passam do limite de gás por transação da BSC num programa de 100 KB).
    function finalizeProgram(bytes32 programId) external {
        if (uploader[programId] != msg.sender || layout_[programId] != address(0)) revert UploadNotOpen(programId);
        _finalize(programId);
    }

    /// @notice Segunda etapa de um programa v0 publicado em pedaços: verifica a imagem e ativa.
    function verifyProgram(bytes32 programId) external {
        if (uploader[programId] != msg.sender || layout_[programId] == address(0)) revert UploadNotOpen(programId);
        _verifyV0(programId);
    }

    /// @dev Quem pode publicar em `programId`: o dono da chave ou a gênese; a conta tem de estar livre.
    function _open(bytes32 programId) private {
        if (!signs(programId, msg.sender) && msg.sender != genesis) revert NotSigner(programId);
        if (chunks_[programId].length != 0) revert AlreadyDeployed(programId);
        Stored storage s = accounts_[programId];
        if (s.lamports != 0 || s.data.length != 0 || s.owner != SYSTEM_PROGRAM) revert AccountInUse(programId);
        uploader[programId] = msg.sender;
    }

    /// @dev v3: verifica e ativa. v0 (e_flags = 0): guarda as relocações do SolanaLoader e devolve
    ///      true (falta `_verifyV0`).
    function _finalize(bytes32 programId) private returns (bool v0) {
        bytes memory e = elf(programId);
        if (e.length >= 64 && bytes4(e) == 0x7f454c46 && e[48] == 0 && e[49] == 0 && e[50] == 0 && e[51] == 0) {
            layout_[programId] = _storeMem(loader.load(e));
            return true;
        }
        if (!vm.verifyElf(e)) revert InvalidElf(); // carregador + verificador, uma vez só (como no Solana)
        _activate(programId, BPF_LOADER);
    }

    function _verifyV0(bytes32 programId) private {
        if (!vm.verifyElf(program(programId))) revert InvalidElf();
        _activate(programId, BPF_LOADER_2);
    }

    function _activate(bytes32 programId, bytes32 owner) private {
        Stored storage s = accounts_[programId];
        s.owner = owner;
        s.executable = true;
        delete uploader[programId];
        emit ProgramDeployed(programId, msg.sender, elfLength[programId]);
    }

    /// @notice Guarda a imagem v0 pronta (`program(programId)`, lida por eth_call) em pedaços, para
    ///         que cada instrução não precise remontá-la (~0,7M de gás a menos por programa).
    ///         `index` 0 recomeça; `finalizeImage` só aceita a imagem idêntica à remontada.
    function writeImage(bytes32 programId, uint256 index, bytes calldata chunk) external {
        if (!signs(programId, msg.sender) && msg.sender != genesis) revert NotSigner(programId);
        if (layout_[programId] == address(0) || imageReady[programId]) revert UnknownProgram(programId);
        if (chunk.length == 0 || chunk.length > CHUNK) revert ChunkTooBig();
        if (index == 0) delete image_[programId];
        else if (index != image_[programId].length) revert UploadNotOpen(programId);
        image_[programId].push(_store(chunk));
    }

    function finalizeImage(bytes32 programId) external {
        if (!signs(programId, msg.sender) && msg.sender != genesis) revert NotSigner(programId);
        bytes memory built = program(programId);
        bytes memory up = _read(image_[programId], built.length);
        if (keccak256(up) != keccak256(built)) revert InvalidElf();
        imageReady[programId] = true;
        emit ImageCached(programId, built.length);
    }

    /// @dev Concatena o código (sem o byte 0 do SSTORE2) dos contratos de `cs`.
    function _read(address[] storage cs, uint256 len) private view returns (bytes memory out) {
        out = new bytes(len);
        uint256 off;
        for (uint256 i = 0; i < cs.length; i++) {
            address c = cs[i];
            uint256 n = c.code.length - 1;
            if (off + n > len) revert InvalidElf();
            assembly ("memory-safe") {
                extcodecopy(c, add(add(out, 32), off), 1, n)
            }
            off += n;
        }
        if (off != len) revert InvalidElf();
    }

    /// @notice O que a SolanaVM executa: o ELF (v3) ou a imagem relocada (v0).
    function program(bytes32 programId) public view returns (bytes memory) {
        if (imageReady[programId]) {
            address[] storage cs = image_[programId];
            uint256 len;
            for (uint256 i = 0; i < cs.length; i++) len += cs[i].code.length - 1;
            return _read(cs, len);
        }
        bytes memory e = elf(programId);
        address l = layout_[programId];
        if (l == address(0)) return e;
        bytes memory layout = new bytes(l.code.length - 1);
        assembly ("memory-safe") {
            extcodecopy(l, add(layout, 32), 1, mload(layout))
        }
        return SolanaImage.build(e, layout);
    }

    /// @dev SSTORE2: cria um contrato cujo código é `00 || data` e devolve o endereço.
    function _store(bytes calldata data) private returns (address c) {
        return _storeMem(data);
    }

    function _storeMem(bytes memory data) private returns (address c) {
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
        o = runtime.invokeWith(elf_, c, _programs(c));
        if (o.err != 0) revert ProgramFailed(o.err, o.custom, o.logs);
        for (uint256 i = 0; i < keys.length; i++) if (!c.accounts[i].executable) _save(keys[i], c.accounts[i], o.accounts[i]);
        emit Invoked(programId, msg.sender, o.cu, o.returnData, o.logs);
    }

    /// @notice Simula uma instrução (sem gravar nada): devolve erro, CU, log, return data e contas finais.
    function simulate(bytes32 programId, AccountMeta[] calldata metas, bytes calldata data, uint64 computeUnitLimit, address signer)
        external
        view
        returns (SolanaRuntime.Outcome memory)
    {
        (bytes memory elf_, SolanaRuntime.Call memory c, ) = _prepare(programId, metas, data, computeUnitLimit, signer);
        return runtime.invokeWith(elf_, c, _programs(c));
    }

    /// @dev Carrega o programa e as contas (sem repetição) e confere as assinaturas.
    function _prepare(bytes32 programId, AccountMeta[] calldata metas, bytes calldata data, uint64 limit, address signer)
        private
        view
        returns (bytes memory elf_, SolanaRuntime.Call memory c, bytes32[] memory keys)
    {
        if (!accounts_[programId].executable) revert UnknownProgram(programId);
        elf_ = program(programId);
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
        // loader v2 (BPFLoader2111...): os dados da conta de programa são o próprio ELF
        if (s.executable && s.owner == BPF_LOADER_2) a.data = elf(key);
    }

    /// @dev Programas sBPF entre as contas da instrução: os que ela pode chamar por CPI.
    function _programs(SolanaRuntime.Call memory c) private view returns (SolanaRuntime.Program[] memory ps) {
        uint256 n;
        for (uint256 i = 0; i < c.accounts.length; i++) if (_isProgram(c.accounts[i])) n++;
        ps = new SolanaRuntime.Program[](n);
        n = 0;
        for (uint256 i = 0; i < c.accounts.length; i++) {
            if (_isProgram(c.accounts[i])) ps[n++] = SolanaRuntime.Program(c.accounts[i].key, program(c.accounts[i].key));
        }
    }

    function _isProgram(SolanaRuntime.Account memory a) private view returns (bool) {
        return a.executable && (a.owner == BPF_LOADER_2 || a.owner == BPF_LOADER) && chunks_[a.key].length != 0;
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
        // Rent::default() do agave 4.3 (bincode, 17 bytes): 6960 lamports/byte, limiar 1.0 (SIMD-0194), 50% queimado
        sv[1] = SolanaVM.Sysvar(SV_RENT, bytes.concat(_le(6960), hex"000000000000f03f", bytes1(uint8(50))));
    }

    function _le(uint64 v) private pure returns (bytes8 out) {
        for (uint256 i = 0; i < 8; i++) out |= bytes8(bytes1(uint8(v >> (8 * i)))) >> (8 * i);
    }
}
