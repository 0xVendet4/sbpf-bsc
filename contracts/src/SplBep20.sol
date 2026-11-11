// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SolanaStore} from "./SolanaStore.sol";
import {SolanaRuntime} from "./SolanaRuntime.sol";

/// @title SplBep20 — a cara BEP-20 de um mint do SPL Token que vive no SolanaStore
/// @notice Não é um token separado nem um embrulho: não há cofre nem segundo supply. `totalSupply` e
///         `decimals` são lidos do mint SPL, `balanceOf` lê a conta de token SPL do endereço e
///         `transfer`/`transferFrom` executam a instrução Transfer do SPL Token (o binário oficial,
///         rodando no SolanaVM). Assim o mesmo token é SPL para quem fala Solana e BEP-20 para a
///         PancakeSwap e as carteiras da BSC.
/// @dev Cada endereço tem uma conta SPL (165 bytes, dono = `store.keyOf(endereço)`): a que este
///      contrato cria na primeira vez que o endereço recebe (chave `n << 160 | este contrato`) ou uma
///      conta existente ligada com `link`. O dono da conta continua podendo usá-la direto pelo
///      SolanaStore. O Store só deixa este contrato assinar Transfer de contas deste mint
///      (`forwarderMint`), e ele só assina por `from` quando `from` é quem chama ou deu allowance.
///
///      Ponte (opcional): para o token existir também na Solana, uma ponte de queima e cunhagem (por
///      exemplo o MintBurnOFTAdapter da LayerZero) chama `mint`/`burn` aqui. Quem assina a autoridade
///      de mint do SPL escolhe a ponte com `setBridge` e depois passa a autoridade para
///      `store.keyOf(este contrato)` (SetAuthority do SPL Token): a partir daí só a ponte cunha e a
///      escolha não muda mais, porque ninguém além deste contrato assina aquela chave.
contract SplBep20 {
    SolanaStore public immutable store;
    /// @notice O mint do SPL Token (chave de 32 bytes no SolanaStore).
    bytes32 public immutable splMint;
    string public name;
    string public symbol;

    bytes32 private constant TOKEN_PROGRAM = 0x06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9;
    uint64 private constant ACCOUNT_LEN = 165;
    uint64 private constant RENT = (128 + 165) * 6960; // Rent::default().minimum_balance(165)

    /// @notice Conta SPL de cada endereço (0 = ainda não tem).
    mapping(address => bytes32) public accountOf;
    mapping(address => mapping(address => uint256)) public allowance;
    /// @notice Contas SPL criadas por este contrato.
    uint96 public created;
    /// @notice Ponte que pode cunhar e queimar (0 = nenhuma).
    address public bridge;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Linked(address indexed holder, bytes32 indexed account);
    event BridgeSet(address indexed bridge);

    error InsufficientBalance(uint256 balance, uint256 needed);
    error InsufficientAllowance(uint256 allowance, uint256 needed);
    error AmountTooLarge();
    error BadAccount(bytes32 account);
    error NotBridge();
    error NotMintAuthority();

    /// @dev O BNB enviado paga o rent das contas novas (lamports = wei; 2.039.280 wei por conta).
    constructor(SolanaStore store_, bytes32 mint_, string memory name_, string memory symbol_) payable {
        store = store_;
        splMint = mint_;
        name = name_;
        symbol = symbol_;
        bytes memory d = _data(mint_);
        if (d.length != 82 || d[45] != 0x01) revert BadAccount(mint_); // Mint inicializado
    }

    receive() external payable {}

    // ------------------------------------------------------------------ leitura (do SPL)

    function decimals() external view returns (uint8) {
        return uint8(_data(splMint)[44]);
    }

    function totalSupply() external view returns (uint256) {
        return _u64(_data(splMint), 36);
    }

    /// @notice Saldo da conta SPL do endereço (0 se ela mudou de dono ou de mint fora daqui).
    function balanceOf(address holder) public view returns (uint256) {
        bytes32 k = accountOf[holder];
        if (k == 0) return 0;
        bytes memory d = _data(k);
        if (!_valid(d, holder)) return 0;
        return _u64(d, 64);
    }

    // ------------------------------------------------------------------ BEP-20

    function transfer(address to, uint256 value) external returns (bool) {
        _move(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        if (a != type(uint256).max) {
            if (a < value) revert InsufficientAllowance(a, value);
            allowance[from][msg.sender] = a - value;
        }
        _move(from, to, value);
        return true;
    }

    // ------------------------------------------------------------------ contas SPL

    /// @notice Cria (se ainda não existe) a conta SPL de quem chama, por exemplo para receber um
    ///         MintTo direto pelo SPL Token.
    function open() external returns (bytes32) {
        return _open(msg.sender);
    }

    /// @notice Passa a usar uma conta SPL que quem chama já tem (deste mint, com dono `keyOf(quem chama)`).
    function link(bytes32 account) external {
        if (store.account(account).owner != TOKEN_PROGRAM || !_valid(_data(account), msg.sender)) revert BadAccount(account);
        accountOf[msg.sender] = account;
        emit Linked(msg.sender, account);
    }

    // ------------------------------------------------------------------ ponte (queima e cunhagem)

    /// @notice Autoridade de mint do SPL (0 = nenhuma: supply fixo).
    function mintAuthority() public view returns (bytes32) {
        bytes memory d = _data(splMint);
        return d[0] == 0x01 ? _b32(d, 4) : bytes32(0); // COption<Pubkey>: tag u32 + chave
    }

    /// @notice Escolhe a ponte. Só quem assina a autoridade de mint do SPL; depois que a autoridade
    ///         passa para este contrato, a ponte fica fixa.
    function setBridge(address bridge_) external {
        bytes32 a = mintAuthority();
        if (a == 0 || !store.signs(a, msg.sender)) revert NotMintAuthority();
        bridge = bridge_;
        emit BridgeSet(bridge_);
    }

    /// @notice Cunha `value` para `to` com o MintTo do SPL Token (só a ponte; este contrato precisa
    ///         ser a autoridade de mint).
    function mint(address to, uint256 value) external returns (bool) {
        if (msg.sender != bridge) revert NotBridge();
        if (value > type(uint64).max) revert AmountTooLarge();
        if (value != 0) {
            bytes32 dst = _open(to);
            SolanaStore.AccountMeta[] memory m = new SolanaStore.AccountMeta[](3);
            m[0] = SolanaStore.AccountMeta(splMint, false, true);
            m[1] = SolanaStore.AccountMeta(dst, false, true);
            m[2] = SolanaStore.AccountMeta(store.keyOf(address(this)), true, false);
            store.invoke(TOKEN_PROGRAM, m, abi.encodePacked(uint8(7), _le64(uint64(value))), 0); // MintTo
        }
        emit Transfer(address(0), to, value);
        return true;
    }

    /// @notice Queima `value` de `from` (só a ponte): Transfer do SPL para a conta deste contrato e
    ///         Burn dela, porque o Store só deixa este contrato assinar Transfer pelos usuários.
    function burn(address from, uint256 value) external returns (bool) {
        if (msg.sender != bridge) revert NotBridge();
        if (value != 0) {
            _send(from, address(this), value);
            SolanaStore.AccountMeta[] memory m = new SolanaStore.AccountMeta[](3);
            m[0] = SolanaStore.AccountMeta(accountOf[address(this)], false, true);
            m[1] = SolanaStore.AccountMeta(splMint, false, true);
            m[2] = SolanaStore.AccountMeta(store.keyOf(address(this)), true, false);
            store.invoke(TOKEN_PROGRAM, m, abi.encodePacked(uint8(8), _le64(uint64(value))), 0); // Burn
        }
        emit Transfer(from, address(0), value);
        return true;
    }

    // ------------------------------------------------------------------ interno

    function _move(address from, address to, uint256 value) private {
        _send(from, to, value);
        emit Transfer(from, to, value);
    }

    /// @dev Transfer do SPL Token de `from` para `to`, assinado por `from` através do Store.
    function _send(address from, address to, uint256 value) private {
        if (value > type(uint64).max) revert AmountTooLarge();
        uint256 bal = balanceOf(from);
        if (bal < value) revert InsufficientBalance(bal, value);
        if (value != 0 && from != to) {
            bytes32 dst = _open(to);
            SolanaStore.AccountMeta[] memory m = new SolanaStore.AccountMeta[](3);
            m[0] = SolanaStore.AccountMeta(accountOf[from], false, true);
            m[1] = SolanaStore.AccountMeta(dst, false, true);
            m[2] = SolanaStore.AccountMeta(store.keyOf(from), true, false);
            store.invokeAs(from, m, abi.encodePacked(uint8(3), _le64(uint64(value)))); // SPL Token Transfer
        }
    }

    /// @dev Conta SPL do endereço; se não existe, cria (system program) e inicializa (InitializeAccount3).
    function _open(address holder) private returns (bytes32 k) {
        k = accountOf[holder];
        if (k != 0) return k;
        uint96 n = ++created;
        k = bytes32((uint256(n) << 160) | uint160(address(this)));
        bytes32 payer = store.keyOf(address(this));
        store.deposit{value: RENT}(payer);
        store.createAccount(payer, k, RENT, ACCOUNT_LEN, TOKEN_PROGRAM);
        SolanaStore.AccountMeta[] memory m = new SolanaStore.AccountMeta[](2);
        m[0] = SolanaStore.AccountMeta(k, false, true);
        m[1] = SolanaStore.AccountMeta(splMint, false, false);
        store.invoke(TOKEN_PROGRAM, m, abi.encodePacked(uint8(18), store.keyOf(holder)), 0); // InitializeAccount3
        accountOf[holder] = k;
        emit Linked(holder, k);
    }

    /// @dev Conta de token deste mint, inicializada (ou congelada), com dono `keyOf(holder)`.
    function _valid(bytes memory d, address holder) private view returns (bool) {
        return d.length == ACCOUNT_LEN && bytes32(d) == splMint && _b32(d, 32) == store.keyOf(holder) && (d[108] == 0x01 || d[108] == 0x02);
    }

    function _data(bytes32 key) private view returns (bytes memory) {
        return store.account(key).data;
    }

    function _u64(bytes memory d, uint256 off) private pure returns (uint256 v) {
        for (uint256 i = 0; i < 8; i++) v |= uint256(uint8(d[off + i])) << (8 * i);
    }

    function _b32(bytes memory d, uint256 off) private pure returns (bytes32 v) {
        assembly ("memory-safe") {
            v := mload(add(add(d, 32), off))
        }
    }

    function _le64(uint64 v) private pure returns (bytes8 out) {
        for (uint256 i = 0; i < 8; i++) out |= bytes8(bytes1(uint8(v >> (8 * i)))) >> (8 * i);
    }
}
