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
contract SplBep20 {
    SolanaStore public immutable store;
    bytes32 public immutable mint;
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

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Linked(address indexed holder, bytes32 indexed account);

    error InsufficientBalance(uint256 balance, uint256 needed);
    error InsufficientAllowance(uint256 allowance, uint256 needed);
    error AmountTooLarge();
    error BadAccount(bytes32 account);

    /// @dev O BNB enviado paga o rent das contas novas (lamports = wei; 2.039.280 wei por conta).
    constructor(SolanaStore store_, bytes32 mint_, string memory name_, string memory symbol_) payable {
        store = store_;
        mint = mint_;
        name = name_;
        symbol = symbol_;
        bytes memory d = _data(mint_);
        if (d.length != 82 || d[45] != 0x01) revert BadAccount(mint_); // Mint inicializado
    }

    receive() external payable {}

    // ------------------------------------------------------------------ leitura (do SPL)

    function decimals() external view returns (uint8) {
        return uint8(_data(mint)[44]);
    }

    function totalSupply() external view returns (uint256) {
        return _u64(_data(mint), 36);
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

    // ------------------------------------------------------------------ interno

    function _move(address from, address to, uint256 value) private {
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
        emit Transfer(from, to, value);
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
        m[1] = SolanaStore.AccountMeta(mint, false, false);
        store.invoke(TOKEN_PROGRAM, m, abi.encodePacked(uint8(18), store.keyOf(holder)), 0); // InitializeAccount3
        accountOf[holder] = k;
        emit Linked(holder, k);
    }

    /// @dev Conta de token deste mint, inicializada (ou congelada), com dono `keyOf(holder)`.
    function _valid(bytes memory d, address holder) private view returns (bool) {
        return d.length == ACCOUNT_LEN && bytes32(d) == mint && _b32(d, 32) == store.keyOf(holder) && (d[108] == 0x01 || d[108] == 0x02);
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
