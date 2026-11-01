// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";

/// @title GolfToken (GOLF) — prêmio e taxa do CU Golf
/// @notice ERC-20 padrão (OpenZeppelin). Só o `minter` (o contrato SbpfGolf) pode emitir, até
///         MAX_SUPPLY. Queimas acontecem via `burnFrom`/`burn` do ERC20Burnable.
///         Sem funções de admin além de definir o minter uma única vez.
contract GolfToken is ERC20, ERC20Burnable {
    uint256 public constant MAX_SUPPLY = 21_000_000 ether;

    address public minter;
    address public immutable deployer;

    error NotMinter();
    error MinterAlreadySet();
    error MaxSupplyExceeded();

    constructor() ERC20("CU Golf", "GOLF") {
        deployer = msg.sender;
    }

    /// @notice Define o minter uma única vez (chamado pelo deployer logo após o deploy do SbpfGolf).
    function setMinter(address minter_) external {
        if (msg.sender != deployer || minter != address(0)) revert MinterAlreadySet();
        minter = minter_;
    }

    function mint(address to, uint256 amount) external {
        if (msg.sender != minter) revert NotMinter();
        if (totalSupply() + amount > MAX_SUPPLY) revert MaxSupplyExceeded();
        _mint(to, amount);
    }
}
