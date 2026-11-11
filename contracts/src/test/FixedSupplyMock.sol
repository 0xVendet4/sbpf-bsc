// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @dev Só para testes: faz o papel do token na Solana. Supply fixo criado uma vez, 9 casas como
///      um mint SPL comum, sem função de mint nem de burn.
contract FixedSupplyMock is ERC20 {
    constructor(address to, uint256 supply) ERC20("Token na Solana", "TSOL") {
        _mint(to, supply);
    }

    function decimals() public pure override returns (uint8) {
        return 9;
    }
}
