// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {OFT} from "@layerzerolabs/oft-evm/contracts/OFT.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @dev Só para testes: o OFT do outro lado da ponte (faz o papel do token na Solana, com 9 casas
///      como um mint SPL comum). O formato da mensagem OFT é o mesmo em todas as redes.
contract RemoteOftMock is OFT {
    constructor(address endpoint_, address owner_) OFT("Token na Solana", "TSOL", endpoint_, owner_) Ownable(owner_) {}

    function decimals() public pure override returns (uint8) {
        return 9;
    }

    function mintTo(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
}
