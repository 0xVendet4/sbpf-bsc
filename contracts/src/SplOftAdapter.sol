// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MintBurnOFTAdapter} from "@layerzerolabs/oft-evm/contracts/MintBurnOFTAdapter.sol";
import {IMintableBurnable} from "@layerzerolabs/oft-evm/contracts/interfaces/IMintableBurnable.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title SplOftAdapter — a ponte LayerZero (OFT) de um SplBep20
/// @notice É o adaptador de queima e cunhagem da própria LayerZero (`@layerzerolabs/oft-evm`), sem
///         lógica nossa: ao enviar para outra rede ele chama `burn(de, valor)` no SplBep20 e ao
///         receber chama `mint(para, valor)`. Do outro lado fica o OFT do mesmo token (na Solana, o
///         mint SPL de verdade com o programa OFT), então o supply somado das redes não muda.
/// @dev `token_` é o SplBep20, que precisa ter este contrato como `bridge` e ser a autoridade de
///      mint do SPL. O dono (`owner_`) liga os pares (`setPeer`) e configura a LayerZero; na mainnet
///      isso é multisig. O gás do `lzReceive` na BSC precisa cobrir um MintTo do SPL Token
///      (~0,7 M, ou ~1,5 M quando cria a conta SPL de quem recebe).
contract SplOftAdapter is MintBurnOFTAdapter {
    constructor(address token_, address endpoint_, address owner_)
        MintBurnOFTAdapter(token_, IMintableBurnable(token_), endpoint_, owner_)
        Ownable(owner_)
    {}
}
