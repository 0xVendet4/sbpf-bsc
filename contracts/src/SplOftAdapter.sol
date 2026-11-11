// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {OFTAdapter} from "@layerzerolabs/oft-evm/contracts/OFTAdapter.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title SplOftAdapter — o cofre da ponte LayerZero (OFT) de um SplBep20, sem mint e sem burn
/// @notice É o adaptador de trava e libera da própria LayerZero (`@layerzerolabs/oft-evm`), sem
///         lógica nossa: ao enviar para outra rede ele recebe os tokens de quem envia e os deixa
///         trancados aqui (`transferFrom`, precisa de `approve`); ao receber, libera daqui para o
///         destinatário (`transfer`). Nada é cunhado nem queimado.
/// @dev Modelo de supply fixo: o supply inteiro é criado uma vez em cada rede e a autoridade de mint
///      do SPL é revogada nas duas. Na rede onde o token não circula no começo (a BSC), o supply
///      nasce todo neste cofre. O que circula somando as redes é sempre o supply original, e o
///      cofre nunca fica sem saldo: o que ele precisa liberar já foi trancado no cofre da outra
///      rede. A LayerZero avisa que só deve existir um adaptador por token porque dois cofres podem
///      ficar sem liquidez; aqui isso não acontece porque cada cofre nasce com o supply inteiro.
///      O dono (`owner_`) liga os pares (`setPeer`) e configura a LayerZero; na mainnet é multisig.
///      O gás do `lzReceive` na BSC precisa cobrir um Transfer do SPL Token (~0,7 M, ou ~1,5 M
///      quando cria a conta SPL de quem recebe).
contract SplOftAdapter is OFTAdapter {
    constructor(address token_, address endpoint_, address owner_) OFTAdapter(token_, endpoint_, owner_) Ownable(owner_) {}
}
