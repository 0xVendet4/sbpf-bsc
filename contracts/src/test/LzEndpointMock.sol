// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MessagingParams, MessagingReceipt, MessagingFee, Origin} from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import {ILayerZeroReceiver} from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroReceiver.sol";

/// @dev Só para testes: endpoint LayerZero V2 mínimo (o EndpointV2Mock oficial passa de 24 KB e não
///      dá para publicar com o limite de tamanho ligado). Cobra uma taxa fixa e entrega a mensagem
///      na mesma transação ao endpoint da outra rede, que chama `lzReceive` no OApp de destino com o
///      gás pedido nas opções tipo 3. Uma falha no destino reverte tudo (na LayerZero de verdade a
///      mensagem ficaria guardada para nova tentativa).
contract LzEndpointMock {
    uint32 public immutable eid;
    uint256 public constant FEE = 1e15;
    mapping(uint32 => LzEndpointMock) public remote;
    mapping(address => mapping(uint32 => mapping(bytes32 => uint64))) public outboundNonce;
    mapping(address => address) public delegates;

    constructor(uint32 eid_) {
        eid = eid_;
    }

    function setRemote(uint32 dstEid, LzEndpointMock endpoint) external {
        remote[dstEid] = endpoint;
    }

    function setDelegate(address delegate) external {
        delegates[msg.sender] = delegate;
    }

    function quote(MessagingParams calldata, address) external pure returns (MessagingFee memory) {
        return MessagingFee(FEE, 0);
    }

    function send(MessagingParams calldata p, address refund) external payable returns (MessagingReceipt memory r) {
        require(msg.value >= FEE, "LzEndpointMock: taxa");
        if (msg.value > FEE) {
            (bool ok,) = refund.call{value: msg.value - FEE}("");
            require(ok, "LzEndpointMock: troco");
        }
        bytes32 sender = bytes32(uint256(uint160(msg.sender)));
        uint64 nonce = ++outboundNonce[msg.sender][p.dstEid][p.receiver];
        bytes32 guid = keccak256(abi.encodePacked(nonce, eid, sender, p.dstEid, p.receiver));
        r = MessagingReceipt(guid, nonce, MessagingFee(FEE, 0));
        // opções tipo 3: 0x0003 | executor 01 | tamanho 0011 | lzReceive 01 | gás (uint128)
        uint128 gasLimit = uint128(bytes16(p.options[6:22]));
        remote[p.dstEid].deliver(Origin(eid, sender, nonce), address(uint160(uint256(p.receiver))), guid, p.message, gasLimit);
    }

    function deliver(Origin calldata origin, address receiver, bytes32 guid, bytes calldata message, uint128 gasLimit) external {
        ILayerZeroReceiver(receiver).lzReceive{gas: gasLimit}(origin, guid, message, msg.sender, "");
    }
}
