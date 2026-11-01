// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @dev Imita o contrato da EIP-2935 nos testes (o Hardhat 2.22 não tem Prague): instalado com
///      hardhat_setCode no endereço oficial. Calldata de 32 bytes = número do bloco.
contract MockBlockHistory {
    mapping(uint256 => bytes32) internal _hashes;

    function set(uint256 n, bytes32 h) external {
        _hashes[n] = h;
    }

    fallback(bytes calldata data) external returns (bytes memory) {
        require(data.length == 32);
        bytes32 h = _hashes[abi.decode(data, (uint256))];
        require(h != bytes32(0));
        return abi.encode(h);
    }
}
