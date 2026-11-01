// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice Guarda bytes como bytecode de um contrato (padrão SSTORE2): ler sai muito
///         mais barato que SLOAD. É assim que os "program accounts" ficam on-chain.
library CodeStore {
    error WriteFailed();

    function write(bytes memory data) internal returns (address ptr) {
        // 0x61 <size> 80 60 0a 3d 39 3d f3 | 00 <data>
        bytes memory init = abi.encodePacked(hex"61", uint16(data.length + 1), hex"80600a3d393df3", hex"00", data);
        assembly {
            ptr := create(0, add(init, 32), mload(init))
        }
        if (ptr == address(0)) revert WriteFailed();
    }

    function read(address ptr) internal view returns (bytes memory data) {
        uint256 size = ptr.code.length;
        if (size == 0) return data;
        size -= 1;
        data = new bytes(size);
        assembly {
            extcodecopy(ptr, add(data, 32), 1, size)
        }
    }
}
