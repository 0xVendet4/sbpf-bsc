// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice Hash de um bloco passado, para usar como seed de rodada.
/// @dev `blockhash` só enxerga os últimos 256 blocos (~2 min na BSC, 0,45 s/bloco). Para janelas de
///      reveal maiores, lê o contrato de histórico da EIP-2935 (ativo na BSC desde o hardfork Pascal),
///      que guarda os últimos 8191 hashes (~1 h na BSC). Devolve 0 se o hash não estiver disponível.
library BlockSeed {
    address internal constant HISTORY = 0x0000F90827F1C53a10cb7A02335B175320002935;
    uint256 internal constant HISTORY_WINDOW = 8191;
    /// Janela de reveal máxima: todo reveal dentro dela ainda acha blockhash(commitEnd).
    uint64 internal constant MAX_REVEAL_BLOCKS = 8000;

    function hashOf(uint256 n) internal view returns (bytes32 h) {
        h = blockhash(n);
        if (h == bytes32(0) && n < block.number && block.number - n <= HISTORY_WINDOW) {
            (bool ok, bytes memory ret) = HISTORY.staticcall(abi.encode(n));
            if (ok && ret.length == 32) h = abi.decode(ret, (bytes32));
        }
    }
}
