// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {SbpfVM} from "./SbpfVM.sol";
import {CodeStore} from "./CodeStore.sol";

/// @title ProofOfExecutionToken (POE)
/// @notice Token BEP-20 cujo mint exige executar um programa sBPF dentro do interpretador
///         on-chain. O programa ("puzzle") é fixado no deploy. O minerador procura off-chain
///         um nonce que faça o programa retornar 0 e o contrato reexecuta o programa para
///         verificar. Input do puzzle:
///
///         [32 bytes seed = keccak(challenge, minerador)][u64 nonce][u64 difficultyTarget]
///
///         O challenge muda a cada mint (corrida entre mineradores, estilo 0xBitcoin) e a
///         dificuldade se reajusta a cada RETARGET_EVERY mints para mirar TARGET_SECONDS.
contract ProofOfExecutionToken is ERC20 {
    uint256 public constant MAX_SUPPLY = 21_000_000 ether;
    uint256 public constant BASE_REWARD = 50 ether;
    uint256 public constant HALVING_EVERY = 100_000;
    uint256 public constant RETARGET_EVERY = 32;
    uint256 public constant TARGET_SECONDS = 60;
    uint256 public constant COMPUTE_BUDGET = 20_000;

    address public immutable puzzle;
    bytes32 public immutable puzzleHash;

    bytes32 public challenge;
    uint64 public difficultyTarget;
    uint256 public mintCount;
    uint256 public epochStart;

    event Mined(address indexed miner, uint64 nonce, uint256 reward, uint256 computeUnits, bytes32 newChallenge);
    event Retarget(uint64 oldTarget, uint64 newTarget, uint256 elapsed);

    error InvalidProof(uint64 r0);
    error MiningFinished();

    constructor(bytes memory code, uint64 initialTarget) ERC20("Proof of Execution", "POE") {
        puzzle = CodeStore.write(code);
        puzzleHash = keccak256(code);
        difficultyTarget = initialTarget;
        challenge = keccak256(abi.encode(block.chainid, address(this), blockhash(block.number - 1)));
        epochStart = block.timestamp;
    }

    function puzzleCode() public view returns (bytes memory) {
        return CodeStore.read(puzzle);
    }

    function buildInput(address miner, uint64 nonce) public view returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encode(challenge, miner)), _le64(nonce), _le64(difficultyTarget));
    }

    /// @notice Verifica sem gastar gas (eth_call).
    function verify(address miner, uint64 nonce) external view returns (uint64 r0, uint256 computeUnits) {
        SbpfVM.Result memory res = SbpfVM.run(puzzleCode(), buildInput(miner, nonce), COMPUTE_BUDGET);
        return (res.r0, res.steps);
    }

    function currentReward() public view returns (uint256 reward) {
        uint256 halvings = mintCount / HALVING_EVERY;
        reward = halvings >= 64 ? 0 : BASE_REWARD >> halvings;
        uint256 left = MAX_SUPPLY - totalSupply();
        if (reward > left) reward = left;
    }

    function mint(uint64 nonce) external returns (uint256 reward) {
        reward = currentReward();
        if (reward == 0) revert MiningFinished();

        SbpfVM.Result memory res = SbpfVM.run(puzzleCode(), buildInput(msg.sender, nonce), COMPUTE_BUDGET);
        if (res.r0 != 0) revert InvalidProof(res.r0);

        challenge = keccak256(abi.encode(challenge, msg.sender, nonce));
        mintCount++;
        if (mintCount % RETARGET_EVERY == 0) _retarget();

        _mint(msg.sender, reward);
        emit Mined(msg.sender, nonce, reward, res.steps, challenge);
    }

    function _retarget() internal {
        uint256 elapsed = block.timestamp - epochStart;
        uint256 expected = RETARGET_EVERY * TARGET_SECONDS;
        if (elapsed < expected / 4) elapsed = expected / 4;
        if (elapsed > expected * 4) elapsed = expected * 4;
        uint256 t = (uint256(difficultyTarget) * elapsed) / expected;
        if (t > type(uint64).max) t = type(uint64).max;
        if (t == 0) t = 1;
        emit Retarget(difficultyTarget, uint64(t), block.timestamp - epochStart);
        difficultyTarget = uint64(t);
        epochStart = block.timestamp;
    }

    function _le64(uint64 x) internal pure returns (bytes8) {
        x = ((x & 0x00000000ffffffff) << 32) | (x >> 32);
        x = ((x & 0x0000ffff0000ffff) << 16) | ((x >> 16) & 0x0000ffff0000ffff);
        x = ((x & 0x00ff00ff00ff00ff) << 8) | ((x >> 8) & 0x00ff00ff00ff00ff);
        return bytes8(x);
    }
}
