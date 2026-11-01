// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {SbpfVM} from "./SbpfVM.sol";
import {BlockSeed} from "./BlockSeed.sol";
import {GolfToken} from "./GolfToken.sol";

/// @title BountyBoard — bounties de código sBPF otimizado, julgados on-chain
/// @notice Quem posta deposita o prêmio em qualquer ERC-20, queima BOUNTY_FEE em GOLF e publica um
///         programa sBPF de referência (lento, mas correto) mais casos de borda. Candidatos disputam
///         por commit-reveal: o contrato roda referência e candidato nos mesmos inputs (K aleatórios
///         derivados da seed + casos de borda) e exige r0 igual em todos; inputs em que a referência
///         falha são descartados. No prazo final ganha o menor CU total e o prêmio é pago sozinho.
///
///         Limites: só funções puras (sem syscalls/accounts). Equivalência em inputs aleatórios é
///         probabilística; os casos de borda cobrem o que o acaso não pega.
contract BountyBoard {
    using SafeERC20 for IERC20;

    uint256 public constant K_INPUTS = 4;
    uint256 public constant MAX_PROGRAM_BYTES = 256 * 8;
    uint256 public constant MAX_EDGE_INPUTS = 8;
    uint256 public constant MAX_INPUT_LEN = 256;

    SbpfVM public immutable vm;
    GolfToken public immutable token;
    uint256 public immutable BOUNTY_FEE;

    struct Bounty {
        address poster;
        IERC20 rewardToken;
        uint256 reward;
        bytes refProgram; // programa sBPF de referência
        uint64 maxCu; // limite de CU por input (vale para referência e candidatos)
        uint32 inputLen; // tamanho do input aleatório em bytes
        bytes[] edgeInputs; // casos de borda fixos
        string spec; // descrição da rotina
        uint64 commitEnd;
        uint64 revealEnd;
        bytes32 seed;
        address best;
        uint64 bestCu;
        uint64 bestCommitBlock;
        bool finalized;
    }

    struct Commit {
        bytes32 hash;
        uint64 blockNumber;
        bool revealed;
    }

    uint256 public count;
    mapping(uint256 => Bounty) internal _bounties;
    mapping(uint256 => mapping(address => Commit)) public commits;

    event Posted(uint256 indexed id, address indexed poster, address rewardToken, uint256 reward, string spec);
    event Committed(uint256 indexed id, address indexed player, bytes32 hash);
    event Revealed(uint256 indexed id, address indexed player, uint64 totalCu, bool isBest, bytes program);
    event Finalized(uint256 indexed id, address indexed winner, uint64 cu, uint256 reward);

    error BadParams();
    error ReferenceRejected();
    error NotCommitWindow();
    error NotRevealWindow();
    error NotOver();
    error AlreadyFinalized();
    error AlreadyCommitted();
    error AlreadyRevealed();
    error NoCommit();
    error BadReveal();
    error ProgramTooLarge();
    error ProgramRejected(uint256 inputIndex, SbpfVM.Status status, uint64 r0, uint64 expected);
    error SeedUnavailable();

    constructor(SbpfVM vm_, GolfToken token_, uint256 bountyFee) {
        vm = vm_;
        token = token_;
        BOUNTY_FEE = bountyFee;
    }

    // ------------------------------------------------------------------ postar

    struct PostParams {
        IERC20 rewardToken; // qualquer ERC-20 (USDC, por exemplo)
        uint256 reward;
        bytes refProgram; // programa sBPF de referência (precisa passar no verificador)
        uint64 maxCu; // limite de CU por input
        uint32 inputLen; // tamanho em bytes dos inputs aleatórios (múltiplo de 8 recomendado)
        bytes[] edgeInputs; // casos de borda fixos (até MAX_EDGE_INPUTS)
        string spec; // descrição da rotina
        uint64 commitBlocks;
        uint64 revealBlocks; // <= 8000 (o hash do bloco commitEnd precisa existir no primeiro reveal; EIP-2935)
    }

    /// @notice Publica um bounty. Transfere `reward` de `rewardToken` para o contrato e queima
    ///         BOUNTY_FEE em GOLF do remetente.
    function post(PostParams calldata p) external returns (uint256 id) {
        if (
            p.reward == 0 || p.maxCu == 0 || p.inputLen > MAX_INPUT_LEN || p.edgeInputs.length > MAX_EDGE_INPUTS
                || p.commitBlocks == 0 || p.revealBlocks == 0 || p.revealBlocks > BlockSeed.MAX_REVEAL_BLOCKS
                || p.refProgram.length > MAX_PROGRAM_BYTES
        ) revert BadParams();
        if (!vm.verify(p.refProgram)) revert ReferenceRejected();
        for (uint256 i = 0; i < p.edgeInputs.length; i++) {
            if (p.edgeInputs[i].length > MAX_INPUT_LEN) revert BadParams();
        }

        if (BOUNTY_FEE > 0) token.burnFrom(msg.sender, BOUNTY_FEE);
        p.rewardToken.safeTransferFrom(msg.sender, address(this), p.reward);

        id = count++;
        Bounty storage b = _bounties[id];
        b.poster = msg.sender;
        b.rewardToken = p.rewardToken;
        b.reward = p.reward;
        b.refProgram = p.refProgram;
        b.maxCu = p.maxCu;
        b.inputLen = p.inputLen;
        for (uint256 i = 0; i < p.edgeInputs.length; i++) b.edgeInputs.push(p.edgeInputs[i]);
        b.spec = p.spec;
        b.commitEnd = uint64(block.number) + p.commitBlocks;
        b.revealEnd = b.commitEnd + p.revealBlocks;
        emit Posted(id, msg.sender, address(p.rewardToken), p.reward, p.spec);
    }

    // ------------------------------------------------------------------ disputar

    function commitHash(address player, uint256 id, bytes calldata program, bytes32 salt) external pure returns (bytes32) {
        return keccak256(abi.encode(player, id, keccak256(program), salt));
    }

    function commit(uint256 id, bytes32 hash) external {
        Bounty storage b = _bounties[id];
        if (b.poster == address(0) || block.number > b.commitEnd) revert NotCommitWindow();
        Commit storage c = commits[id][msg.sender];
        if (c.hash != bytes32(0)) revert AlreadyCommitted();
        c.hash = hash;
        c.blockNumber = uint64(block.number);
        emit Committed(id, msg.sender, hash);
    }

    function reveal(uint256 id, bytes calldata program, bytes32 salt) external returns (uint64 totalCu) {
        Bounty storage b = _bounties[id];
        if (block.number <= b.commitEnd || block.number > b.revealEnd) revert NotRevealWindow();
        Commit storage c = commits[id][msg.sender];
        if (c.hash == bytes32(0)) revert NoCommit();
        if (c.revealed) revert AlreadyRevealed();
        if (keccak256(abi.encode(msg.sender, id, keccak256(program), salt)) != c.hash) revert BadReveal();
        if (program.length > MAX_PROGRAM_BYTES) revert ProgramTooLarge();
        c.revealed = true;
        if (b.seed == bytes32(0)) {
            b.seed = BlockSeed.hashOf(b.commitEnd);
            if (b.seed == bytes32(0)) revert SeedUnavailable();
        }

        totalCu = judge(id, b.seed, program);

        bool isBest = b.best == address(0) || totalCu < b.bestCu
            || (totalCu == b.bestCu && c.blockNumber < b.bestCommitBlock);
        if (isBest) {
            b.best = msg.sender;
            b.bestCu = totalCu;
            b.bestCommitBlock = c.blockNumber;
        }
        emit Revealed(id, msg.sender, totalCu, isBest, program);
    }

    /// @notice Roda referência e candidato nos K inputs aleatórios + casos de borda. Inputs em que a
    ///         referência falha são descartados; o candidato precisa acertar todos os restantes.
    function judge(uint256 id, bytes32 seed, bytes calldata program) public view returns (uint64 totalCu) {
        Bounty storage b = _bounties[id];
        bytes memory refProgram = b.refProgram;
        uint256 total = K_INPUTS + b.edgeInputs.length;
        uint256 used;
        for (uint256 i = 0; i < total; i++) {
            bytes memory input = i < K_INPUTS ? _randomBytes(seed, i, b.inputLen) : b.edgeInputs[i - K_INPUTS];
            (SbpfVM.Status rs, uint64 want,) = vm.run(refProgram, input, b.maxCu);
            if (rs != SbpfVM.Status.Ok) continue;
            (SbpfVM.Status status, uint64 r0, uint64 cu) = vm.run(program, input, b.maxCu);
            if (status != SbpfVM.Status.Ok || r0 != want) revert ProgramRejected(i, status, r0, want);
            totalCu += cu;
            used++;
        }
        if (used == 0) revert ProgramRejected(type(uint256).max, SbpfVM.Status.Invalid, 0, 0);
    }

    /// @notice Paga o vencedor (ou devolve o prêmio a quem postou, se ninguém venceu).
    function finalize(uint256 id) external {
        Bounty storage b = _bounties[id];
        if (block.number <= b.revealEnd) revert NotOver();
        if (b.finalized) revert AlreadyFinalized();
        b.finalized = true;
        address to = b.best != address(0) ? b.best : b.poster;
        b.rewardToken.safeTransfer(to, b.reward);
        emit Finalized(id, b.best, b.bestCu, b.reward);
    }

    // ------------------------------------------------------------------ leitura

    /// @notice Usado pelo SbpfGolf quando um bounty é escolhido como tarefa da rodada.
    function referenceSpec(uint256 id) external view returns (bool active, bytes memory program, uint64 maxCu, uint32 inputLen) {
        Bounty storage b = _bounties[id];
        active = b.poster != address(0) && !b.finalized;
        return (active, b.refProgram, b.maxCu, b.inputLen);
    }

    function bounty(uint256 id) external view returns (Bounty memory) {
        return _bounties[id];
    }

    function _randomBytes(bytes32 seed, uint256 k, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i += 32) {
            bytes32 h = keccak256(abi.encode(seed, k, i));
            for (uint256 j = 0; j < 32 && i + j < len; j++) out[i + j] = h[j];
        }
    }
}
