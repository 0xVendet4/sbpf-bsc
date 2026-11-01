// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SbpfVM} from "./SbpfVM.sol";
import {Tasks} from "./Tasks.sol";
import {GolfToken} from "./GolfToken.sol";

interface IBountyBoard {
    function referenceSpec(uint256 id) external view returns (bool active, bytes memory program, uint64 maxCu, uint32 inputLen);
}

/// @title SbpfGolf — "CU Golf": mint exige rodar programas Solana dentro do contrato
/// @notice Rodadas de commit-reveal. A tarefa da rodada é conhecida antes do commit. Cada jogador
///         comita o hash do seu programa sBPF (e paga a taxa de entrada em GOLF); depois revela o
///         programa, que é verificado e executado pelo SbpfVM em K inputs derivados de uma seed
///         (blockhash do último bloco de commit, desconhecida na hora do commit). Ganha quem gastar
///         menos compute units com todas as respostas certas. Empate: commit mais antigo.
///
///         Seção 6.1 (taxa de entrada): parte queimada, resto vai para o prêmio da rodada.
///         Seção 6.3 (leilão da próxima tarefa): a maior oferta em GOLF escolhe a tarefa seguinte
///         (uma da lista ou um bounty ativo do BountyBoard); a oferta vencedora é queimada e as
///         perdedoras são devolvidas (pull: `claimRefund`).
///
/// @dev Tarefas: 0..NUM_TASKS-1 são as nativas (Tasks.sol); BOUNTY_TASK_BASE + id usa o programa
///      de referência do bounty como oráculo de correção.
contract SbpfGolf {
    // ------------------------------------------------------------------ parâmetros
    uint256 public constant K_INPUTS = 4;
    uint64 public constant MAX_CU_PER_INPUT = 5_000;
    uint256 public constant MAX_PROGRAM_BYTES = 256 * 8;
    uint256 public constant BOUNTY_TASK_BASE = 1_000;

    uint256 public constant BASE_REWARD = 100 ether;
    uint256 public constant HALVING_ROUNDS = 1_000;

    uint256 public immutable ENTRY_FEE;
    uint256 public immutable ENTRY_BURN_BPS; // parte da taxa queimada (resto vai para o prêmio)
    uint256 public immutable FREE_ROUNDS; // rodadas iniciais sem taxa (ninguém tem GOLF antes do 1º mint)
    uint64 public immutable COMMIT_BLOCKS;
    uint64 public immutable REVEAL_BLOCKS;

    SbpfVM public immutable vm;
    GolfToken public immutable token;
    IBountyBoard public bountyBoard; // definido uma vez pelo deployer

    // ------------------------------------------------------------------ estado
    struct Round {
        uint256 task;
        uint64 commitEnd; // último bloco em que se pode comitar
        uint64 revealEnd; // último bloco em que se pode revelar
        bytes32 seed; // blockhash(commitEnd), gravada no primeiro reveal
        address best;
        uint64 bestCu;
        uint64 bestCommitBlock;
        uint256 prize; // taxas de entrada acumuladas (GOLF) desta rodada
        bool finalized;
        // leilão da próxima tarefa
        address topBidder;
        uint256 topBid;
        uint256 topChoice;
    }

    struct Commit {
        bytes32 hash;
        uint64 blockNumber;
        bool revealed;
    }

    struct Bid {
        uint256 choice;
        uint256 amount;
        bool refunded;
    }

    uint256 public round;
    uint256 public carry; // prêmio não distribuído (sem vencedor) que passa para a rodada seguinte
    address public immutable deployer;
    mapping(uint256 => Round) public rounds;
    mapping(uint256 => mapping(address => Commit)) public commits;
    mapping(uint256 => mapping(address => Bid)) public bids;

    // ------------------------------------------------------------------ eventos / erros
    event RoundStarted(uint256 indexed round, uint256 task, uint64 commitEnd, uint64 revealEnd);
    event Committed(uint256 indexed round, address indexed player, bytes32 hash);
    event Revealed(uint256 indexed round, address indexed player, uint64 totalCu, bool isBest, bytes program);
    event Finalized(uint256 indexed round, address indexed winner, uint64 cu, uint256 reward, uint256 prize);
    event BidPlaced(uint256 indexed round, address indexed bidder, uint256 choice, uint256 total);
    event BidRefunded(uint256 indexed round, address indexed bidder, uint256 amount);

    error NotCommitWindow();
    error NotRevealWindow();
    error RoundNotOver();
    error AlreadyFinalized();
    error AlreadyCommitted();
    error AlreadyRevealed();
    error NoCommit();
    error BadReveal();
    error ProgramTooLarge();
    error ProgramRejected(uint256 inputIndex, SbpfVM.Status status, uint64 r0, uint64 expected);
    error BidTooLow(uint256 topBid);
    error InvalidChoice();
    error NothingToRefund();
    error NotDeployer();
    error RevealWindowTooLong();

    constructor(
        SbpfVM vm_,
        GolfToken token_,
        uint256 entryFee_,
        uint256 entryBurnBps,
        uint256 freeRounds,
        uint64 commitBlocks,
        uint64 revealBlocks
    ) {
        if (revealBlocks == 0 || revealBlocks > 250 || commitBlocks == 0 || entryBurnBps > 10_000) revert RevealWindowTooLong();
        vm = vm_;
        token = token_;
        ENTRY_FEE = entryFee_;
        ENTRY_BURN_BPS = entryBurnBps;
        FREE_ROUNDS = freeRounds;
        COMMIT_BLOCKS = commitBlocks;
        REVEAL_BLOCKS = revealBlocks;
        deployer = msg.sender;
        _startRound(1, 1 % Tasks.NUM_TASKS);
    }

    function setBountyBoard(IBountyBoard board) external {
        if (msg.sender != deployer || address(bountyBoard) != address(0)) revert NotDeployer();
        bountyBoard = board;
    }

    // ------------------------------------------------------------------ jogo

    /// @notice Hash que o jogador deve comitar.
    function commitHash(address player, uint256 round_, bytes calldata program, bytes32 salt) external pure returns (bytes32) {
        return keccak256(abi.encode(player, round_, keccak256(program), salt));
    }

    /// @notice Comita `keccak256(abi.encode(msg.sender, round, keccak256(program), salt))` e paga a taxa.
    function commit(bytes32 hash) external {
        Round storage r = rounds[round];
        if (block.number > r.commitEnd) revert NotCommitWindow();
        Commit storage c = commits[round][msg.sender];
        if (c.hash != bytes32(0)) revert AlreadyCommitted();
        c.hash = hash;
        c.blockNumber = uint64(block.number);

        uint256 fee = entryFee();
        if (fee > 0) {
            uint256 burn = (fee * ENTRY_BURN_BPS) / 10_000;
            if (burn > 0) token.burnFrom(msg.sender, burn);
            uint256 toPrize = fee - burn;
            if (toPrize > 0) {
                token.transferFrom(msg.sender, address(this), toPrize);
                r.prize += toPrize;
            }
        }
        emit Committed(round, msg.sender, hash);
    }

    /// @notice Revela o programa. Executa em K inputs; reverte se alguma resposta estiver errada.
    /// @return totalCu compute units somadas nos K inputs
    function reveal(bytes calldata program, bytes32 salt) external returns (uint64 totalCu) {
        Round storage r = rounds[round];
        if (block.number <= r.commitEnd || block.number > r.revealEnd) revert NotRevealWindow();
        Commit storage c = commits[round][msg.sender];
        if (c.hash == bytes32(0)) revert NoCommit();
        if (c.revealed) revert AlreadyRevealed();
        if (keccak256(abi.encode(msg.sender, round, keccak256(program), salt)) != c.hash) revert BadReveal();
        if (program.length > MAX_PROGRAM_BYTES) revert ProgramTooLarge();
        c.revealed = true;

        if (r.seed == bytes32(0)) {
            // ninguém conhecia este hash durante a janela de commit
            r.seed = blockhash(r.commitEnd);
        }

        totalCu = judge(r.task, r.seed, program);

        bool isBest = r.best == address(0) || totalCu < r.bestCu
            || (totalCu == r.bestCu && c.blockNumber < r.bestCommitBlock);
        if (isBest) {
            r.best = msg.sender;
            r.bestCu = totalCu;
            r.bestCommitBlock = c.blockNumber;
        }
        emit Revealed(round, msg.sender, totalCu, isBest, program);
    }

    /// @notice Executa `program` nos K inputs da tarefa e devolve a soma de CU. Reverte com
    ///         `ProgramRejected` se alguma execução falhar ou responder errado.
    function judge(uint256 task, bytes32 seed, bytes calldata program) public view returns (uint64 totalCu) {
        bool isBounty = task >= BOUNTY_TASK_BASE;
        bytes memory refProgram;
        uint64 refMaxCu;
        uint32 inputLen;
        if (isBounty) {
            bool active;
            (active, refProgram, refMaxCu, inputLen) = bountyBoard.referenceSpec(task - BOUNTY_TASK_BASE);
            if (!active) revert InvalidChoice();
        }

        uint256 used;
        for (uint256 k = 0; k < K_INPUTS; k++) {
            bytes memory input;
            uint64 want;
            if (isBounty) {
                input = _randomBytes(seed, k, inputLen);
                (SbpfVM.Status rs, uint64 rr0,) = vm.run(refProgram, input, refMaxCu);
                if (rs != SbpfVM.Status.Ok) continue; // input em que a referência falha é descartado
                want = rr0;
            } else {
                input = Tasks.inputFor(task, seed, k);
                want = Tasks.expected(task, input);
            }
            (SbpfVM.Status status, uint64 r0, uint64 cu) = vm.run(program, input, MAX_CU_PER_INPUT);
            if (status != SbpfVM.Status.Ok || r0 != want) revert ProgramRejected(k, status, r0, want);
            totalCu += cu;
            used++;
        }
        if (used == 0) revert ProgramRejected(type(uint256).max, SbpfVM.Status.Invalid, 0, 0);
    }

    /// @notice Encerra a rodada (qualquer um pode chamar depois da janela de reveal) e abre a próxima.
    function finalize() external {
        Round storage r = rounds[round];
        if (block.number <= r.revealEnd) revert RoundNotOver();
        if (r.finalized) revert AlreadyFinalized();
        r.finalized = true;

        uint256 reward = currentReward();
        uint256 prize = r.prize + carry;
        if (r.best != address(0)) {
            carry = 0;
            if (reward > 0) token.mint(r.best, reward);
            if (prize > 0) token.transfer(r.best, prize);
            emit Finalized(round, r.best, r.bestCu, reward, prize);
        } else {
            carry = prize;
            emit Finalized(round, address(0), 0, 0, 0);
        }

        // leilão: a oferta vencedora é queimada; as outras ficam disponíveis em claimRefund
        uint256 nextTask = (round + 1) % Tasks.NUM_TASKS;
        if (r.topBidder != address(0)) {
            token.burn(r.topBid);
            nextTask = r.topChoice;
            bids[round][r.topBidder].refunded = true; // nada a devolver
        }
        _startRound(round + 1, nextTask);
    }

    /// @notice Taxa de entrada da rodada atual (zero nas FREE_ROUNDS primeiras rodadas).
    function entryFee() public view returns (uint256) {
        return round <= FREE_ROUNDS ? 0 : ENTRY_FEE;
    }

    /// @notice Recompensa em GOLF da rodada atual (halving a cada HALVING_ROUNDS, limitado ao supply).
    function currentReward() public view returns (uint256 reward) {
        uint256 halvings = (round - 1) / HALVING_ROUNDS;
        reward = halvings >= 64 ? 0 : BASE_REWARD >> halvings;
        uint256 left = token.MAX_SUPPLY() - token.totalSupply();
        if (reward > left) reward = left;
    }

    // ------------------------------------------------------------------ leilão da próxima tarefa (6.3)

    /// @notice Oferece GOLF para escolher a tarefa da próxima rodada. Ofertas do mesmo endereço se
    ///         acumulam; o total precisa superar a maior oferta atual.
    /// @param choice id de tarefa nativa (0..NUM_TASKS-1) ou BOUNTY_TASK_BASE + id de bounty ativo
    function bid(uint256 choice, uint256 amount) external {
        Round storage r = rounds[round];
        if (block.number > r.revealEnd) revert RoundNotOver();
        if (!_validChoice(choice)) revert InvalidChoice();
        Bid storage b = bids[round][msg.sender];
        if (b.amount != 0 && b.choice != choice) revert InvalidChoice();
        token.transferFrom(msg.sender, address(this), amount);
        b.choice = choice;
        b.amount += amount;
        if (b.amount <= r.topBid) revert BidTooLow(r.topBid);
        r.topBid = b.amount;
        r.topBidder = msg.sender;
        r.topChoice = choice;
        emit BidPlaced(round, msg.sender, choice, b.amount);
    }

    /// @notice Devolve a oferta perdedora de uma rodada já finalizada.
    function claimRefund(uint256 round_) external {
        Round storage r = rounds[round_];
        Bid storage b = bids[round_][msg.sender];
        if (!r.finalized || b.amount == 0 || b.refunded) revert NothingToRefund();
        b.refunded = true;
        token.transfer(msg.sender, b.amount);
        emit BidRefunded(round_, msg.sender, b.amount);
    }

    // ------------------------------------------------------------------ leitura

    function currentRound() external view returns (Round memory) {
        return rounds[round];
    }

    function taskName(uint256 task) external pure returns (string memory) {
        return task >= BOUNTY_TASK_BASE ? "bounty" : Tasks.name(task);
    }

    /// @notice Inputs que serão usados no reveal (só conhecidos depois da seed).
    function inputsFor(uint256 round_) external view returns (bytes[] memory inputs) {
        Round storage r = rounds[round_];
        inputs = new bytes[](K_INPUTS);
        if (r.task >= BOUNTY_TASK_BASE) {
            (, , , uint32 inputLen) = bountyBoard.referenceSpec(r.task - BOUNTY_TASK_BASE);
            for (uint256 k = 0; k < K_INPUTS; k++) inputs[k] = _randomBytes(r.seed, k, inputLen);
        } else {
            for (uint256 k = 0; k < K_INPUTS; k++) inputs[k] = Tasks.inputFor(r.task, r.seed, k);
        }
    }

    // ------------------------------------------------------------------ internos

    function _startRound(uint256 n, uint256 task) internal {
        Round storage r = rounds[n];
        round = n;
        r.task = task;
        r.commitEnd = uint64(block.number) + COMMIT_BLOCKS;
        r.revealEnd = r.commitEnd + REVEAL_BLOCKS;
        emit RoundStarted(n, task, r.commitEnd, r.revealEnd);
    }

    function _validChoice(uint256 choice) internal view returns (bool) {
        if (choice < Tasks.NUM_TASKS) return true;
        if (choice < BOUNTY_TASK_BASE || address(bountyBoard) == address(0)) return false;
        (bool active,,,) = bountyBoard.referenceSpec(choice - BOUNTY_TASK_BASE);
        return active;
    }

    function _randomBytes(bytes32 seed, uint256 k, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i += 32) {
            bytes32 h = keccak256(abi.encode(seed, k, i));
            for (uint256 j = 0; j < 32 && i + j < len; j++) out[i + j] = h[j];
        }
    }
}
