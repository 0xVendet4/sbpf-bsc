// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SbpfVM} from "./SbpfVM.sol";

/// @title SbpfDispute — prova de fraude de um passo para execuções sBPF
/// @notice Alguém afirma: "execute(program, input, maxCu) para após `steps` instruções no estado
///         `endHash`" e deposita uma caução. Qualquer um pode contestar com a mesma caução. Os dois
///         então dividem o intervalo de instruções ao meio até sobrar uma única instrução: quem
///         afirmou posta o hash do estado no meio, quem contestou diz de que lado discorda. No fim,
///         o SbpfVM executa só essa instrução on-chain (`step`, ~50k gas) e decide. Quem não joga
///         dentro do prazo perde. O vencedor leva as duas cauções.
///
///         Afirmações não contestadas na janela viram `Confirmed` e podem ser usadas por outros
///         contratos (`result(id)`), que assim obtêm o resultado de um programa Solana sem rodá-lo
///         inteiro on-chain.
///
/// @dev O estado inicial é fixo (`vm.initialState()`); programa é conferido pelo verificador na
///      afirmação; input entra só por hash e é apresentado inteiro no passo final.
contract SbpfDispute {
    enum Phase {
        Open, // afirmado, janela de contestação aberta
        Bisecting, // em disputa: quem afirmou deve postar o meio
        Choosing, // em disputa: quem contestou deve escolher o lado
        Proving, // sobrou uma instrução: quem afirmou deve provar
        Confirmed,
        Rejected
    }

    struct Claim {
        address asserter;
        address challenger;
        bytes32 programHash;
        bytes32 inputHash;
        uint64 maxCu;
        uint64 steps;
        bytes32 endHash;
        uint64 deadline; // bloco limite da jogada atual (ou fim da janela de contestação)
        Phase phase;
        // bisseção: o estado após `lo` instruções tem hash `loHash` (acordado) e após `hi`, `hiHash` (disputado)
        uint64 lo;
        uint64 hi;
        bytes32 loHash;
        bytes32 hiHash;
        bytes32 midHash;
    }

    SbpfVM public immutable vm;
    uint256 public immutable BOND;
    uint64 public immutable CHALLENGE_BLOCKS; // janela para contestar
    uint64 public immutable MOVE_BLOCKS; // prazo de cada jogada
    bytes32 public immutable START_HASH;

    uint256 public count;
    mapping(uint256 => Claim) internal _claims;

    event Asserted(uint256 indexed id, address indexed asserter, bytes32 programHash, bytes32 inputHash, uint64 maxCu, uint64 steps, bytes32 endHash);
    event Challenged(uint256 indexed id, address indexed challenger);
    event Bisected(uint256 indexed id, uint64 mid, bytes32 midHash);
    event Chosen(uint256 indexed id, uint64 lo, uint64 hi);
    event Resolved(uint256 indexed id, bool confirmed, address winner);

    error BadBond();
    error BadClaim();
    error WrongPhase();
    error NotYourMove();
    error Expired();
    error NotExpired();
    error BadProof();

    constructor(SbpfVM vm_, uint256 bond, uint64 challengeBlocks, uint64 moveBlocks) {
        vm = vm_;
        BOND = bond;
        CHALLENGE_BLOCKS = challengeBlocks;
        MOVE_BLOCKS = moveBlocks;
        START_HASH = vm_.stateHash(vm_.initialState());
    }

    // ------------------------------------------------------------------ afirmação e contestação

    /// @notice Afirma o resultado de `execute(program, input, maxCu)`.
    /// @param program  bytecode (passa pelo verificador aqui; só o hash fica guardado)
    /// @param inputHash keccak256 do input
    /// @param steps    instruções executadas até parar (inclui a que parou)
    /// @param endHash  `vm.stateHash` do estado final, com `halted = true`
    function assertRun(bytes calldata program, bytes32 inputHash, uint64 maxCu, uint64 steps, bytes32 endHash)
        external
        payable
        returns (uint256 id)
    {
        if (msg.value != BOND) revert BadBond();
        if (steps == 0 || steps > uint64(maxCu) + 1 || !vm.verify(program)) revert BadClaim();
        id = count++;
        Claim storage c = _claims[id];
        c.asserter = msg.sender;
        c.programHash = keccak256(program);
        c.inputHash = inputHash;
        c.maxCu = maxCu;
        c.steps = steps;
        c.endHash = endHash;
        c.deadline = uint64(block.number) + CHALLENGE_BLOCKS;
        emit Asserted(id, msg.sender, c.programHash, inputHash, maxCu, steps, endHash);
    }

    function challenge(uint256 id) external payable {
        Claim storage c = _claims[id];
        if (msg.value != BOND) revert BadBond();
        if (c.phase != Phase.Open) revert WrongPhase();
        if (block.number > c.deadline) revert Expired();
        c.challenger = msg.sender;
        c.lo = 0;
        c.hi = c.steps;
        c.loHash = START_HASH;
        c.hiHash = c.endHash;
        _next(c, c.steps == 1 ? Phase.Proving : Phase.Bisecting);
        emit Challenged(id, msg.sender);
    }

    // ------------------------------------------------------------------ bisseção

    /// @notice Quem afirmou posta o hash do estado após `(lo + hi) / 2` instruções.
    function bisect(uint256 id, bytes32 midHash) external {
        Claim storage c = _claims[id];
        if (c.phase != Phase.Bisecting) revert WrongPhase();
        if (msg.sender != c.asserter) revert NotYourMove();
        if (block.number > c.deadline) revert Expired();
        c.midHash = midHash;
        _next(c, Phase.Choosing);
        emit Bisected(id, (c.lo + c.hi) / 2, midHash);
    }

    /// @notice Quem contestou escolhe: `left` = discorda do meio (o erro está em [lo, mid]);
    ///         senão concorda com o meio e o erro está em [mid, hi].
    function choose(uint256 id, bool left) external {
        Claim storage c = _claims[id];
        if (c.phase != Phase.Choosing) revert WrongPhase();
        if (msg.sender != c.challenger) revert NotYourMove();
        if (block.number > c.deadline) revert Expired();
        uint64 mid = (c.lo + c.hi) / 2;
        if (left) {
            c.hi = mid;
            c.hiHash = c.midHash;
        } else {
            c.lo = mid;
            c.loHash = c.midHash;
        }
        _next(c, c.hi - c.lo == 1 ? Phase.Proving : Phase.Bisecting);
        emit Chosen(id, c.lo, c.hi);
    }

    /// @notice Passo final: executa a instrução `lo` on-chain. Qualquer um pode chamar; o resultado
    ///         decide a disputa a favor de quem estiver certo.
    /// @param pre   estado após `lo` instruções (seu hash tem que ser `loHash`)
    /// @param stack pilha desse estado
    function prove(uint256 id, SbpfVM.State calldata pre, bytes calldata stack, bytes calldata program, bytes calldata input) external {
        Claim storage c = _claims[id];
        if (c.phase != Phase.Proving) revert WrongPhase();
        if (block.number > c.deadline) revert Expired();
        if (keccak256(program) != c.programHash || keccak256(input) != c.inputHash) revert BadProof();
        if (vm.stateHash(pre) != c.loHash) revert BadProof();
        // `step` reverte se `pre` já estiver parado ou a pilha não bater: quem afirmou não consegue
        // provar e perde por prazo. Quem contestou pode chamar para encerrar antes, se o passo
        // mostrar o erro.
        SbpfVM.State memory post = vm.step(pre, stack, program, input, c.maxCu);
        bool ok = vm.stateHash(post) == c.hiHash;
        // o último estado afirmado tem que estar parado
        if (ok && c.hi == c.steps && !post.halted) ok = false;
        _resolve(id, c, ok);
    }

    /// @notice Quem deveria jogar não jogou no prazo: perde. Na fase Open, encerra a janela e
    ///         confirma a afirmação.
    function timeout(uint256 id) external {
        Claim storage c = _claims[id];
        if (block.number <= c.deadline) revert NotExpired();
        if (c.phase == Phase.Open) return _resolve(id, c, true);
        if (c.phase == Phase.Bisecting || c.phase == Phase.Proving) return _resolve(id, c, false);
        if (c.phase == Phase.Choosing) return _resolve(id, c, true);
        revert WrongPhase();
    }

    // ------------------------------------------------------------------ leitura

    function claim(uint256 id) external view returns (Claim memory) {
        return _claims[id];
    }

    /// @notice Resultado confirmado (reverte se a afirmação não estiver confirmada).
    function result(uint256 id) external view returns (bytes32 programHash, bytes32 inputHash, uint64 maxCu, bytes32 endHash) {
        Claim storage c = _claims[id];
        if (c.phase != Phase.Confirmed) revert WrongPhase();
        return (c.programHash, c.inputHash, c.maxCu, c.endHash);
    }

    // ------------------------------------------------------------------ internos

    function _next(Claim storage c, Phase p) internal {
        c.phase = p;
        c.deadline = uint64(block.number) + MOVE_BLOCKS;
    }

    function _resolve(uint256 id, Claim storage c, bool confirmed) internal {
        address winner = confirmed ? c.asserter : c.challenger;
        uint256 pot = c.challenger == address(0) ? BOND : 2 * BOND;
        c.phase = confirmed ? Phase.Confirmed : Phase.Rejected;
        emit Resolved(id, confirmed, winner);
        (bool sent,) = winner.call{value: pot}("");
        require(sent, "pay");
    }
}
