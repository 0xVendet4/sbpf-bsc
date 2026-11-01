// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SolanaVM} from "./SolanaVM.sol";
import {SolanaCpi} from "./SolanaCpi.sol";
import {SolanaLog, IE} from "./SolanaLog.sol";

/// @title SolanaRuntime — a camada de contas do runtime Solana (loader v3 / ABIv1) em Solidity
/// @notice Recebe uma instrução como o agave recebe (programa, contas, metas, dados), serializa as
///         contas no formato que o programa espera (`serialize_parameters`, agave 4.3, com
///         direct mapping e ponteiros diretos), roda o programa no `SolanaVM` e aplica as regras
///         de desserialização (`deserialize_parameters`: lamports, realloc, owner, saldo) para
///         produzir o `InstructionError`, as contas finais e o log no formato do agave.
///
/// @dev Semântica: `solana-program-runtime` 4.3 (`serialization.rs`, `vm.rs`) e
///      `solana-transaction-context` 4.3 (`instruction_accounts.rs`). Conferida pelos fixtures do
///      Mollusk em `fixtures/solana/programs.json`. Uma CPI (`sol_invoke_signed_*`) suspende a VM;
///      o runtime executa a instrução chamada no `SolanaCpi` e retoma a VM. Se a CPI é para um
///      programa sBPF, o runtime roda esse programa numa chamada a si mesmo (`invokeNested`, com a
///      imagem vinda de `programs`) e devolve as contas ao `SolanaCpi.finish`. O texto do log é
///      montado pelo `SolanaLog`.
///
///      Memória: o laço de CPIs compacta o estado a cada volta (o custo de memória da EVM é
///      quadrático), e os dados de contas executáveis (o ELF de um programa, 100+ KB) não vão para a
///      VM nem para o SolanaCpi; se o programa tocar nesses bytes (nunca acontece na prática), a
///      instrução roda de novo com os dados completos, então o resultado é sempre o do agave.
contract SolanaRuntime {
    SolanaVM public immutable vm;
    SolanaCpi public immutable cpi;
    SolanaLog public immutable log;

    struct Account {
        bytes32 key;
        bytes32 owner;
        uint64 lamports;
        bool executable;
        bytes data;
    }

    /// @notice Conta da instrução: índice em `Call.accounts` + privilégios.
    struct Meta {
        uint8 account;
        bool isSigner;
        bool isWritable;
    }

    struct Call {
        bytes32 programId;
        uint64 maxCu;
        Account[] accounts;
        Meta[] metas;
        bytes data;
        SolanaVM.Sysvar[] sysvars;
    }

    /// @notice Programa sBPF que pode ser chamado por CPI: id e imagem executável (ELF v3 ou imagem v0).
    struct Program {
        bytes32 id;
        bytes image;
    }

    struct Outcome {
        uint32 err; // 0 = sucesso; senão uint32(InstructionError) + 1
        uint32 custom; // código de `Custom(n)`
        uint64 cu; // compute units cobradas (esgota em falhas da VM, como no agave)
        bytes returnData;
        string logs; // linhas no formato do agave, separadas por "\n"
        Account[] accounts; // estado final (igual ao inicial se falhou)
    }

    uint256 private constant MAX_PERMITTED_DATA_INCREASE = 10240;
    // códigos de erro de syscall do SolanaVM (SolanaVM.E_*)
    uint64 private constant E_ARITHMETIC_OVERFLOW = 10;
    uint64 private constant E_UNSUPPORTED_SYSVAR = 12;
    uint64 private constant E_INSTRUCTION = 13; // InstructionError vindo de uma syscall (CPI)
    uint256 private constant MAX_ACCOUNT_DATA_LEN = 10 * 1024 * 1024;
    uint256 private constant MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION = 2 * MAX_ACCOUNT_DATA_LEN;
    uint256 private constant MAX_ACCOUNTS_PER_INSTRUCTION = 255;
    uint64 private constant INPUT_START = 0x400000000;
    uint64 private constant STACK_START = 0x200000000;
    uint64 private constant HEAP_START = 0x300000000;
    uint64 private constant STACK_SIZE = 64 * 4096;
    uint64 private constant HEAP_SIZE = 32 * 1024;
    uint256 private constant MAX_STACK_HEIGHT = 9; // SIMD-0268 (raise_cpi_nesting_limit_to_8)
    uint8 private constant ST_ACCESS_VIOLATION = 3;
    uint8 private constant ST_CALLEE = 0xff; // SolanaCpi.ST_CALLEE
    uint64 private constant E_INSTRUCTION_ = 13;

    error BadMeta();

    constructor(SolanaVM vm_, SolanaCpi cpi_, SolanaLog log_) {
        vm = vm_;
        cpi = cpi_;
        log = log_;
    }

    // ------------------------------------------------------------------ serialização

    /// @dev Conta da instrução já posicionada na serialização.
    struct Slot {
        uint8 account; // índice em Call.accounts
        bool dup;
        uint8 dupOf; // índice do meta original (se dup)
        bool isSigner;
        bool isWritable;
        uint256 metaRegion; // região com o cabeçalho (marker, flags, key, owner, lamports, data_len)
        uint256 metaOff; // offset do marker dentro da região
        uint256 dataRegion; // região dos dados
        uint256 preLen;
        uint64 markerAddr; // endereço virtual do marker (entra na tabela de ponteiros)
        bool elided; // conta executável: os dados não foram para a VM (região vazia)
    }

    struct Ser {
        SolanaVM.Region[] regions;
        Slot[] slots;
        uint64 ixDataAddr;
    }

    /// @notice Serializa as contas da instrução (`serialize_parameters_for_abiv1` do agave com
    ///         `virtual_address_space_adjustments`, `account_data_direct_mapping` e
    ///         `direct_account_pointers_in_program_input`).
    function serialize(Call calldata c) public pure returns (Ser memory s) {
        return _serialize(c, false);
    }

    function _serialize(Call calldata c, bool elide) private pure returns (Ser memory s) {
        uint256 n = c.metas.length;
        if (n > MAX_ACCOUNTS_PER_INSTRUCTION) revert BadMeta();
        s.slots = new Slot[](n);
        uint256 nonDup;
        for (uint256 i = 0; i < n; i++) {
            if (c.metas[i].account >= c.accounts.length) revert BadMeta();
            bool dup;
            for (uint256 j = 0; j < i; j++) {
                if (c.metas[j].account == c.metas[i].account) {
                    dup = true;
                    s.slots[i].dup = true;
                    s.slots[i].dupOf = uint8(j);
                    break;
                }
            }
            if (!dup) nonDup++;
            s.slots[i].account = c.metas[i].account;
            s.slots[i].isSigner = c.metas[i].isSigner;
            s.slots[i].isWritable = c.metas[i].isWritable;
        }
        s.regions = new SolanaVM.Region[](1 + 2 * nonDup);
        uint256 ri; // próxima região
        uint64 vaddr = INPUT_START; // começo da região em construção
        bytes memory cur = abi.encodePacked(_le(uint64(n)));
        for (uint256 i = 0; i < n; i++) {
            Slot memory sl = s.slots[i];
            sl.markerAddr = vaddr + uint64(cur.length);
            if (sl.dup) {
                cur = bytes.concat(cur, bytes1(sl.dupOf), bytes7(0));
                continue;
            }
            Account calldata a = c.accounts[sl.account];
            cur = bytes.concat(
                cur, bytes1(0xff), bytes1(sl.isSigner ? 1 : 0), bytes1(sl.isWritable ? 1 : 0), bytes1(a.executable ? 1 : 0), bytes4(0),
                a.key, a.owner, _le(a.lamports), _le(uint64(a.data.length))
            );
            sl.metaRegion = ri;
            sl.metaOff = cur.length - 88;
            sl.preLen = a.data.length;
            s.regions[ri++] = SolanaVM.Region(vaddr, true, 0, cur);
            vaddr += uint64(cur.length);
            // região dos dados: gravável só se a conta for gravável e do programa; cresce até +10240
            bool w = sl.isWritable && a.owner == c.programId;
            sl.dataRegion = ri;
            sl.elided = elide && a.executable && a.data.length != 0;
            s.regions[ri++] = sl.elided
                ? SolanaVM.Region(vaddr, false, 0, "")
                : SolanaVM.Region(vaddr, w, uint64(a.data.length + MAX_PERMITTED_DATA_INCREASE), a.data);
            vaddr += uint64(a.data.length + MAX_PERMITTED_DATA_INCREASE);
            // a região seguinte começa com o alinhamento a 8 dos dados e o rent_epoch
            cur = bytes.concat(new bytes((8 - a.data.length % 8) % 8), bytes8(0xffffffffffffffff));
        }
        cur = bytes.concat(cur, _le(uint64(c.data.length)));
        s.ixDataAddr = vaddr + uint64(cur.length);
        cur = bytes.concat(cur, c.data, c.programId);
        // tabela de ponteiros (SIMD-0449), alinhada a 8
        cur = bytes.concat(cur, new bytes((8 - (vaddr + cur.length) % 8) % 8));
        for (uint256 i = 0; i < n; i++) {
            Slot memory sl = s.slots[i];
            cur = bytes.concat(cur, _le(sl.dup ? s.slots[sl.dupOf].markerAddr : sl.markerAddr));
        }
        s.regions[ri] = SolanaVM.Region(vaddr, true, 0, cur);
    }

    // ------------------------------------------------------------------ execução

    /// @notice Processa uma instrução do programa `elf` como o loader do agave faria.
    function invoke(bytes calldata elf, Call calldata c) external view returns (Outcome memory o) {
        (o, ) = _invoke(elf, c, _none(), abi.encodePacked(c.programId), true, true);
    }

    /// @notice Como `invoke`, para um ELF já verificado com `SolanaVM.verifyElf` (poupa o verificador),
    ///         com os programas sBPF que a instrução pode chamar por CPI (pode ser vazio).
    function invokeWith(bytes calldata elf, Call calldata c, Program[] calldata programs) external view returns (Outcome memory o) {
        (o, ) = _invoke(elf, c, programs, abi.encodePacked(c.programId), false, true);
    }

    /// @notice Instrução chamada por CPI. `stack` = ids dos programas na pilha de instruções (32
    ///         bytes cada, o último é `c.programId`). Devolve também o programa dono do return data.
    function invokeNested(bytes calldata elf, Call calldata c, Program[] calldata programs, bytes calldata stack)
        external
        view
        returns (Outcome memory o, bytes32 returnOwner)
    {
        return _invoke(elf, c, programs, stack, false, true);
    }

    function _none() private pure returns (Program[] calldata p) {
        assembly {
            p.offset := 0
            p.length := 0
        }
    }

    /// @dev Estado do laço de CPIs (o que sobrevive à compactação da memória).
    struct Loop {
        SolanaVM.Result r;
        SolanaCpi.Acc[] accts;
        bytes logs;
    }

    function _invoke(bytes calldata elf, Call calldata c, Program[] calldata programs, bytes memory stack, bool check, bool elide)
        private
        view
        returns (Outcome memory, bytes32)
    {
        Ser memory s = _serialize(c, elide);
        Loop memory l = _run(elf, c, programs, stack, check, s);
        if (elide && l.r.status == SolanaVM.Status.AccessViolation && _touchedElided(s, uint64(l.r.fault))) {
            return _invoke(elf, c, programs, stack, check, false); // o programa leu o ELF de uma conta: roda com tudo
        }
        return _outcome(c, s, l, stack.length / 32);
    }

    /// @dev Roda a VM e as CPIs até a instrução terminar.
    function _run(bytes calldata elf, Call calldata c, Program[] calldata programs, bytes memory stack, bool check, Ser memory s)
        private
        view
        returns (Loop memory l)
    {
        SolanaVM.Env memory env = SolanaVM.Env(c.programId, c.maxCu, s.ixDataAddr, c.sysvars);
        uint256 mark;
        assembly {
            mark := mload(0x40)
        }
        l.r = check ? vm.runElf(elf, s.regions, env) : vm.runElfVerified(elf, s.regions, env);
        l.accts = _accounts(c, s);
        l.logs = l.r.logs;
        if (l.r.status == SolanaVM.Status.Cpi) l = _compact(mark, l);
        while (l.r.status == SolanaVM.Status.Cpi) {
            _step(elf, c, programs, stack, s, env, l);
            l = _compact(mark, l);
        }
    }

    /// @dev Desserialização, erro e log da instrução terminada.
    function _outcome(Call calldata c, Ser memory s, Loop memory l, uint256 height) private view returns (Outcome memory o, bytes32 returnOwner) {
        SolanaVM.Result memory r = l.r;
        r.logs = l.logs;
        o.accounts = c.accounts;
        o.returnData = r.returnData;
        o.cu = r.cu;
        if (r.suspended.returnData.length >= 32) returnOwner = bytes32(r.suspended.returnData);
        SolanaLog.Failure memory f = _finish(c, r, s, o.accounts, l.accts);
        if (f.kind != 0) {
            o.err = uint32(f.ie) + 1;
            o.custom = f.custom;
            o.accounts = c.accounts; // nada muda em caso de erro
            if (r.status != SolanaVM.Status.Ok && r.status != SolanaVM.Status.SyscallError && !_inSyscall(r)) o.cu = c.maxCu;
        }
        o.logs = log.render(c.programId, height, l.logs, r.cu, c.maxCu, r.returnData, f); // o log mostra o que a VM contou
    }

    /// @dev Uma volta do laço: a CPI pendente (system program aqui, programa sBPF numa chamada
    ///      aninhada) e a VM retomada.
    function _step(bytes calldata elf, Call calldata c, Program[] calldata programs, bytes memory stack, Ser memory s, SolanaVM.Env memory env, Loop memory l)
        private
        view
    {
        SolanaVM.Result memory r = l.r;
        SolanaCpi.Input memory in_ = _cpiInput(elf, c, s, r, l.accts, stack.length / 32, false);
        SolanaCpi.Output memory co = cpi.invoke(in_);
        if (co.status == ST_ACCESS_VIOLATION && uint64(co.fault) < STACK_START) {
            // a CPI leu a região só leitura do programa (que não vai por padrão): de novo, com ela
            in_ = _cpiInput(elf, c, s, r, l.accts, stack.length / 32, true);
            co = cpi.invoke(in_);
        }
        l.logs = bytes.concat(l.logs, co.logs);
        bytes memory ret; // return data para a VM retomada: dono (32 bytes) || dados
        if (co.status == ST_CALLEE) {
            (co, ret) = _callee(elf, c, programs, stack, in_, co, l);
        } else if (co.returnDataCleared) {
            r.returnData = "";
        }
        l.accts = co.accounts;
        if (co.status != 0) {
            r.status = SolanaVM.Status(co.status);
            r.err = co.err;
            r.fault = co.fault;
            r.cu = co.cu;
            return;
        }
        l.r = _resume(elf, s, env, r.suspended, co, ret);
        l.logs = bytes.concat(l.logs, l.r.logs);
    }

    /// @dev CPI para um programa sBPF: roda o programa chamado (chamada aninhada) com as contas da
    ///      transação e devolve-as ao SolanaCpi (`update_caller_account`).
    function _callee(bytes calldata elf, Call calldata c, Program[] calldata programs, bytes memory stack, SolanaCpi.Input memory in_, SolanaCpi.Output memory co, Loop memory l)
        private
        view
        returns (SolanaCpi.Output memory, bytes memory ret)
    {
        Call memory cc;
        (cc.programId, cc.data) = abi.decode(co.callee, (bytes32, bytes));
        // push(): reentrância só chamando a si mesmo; a pilha não passa do limite
        if (cc.programId != c.programId && _onStack(stack, cc.programId)) return (_cpiFail(co, IE.ReentrancyNotAllowed, 0), ret);
        if (stack.length / 32 + 1 > MAX_STACK_HEIGHT) return (_cpiFail(co, IE.CallDepth, 0), ret);
        cc.maxCu = uint64(c.maxCu - co.cu);
        cc.sysvars = c.sysvars;
        _calleeAccounts(c, co, cc);
        (bool found, uint256 pi) = _program(programs, cc.programId);
        if (cc.programId == c.programId) found = true; // chamar a si mesmo: a própria imagem
        if (!found) {
            l.logs = bytes.concat(l.logs, _raw(bytes(log.notCached(cc.programId, stack.length / 32 + 1))));
            l.r.returnData = ""; // process_executable_chain já fez set_return_data(programa, [])
            return (_cpiFail(co, IE.UnsupportedProgramId, 0), ret);
        }
        Outcome memory sub;
        (sub, ret) = _nested(cc.programId == c.programId ? elf : programs[pi].image, programs, cc, bytes.concat(stack, cc.programId));
        l.logs = bytes.concat(l.logs, _raw(bytes(sub.logs)));
        l.r.returnData = sub.returnData;
        in_.cu = co.cu + sub.cu;
        if (sub.err != 0) {
            co.cu = uint64(in_.cu);
            return (_cpiFail(co, IE(uint8(sub.err - 1)), sub.custom), ret);
        }
        return (_finishCallee(in_, co, sub, l), ret);
    }

    /// @dev Roda o programa chamado numa chamada a este contrato (memória própria) e devolve o
    ///      resultado e o return data para a VM do chamador (dono || dados).
    function _nested(bytes calldata image, Program[] calldata programs, Call memory cc, bytes memory stack)
        private
        view
        returns (Outcome memory sub, bytes memory ret)
    {
        bytes32 owner;
        (sub, owner) = this.invokeNested(image, cc, _callable(programs, stack), stack);
        if (sub.returnData.length != 0) ret = abi.encodePacked(owner, sub.returnData);
    }

    /// @dev Programas que o chamado ainda pode chamar: os da pilha dariam ReentrancyNotAllowed (ou
    ///      são ele mesmo, que já vai como `elf`), então não são copiados para a chamada aninhada.
    function _callable(Program[] calldata programs, bytes memory stack) private pure returns (Program[] memory out) {
        uint256 n;
        for (uint256 i = 0; i < programs.length; i++) if (!_onStack(stack, programs[i].id)) n++;
        out = new Program[](n);
        n = 0;
        for (uint256 i = 0; i < programs.length; i++) if (!_onStack(stack, programs[i].id)) out[n++] = programs[i];
    }

    /// @dev update_caller_account: as contas como o programa chamado deixou voltam ao chamador.
    function _finishCallee(SolanaCpi.Input memory in_, SolanaCpi.Output memory co, Outcome memory sub, Loop memory l)
        private
        view
        returns (SolanaCpi.Output memory fin)
    {
        in_.accounts = co.accounts;
        in_.regions = co.regions;
        SolanaCpi.Post[] memory post = new SolanaCpi.Post[](sub.accounts.length);
        for (uint256 i = 0; i < post.length; i++) post[i] = SolanaCpi.Post(sub.accounts[i].owner, sub.accounts[i].lamports, sub.accounts[i].data);
        fin = cpi.finish(in_, co.callee, post);
        l.logs = bytes.concat(l.logs, fin.logs);
    }

    /// @dev Contas da instrução chamada: uma por chave (na ordem da primeira meta), com o estado
    ///      atual da transação (dados das regiões do chamador).
    function _calleeAccounts(Call calldata c, SolanaCpi.Output memory co, Call memory cc) private pure {
        (, , bytes32[] memory keys, uint256[] memory flags, uint256[] memory caller, uint256[] memory first, , ) =
            abi.decode(co.callee, (bytes32, bytes, bytes32[], uint256[], uint256[], uint256[], uint256[], uint256[]));
        uint256 n = keys.length;
        uint256[] memory slot = new uint256[](n); // índice em cc.accounts de cada meta
        uint256 u;
        for (uint256 i = 0; i < n; i++) if (first[i] == i) slot[i] = u++;
        cc.accounts = new Account[](u);
        cc.metas = new Meta[](n);
        for (uint256 i = 0; i < n; i++) {
            if (first[i] != i) slot[i] = slot[first[i]];
            cc.metas[i] = Meta(uint8(slot[i]), flags[i] & 1 != 0, flags[i] & 2 != 0);
            if (first[i] != i) continue;
            SolanaCpi.Acc memory a = co.accounts[caller[i]];
            bool exe = a.flags & 4 != 0;
            bytes memory data = exe ? _originalData(c, a.key) : _resize(co.regions[a.dataRegion].data, a.len);
            cc.accounts[slot[i]] = Account(a.key, a.owner, a.lamports, exe, data);
        }
    }

    function _originalData(Call calldata c, bytes32 key) private pure returns (bytes memory) {
        for (uint256 i = 0; i < c.accounts.length; i++) if (c.accounts[i].key == key) return c.accounts[i].data;
        return "";
    }

    function _program(Program[] calldata programs, bytes32 id) private pure returns (bool, uint256) {
        for (uint256 i = 0; i < programs.length; i++) if (programs[i].id == id) return (true, i);
        return (false, 0);
    }

    function _onStack(bytes memory stack, bytes32 id) private pure returns (bool) {
        for (uint256 i = 0; i < stack.length; i += 32) {
            bytes32 k;
            assembly {
                k := mload(add(add(stack, 32), i))
            }
            if (k == id) return true;
        }
        return false;
    }

    /// @dev A CPI falha com um InstructionError (a syscall devolve o erro ao chamador).
    function _cpiFail(SolanaCpi.Output memory co, IE e, uint32 custom) private pure returns (SolanaCpi.Output memory) {
        co.status = uint8(SolanaVM.Status.SyscallError);
        co.err = uint64(E_INSTRUCTION_) | (uint64(uint8(e)) << 8) | (uint64(custom) << 32);
        return co;
    }

    /// @dev Linhas já formatadas (log de um programa chamado) como entrada de texto cru do log.
    function _raw(bytes memory text) private pure returns (bytes memory) {
        return bytes.concat(bytes1(uint8(6)), bytes4(uint32(text.length)), text);
    }

    /// @dev A falha de acesso caiu nos bytes de uma conta executável que não foram para a VM?
    function _touchedElided(Ser memory s, uint64 vaddr) private pure returns (bool) {
        for (uint256 i = 0; i < s.slots.length; i++) {
            Slot memory sl = s.slots[i];
            if (!sl.elided) continue;
            uint64 start = s.regions[sl.dataRegion].vaddr;
            if (vaddr >= start && vaddr < start + sl.preLen) return true;
        }
        return false;
    }

    /// @dev Compacta a memória: copia o estado do laço para `mark` e volta o ponteiro livre (o que
    ///      a volta alocou, como as cópias das regiões para as chamadas, deixa de contar).
    function _compact(uint256 mark, Loop memory l) private pure returns (Loop memory) {
        bytes memory blob = abi.encode(l);
        assembly {
            let len := mload(blob)
            mcopy(mark, blob, add(len, 32))
            mstore(0x40, add(add(mark, 32), and(add(len, 31), not(31))))
            blob := mark
        }
        return abi.decode(blob, (Loop));
    }

    /// @dev Estado das contas como a CPI precisa (uma entrada por meta; repetidas copiam a original).
    function _accounts(Call calldata c, Ser memory s) private pure returns (SolanaCpi.Acc[] memory out) {
        out = new SolanaCpi.Acc[](s.slots.length);
        for (uint256 i = 0; i < s.slots.length; i++) {
            Slot memory sl = s.slots[i];
            Slot memory orig = sl.dup ? s.slots[sl.dupOf] : sl;
            Account calldata a = c.accounts[sl.account];
            uint8 flags = (sl.isSigner ? 1 : 0) | (sl.isWritable ? 2 : 0) | (a.executable ? 4 : 0);
            out[i] = SolanaCpi.Acc(
                a.key, a.owner, a.lamports, uint64(a.data.length), uint64(orig.preLen), orig.markerAddr, uint32(3 + orig.dataRegion), flags
            );
        }
    }

    /// @dev Memória da VM suspensa (rodata, pilha, heap, input) + registos para o SolanaCpi. A
    ///      região só leitura do programa só vai com `ro` (a tradução quase nunca aponta para ela).
    function _cpiInput(bytes calldata elf, Call calldata c, Ser memory s, SolanaVM.Result memory r, SolanaCpi.Acc[] memory accts, uint256 height, bool ro)
        private
        view
        returns (SolanaCpi.Input memory in_)
    {
        in_.rust = r.err == 1;
        in_.depth = uint8(height);
        in_.programId = c.programId;
        in_.maxCu = c.maxCu;
        in_.cu = r.cu;
        for (uint256 k = 0; k < 5; k++) in_.args[k] = r.suspended.regs[k + 1];
        in_.accounts = accts;
        in_.regions = new SolanaVM.Region[](3 + s.regions.length);
        if (ro) in_.regions[0] = _roRegion(elf);
        in_.regions[1] = SolanaVM.Region(STACK_START, true, STACK_SIZE, r.suspended.stack);
        in_.regions[2] = SolanaVM.Region(HEAP_START, true, HEAP_SIZE, r.suspended.heap);
        for (uint256 i = 0; i < s.regions.length; i++) {
            SolanaVM.Region memory rg = s.regions[i];
            in_.regions[3 + i] = SolanaVM.Region(rg.vaddr, rg.writable, rg.reserved, r.regions[i]);
        }
    }

    /// @dev Região só leitura: imagem v0 (em 1 << 32, depois da tabela de funções) ou ELF v3 (em 0).
    function _roRegion(bytes calldata elf) private view returns (SolanaVM.Region memory) {
        if (elf.length >= 20 && bytes4(elf[0:4]) == 0x7f534230) {
            uint256 off = 20 + 8 * uint256(uint32(bytes4(elf[16:20])));
            return SolanaVM.Region(1 << 32, false, uint64(elf.length - off), elf[off:]);
        }
        (, , , uint256 roOff, uint256 roLen, ) = vm.parseElf(elf);
        return SolanaVM.Region(0, false, uint64(roLen), elf[roOff:roOff + roLen]);
    }

    /// @dev Retoma a VM depois de uma CPI bem-sucedida (r0 = 0; return data = `ret`).
    function _resume(bytes calldata elf, Ser memory s, SolanaVM.Env memory env, SolanaVM.Suspended memory sp, SolanaCpi.Output memory co, bytes memory ret)
        private
        view
        returns (SolanaVM.Result memory)
    {
        sp.regs[0] = 0;
        sp.cu = co.cu;
        sp.stack = co.regions[1].data;
        sp.heap = co.regions[2].data;
        sp.returnData = ret;
        for (uint256 i = 0; i < s.regions.length; i++) {
            s.regions[i].data = co.regions[3 + i].data;
            s.regions[i].writable = co.regions[3 + i].writable;
        }
        return vm.resumeElfVerified(elf, s.regions, env, sp);
    }

    function _inSyscall(SolanaVM.Result memory r) private pure returns (bool) {
        return (r.fault >> 129) & 1 == 1;
    }

    function _fail(IE err, uint32 custom) private pure returns (SolanaLog.Failure memory f) {
        f.kind = 1;
        f.ie = uint8(err);
        f.custom = custom;
    }

    function _failMsg(uint8 kind, uint64 sysErr) private pure returns (SolanaLog.Failure memory f) {
        f.kind = kind;
        f.ie = uint8(IE.ProgramFailedToComplete);
        f.sysErr = sysErr;
    }

    /// @dev `execute` + `deserialize_parameters` do agave: devolve a falha (kind 0 = sucesso) e atualiza `accounts`.
    function _finish(Call calldata c, SolanaVM.Result memory r, Ser memory s, Account[] memory accounts, SolanaCpi.Acc[] memory accts)
        private
        pure
        returns (SolanaLog.Failure memory f)
    {
        if (r.status == SolanaVM.Status.Ok) {
            if (r.r0 != 0) {
                (IE e, uint32 custom) = _fromU64(r.r0);
                return _fail(e, custom);
            }
            (bool failed, IE err) = _deserialize(c, r, s, accounts, accts);
            if (failed) f = _fail(err, 0);
            return f;
        }
        if (r.status == SolanaVM.Status.CuExceeded) {
            // dentro de uma syscall: ComputationalBudgetExceeded; numa instrução: falha da VM
            if (_inSyscall(r)) return _fail(IE.ComputationalBudgetExceeded, 0);
            f.kind = 8;
            f.ie = uint8(IE.ProgramFailedToComplete);
            return f;
        }
        if (r.status == SolanaVM.Status.SyscallError) {
            if (r.err == E_UNSUPPORTED_SYSVAR) return _fail(IE.UnsupportedSysvar, 0);
            if (r.err == E_ARITHMETIC_OVERFLOW) return _fail(IE.ArithmeticOverflow, 0);
            // a syscall devolveu um InstructionError (CPI): o loader propaga-o tal qual
            if (r.err & 0xff == E_INSTRUCTION) return _fail(IE(uint8(r.err >> 8)), uint32(r.err >> 32));
            return _failMsg(2, r.err);
        }
        if (r.status == SolanaVM.Status.AccessViolation) return _accessViolation(c.programId, s, accts, r.fault);
        if (r.status == SolanaVM.Status.DivideByZero) return _failMsg(4, 0);
        if (r.status == SolanaVM.Status.CallDepthExceeded) return _failMsg(5, 0);
        if (r.status == SolanaVM.Status.CallOutsideTextSegment) return _failMsg(6, 0);
        return _failMsg(7, 0);
    }

    /// @dev Acesso inválido: dentro do espaço reservado de uma conta vira um erro de conta (agave `execute`).
    function _accessViolation(bytes32 programId, Ser memory s, SolanaCpi.Acc[] memory accts, uint256 fault) private pure returns (SolanaLog.Failure memory f) {
        uint64 vaddr = uint64(fault);
        uint64 len = uint64(fault >> 64);
        for (uint256 i = 0; i < s.slots.length; i++) {
            uint256 k = s.slots[i].dup ? s.slots[i].dupOf : i;
            Slot memory sl = s.slots[k];
            uint64 start = s.regions[sl.dataRegion].vaddr;
            uint64 end = start + uint64(sl.preLen + MAX_PERMITTED_DATA_INCREASE);
            if (vaddr >= start && vaddr < end) {
                if (vaddr + len <= end) {
                    // can_data_be_changed com o estado atual da conta (a CPI pode ter mudado o dono)
                    IE e = !sl.isWritable ? IE.ReadonlyDataModified : IE.ExternalAccountDataModified;
                    bool bad = !sl.isWritable || accts[k].owner != programId;
                    bool store = (fault >> 128) & 1 == 1;
                    return _fail(store ? (bad ? e : IE.InvalidRealloc) : (bad ? IE.AccountDataTooSmall : IE.InvalidRealloc), 0);
                }
                break;
            }
        }
        f.kind = 3;
        f.ie = uint8(IE.ProgramFailedToComplete);
        f.vaddr = vaddr;
        f.len = len;
    }

    /// @dev `deserialize_parameters_for_abiv1`: lamports, tamanho dos dados, dados e owner de cada conta.
    function _deserialize(Call calldata c, SolanaVM.Result memory r, Ser memory s, Account[] memory accounts, SolanaCpi.Acc[] memory accts)
        private
        pure
        returns (bool failed, IE err)
    {
        int256[2] memory delta; // [lamports, bytes realocados] acumulados na instrução
        for (uint256 i = 0; i < s.slots.length; i++) {
            Slot memory sl = s.slots[i];
            if (sl.dup) continue;
            (failed, err) = _deserializeOne(c.programId, r, sl, accts[i], accounts[sl.account], delta);
            if (failed) return (failed, err);
        }
        if (delta[0] != 0) return (true, IE.UnbalancedInstruction);
    }

    function _deserializeOne(bytes32 programId, SolanaVM.Result memory r, Slot memory sl, SolanaCpi.Acc memory pre, Account memory a, int256[2] memory delta)
        private
        pure
        returns (bool failed, IE err)
    {
        // o que a transação já sabe da conta (muda com CPI): lamports e owner "comprometidos"
        bool owned = pre.owner == programId;
        bytes memory meta = r.regions[sl.metaRegion];
        {
            uint64 lamports = _u64(meta, sl.metaOff + 72);
            if (lamports != pre.lamports) {
                // set_lamports
                if (!owned && lamports < pre.lamports) return (true, IE.ExternalAccountLamportSpend);
                if (!sl.isWritable) return (true, IE.ReadonlyLamportChange);
            }
            delta[0] += int256(uint256(lamports)) - int256(uint256(a.lamports));
            a.lamports = lamports;
        }
        uint256 postLen = _u64(meta, sl.metaOff + 80);
        if (postLen - (postLen > sl.preLen ? sl.preLen : postLen) > MAX_PERMITTED_DATA_INCREASE || postLen > MAX_ACCOUNT_DATA_LEN) {
            return (true, IE.InvalidRealloc);
        }
        bytes memory data = r.regions[sl.dataRegion];
        uint256 curLen = sl.elided ? sl.preLen : data.length;
        if (curLen != postLen) {
            // set_data_length: can_data_be_resized + can_data_be_changed
            if (delta[1] + int256(postLen) - int256(curLen) > int256(MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION)) {
                return (true, IE.MaxAccountsDataAllocationsExceeded);
            }
            if (!sl.isWritable) return (true, IE.ReadonlyDataModified);
            if (!owned) return (true, IE.ExternalAccountDataModified);
            delta[1] += int256(postLen) - int256(curLen);
        }
        if (!sl.elided) a.data = _resize(data, postLen);
        bytes32 owner = _b32(meta, sl.metaOff + 40);
        if (owner != pre.owner) {
            // set_owner: só o dono, só se gravável, só com dados zerados
            if (!owned || !sl.isWritable || !_zeroed(a.data)) return (true, IE.ModifiedProgramId);
        }
        a.owner = owner;
    }

    // ------------------------------------------------------------------ erros e log

    /// @dev `InstructionError::from(u64)` para o código devolvido pelo programa.
    function _fromU64(uint64 code) private pure returns (IE err, uint32 custom) {
        uint64 hi = code >> 32;
        if (hi == 0) return (IE.Custom, uint32(code));
        if (code != hi << 32) return (IE.InvalidError, 0);
        if (hi == 1) return (IE.Custom, 0);
        if (hi == 2) return (IE.InvalidArgument, 0);
        if (hi == 3) return (IE.InvalidInstructionData, 0);
        if (hi == 4) return (IE.InvalidAccountData, 0);
        if (hi == 5) return (IE.AccountDataTooSmall, 0);
        if (hi == 6) return (IE.InsufficientFunds, 0);
        if (hi == 7) return (IE.IncorrectProgramId, 0);
        if (hi == 8) return (IE.MissingRequiredSignature, 0);
        if (hi == 9) return (IE.AccountAlreadyInitialized, 0);
        if (hi == 10) return (IE.UninitializedAccount, 0);
        if (hi == 11) return (IE.NotEnoughAccountKeys, 0);
        if (hi == 12) return (IE.AccountBorrowFailed, 0);
        if (hi == 13) return (IE.MaxSeedLengthExceeded, 0);
        if (hi == 14) return (IE.InvalidSeeds, 0);
        if (hi == 15) return (IE.BorshIoError, 0);
        if (hi == 16) return (IE.AccountNotRentExempt, 0);
        if (hi == 17) return (IE.UnsupportedSysvar, 0);
        if (hi == 18) return (IE.IllegalOwner, 0);
        if (hi == 19) return (IE.MaxAccountsDataAllocationsExceeded, 0);
        if (hi == 20) return (IE.InvalidRealloc, 0);
        if (hi == 21) return (IE.MaxInstructionTraceLengthExceeded, 0);
        if (hi == 22) return (IE.BuiltinProgramsMustConsumeComputeUnits, 0);
        if (hi == 23) return (IE.InvalidAccountOwner, 0);
        if (hi == 24) return (IE.ArithmeticOverflow, 0);
        if (hi == 25) return (IE.Immutable, 0);
        if (hi == 26) return (IE.IncorrectAuthority, 0);
        return (IE.InvalidError, 0);
    }

    // ------------------------------------------------------------------ utilidades

    function _le(uint64 v) private pure returns (bytes8 out) {
        for (uint256 i = 0; i < 8; i++) out |= bytes8(bytes1(uint8(v >> (8 * i)))) >> (8 * i);
    }

    function _u64(bytes memory b, uint256 off) private pure returns (uint64 v) {
        for (uint256 i = 0; i < 8; i++) v |= uint64(uint8(b[off + i])) << uint64(8 * i);
    }

    function _b32(bytes memory b, uint256 off) private pure returns (bytes32 v) {
        assembly ("memory-safe") {
            v := mload(add(add(b, 32), off))
        }
    }

    /// @dev Dados com o novo tamanho (zeros além do que a VM devolveu).
    function _resize(bytes memory b, uint256 len) private pure returns (bytes memory out) {
        if (b.length == len) return b;
        out = new bytes(len);
        assembly ("memory-safe") {
            mcopy(add(out, 32), add(b, 32), len)
        }
        if (len < b.length) return out;
        // mcopy acima copiou lixo além de b: zera
        assembly ("memory-safe") {
            let p := add(add(out, 32), mload(b))
            calldatacopy(p, calldatasize(), sub(len, mload(b)))
        }
    }

    function _zeroed(bytes memory b) private pure returns (bool) {
        for (uint256 i = 0; i < b.length; i++) if (b[i] != 0) return false;
        return true;
    }
}
