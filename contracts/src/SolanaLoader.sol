// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title SolanaLoader — carregador de ELF sBPF v0 (o formato do SPL Token e da maioria da mainnet)
/// @notice Porta on-chain de `Executable::load_with_lenient_parser` do solana-sbpf 0.23, o carregador
///         que o agave usa para executar programas v0 (configuração de execução do agave 4.3:
///         `reject_broken_elfs = false`, `optimize_rodata = false`, sem labels de depuração):
///           1. `Elf64::parse` + `Executable::validate` (cabeçalhos, tabelas, seções, `.dynamic`);
///           2. relocações: cada `call imm` relativo vira o hash murmur3 do pc alvo (registro de
///              funções), R_BPF_64_64, R_BPF_64_RELATIVE e R_BPF_64_32 (símbolos → hash);
///           3. a entrada registrada como "entrypoint" e a região só leitura em 0x1_0000_0000
///              (.text, .rodata, .data.rel.ro e .eh_frame copiadas nos seus endereços).
///         Roda uma vez, ao publicar o programa. O resultado (`layout`) é pequeno: a tabela de funções,
///         a lista de seções e os remendos que as relocações fazem no arquivo. `SolanaImage.build`
///         refaz a imagem executável a partir do ELF original e do layout.
///
/// @dev Formato da imagem que a SolanaVM executa (inteiros big-endian):
///        "\x7fSB0" | entry u32 | textAddr u32 | textLen u32 | nfunc u32
///        | nfunc × (key u32, pc u32), ordenado por key | ro (a região em 0x1_0000_0000)
///      O layout é o mesmo cabeçalho e tabela, seguidos de
///        roLen u32 | nsec u32 | npatch u32 | nsec × (addr u32, off u32, len u32) | npatch × (off u32, valor u32)
///      onde cada remendo grava `valor` (little-endian, 4 bytes) no offset `off` do arquivo.
contract SolanaLoader {
    error BadElf(uint256 code);

    bytes4 public constant IMAGE_MAGIC = 0x7f534230; // "\x7fSB0"
    /// @notice ebpf::hash_symbol_name(b"entrypoint")
    uint32 public constant ENTRYPOINT_KEY = 0x71e3cf81;

    uint256 private constant REGION = 1 << 32;
    uint256 private constant U64 = (1 << 64) - 1;

    /// @dev hashes das 42 syscalls registradas pelo agave 4.3 (ambiente de execução, todas as features),
    ///      em ordem crescente: um hash de função igual a um destes é SymbolHashCollision.
    bytes private constant SYSCALLS =
        hex"080c98b011f49d8613c1b505174c512217e40350188a0031207559bd23a29a61334fd5ed3770fb22434371f848504a3852ba50965be92f4a5c2a31785d2245e45fdcde3160a40880686093bb717cc4a37317b434780e4c157ef088ca83f00e8f85532d949229cdcc9377323ca226d3eba22b9c85aa2607caadb8efc8ae0c318bb6fc1a11bf7188f6c4947c21d56b5fe9d7449092d7793abbdd1c41a6edef5aeef111a47efdba2b3b";

    /// @dev Estado do carregamento (ponteiros são endereços de memória; offsets são do arquivo).
    struct E {
        uint256 p; // byte 0 da cópia mutável do ELF
        uint256 len;
        uint256 phoff;
        uint256 phEnd;
        uint256 phnum;
        uint256 shoff;
        uint256 shEnd;
        uint256 shnum;
        uint256 names; // header de .shstrtab
        uint256 dynstr; // header de .dynstr (0 = não há)
        uint256 text; // header de .text
        uint256 rel; // tabela de relocações
        uint256 relN;
        uint256 sym; // tabela de símbolos dinâmicos
        uint256 symN;
        uint256 n; // instruções no .text
        uint256 bits; // bitmap dos pcs registrados como função
        uint256 patches; // remendos (8 bytes cada: off u32, valor u32)
        uint256 npatch;
        uint256 eval; // pc + 1 registrado sob o hash de "entrypoint" (0 = nenhum)
        uint256 entry;
    }

    /// @notice Carrega o ELF e devolve o layout (reverte com `BadElf` se o agave o rejeitaria).
    function load(bytes calldata elf) external pure returns (bytes memory layout) {
        return _load(elf);
    }

    /// @notice Carrega e monta a imagem executável (o que o Store faz em duas etapas).
    function image(bytes calldata elf) external pure returns (bytes memory) {
        bytes memory layout = _load(elf);
        return SolanaImage.build(elf, layout);
    }

    /// @notice murmur3 de 32 bits, semente 0 (`ebpf::hash_symbol_name`).
    function hashSymbol(bytes calldata name) external pure returns (uint32) {
        bytes memory b = name;
        uint256 p;
        assembly {
            p := add(b, 32)
        }
        return uint32(_murmur(p, b.length));
    }

    function _load(bytes calldata elf) private pure returns (bytes memory) {
        E memory e;
        bytes memory m = elf;
        e.len = m.length;
        assembly ("memory-safe") {
            mstore(e, add(m, 32))
        }
        _parse(e);
        _dynamic(e);
        _validate(e);
        _relocate(e);
        return _layout(e);
    }

    function _fail(uint256 code) private pure {
        revert BadElf(code);
    }

    // ------------------------------------------------------------------ leitura (little-endian, memória)

    function _u8(uint256 a) private pure returns (uint256 v) {
        assembly {
            v := byte(0, mload(a))
        }
    }

    function _u16(uint256 a) private pure returns (uint256 v) {
        assembly {
            let w := mload(a)
            v := or(byte(0, w), shl(8, byte(1, w)))
        }
    }

    function _u32(uint256 a) private pure returns (uint256 v) {
        assembly {
            let w := mload(a)
            v := or(or(byte(0, w), shl(8, byte(1, w))), or(shl(16, byte(2, w)), shl(24, byte(3, w))))
        }
    }

    function _u64(uint256 a) private pure returns (uint256 v) {
        assembly {
            let w := mload(a)
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } { v := or(v, shl(mul(i, 8), byte(i, w))) }
        }
    }

    /// @dev `slice_from_bytes`: tamanho múltiplo de `size`, dentro do arquivo e alinhado a 8.
    function _sliceOk(E memory e, uint256 off, uint256 sz, uint256 size) private pure returns (bool) {
        return sz % size == 0 && off + sz <= e.len && off % 8 == 0;
    }

    // ------------------------------------------------------------------ Elf64::parse

    function _parse(E memory e) private pure {
        uint256 p = e.p;
        uint256 len = e.len;
        if (len < 64) _fail(1);
        // e_ident: \x7fELF, ELFCLASS64, ELFDATA2LSB, EV_CURRENT; e_version, e_ehsize, e_phentsize, e_shentsize
        if (_u32(p) != 0x464c457f || _u8(p + 4) != 2 || _u8(p + 5) != 1 || _u8(p + 6) != 1) _fail(2);
        if (_u32(p + 20) != 1 || _u16(p + 52) != 64 || _u16(p + 54) != 56 || _u16(p + 58) != 64) _fail(3);
        e.shnum = _u16(p + 60);
        uint256 shstrndx = _u16(p + 62);
        if (shstrndx >= e.shnum) _fail(4);

        // tabelas de program e section headers: sem sobreposição, dentro do arquivo, alinhadas
        e.phoff = _u64(p + 32);
        e.phnum = _u16(p + 56);
        e.phEnd = e.phoff + 56 * e.phnum;
        if (!(64 <= e.phoff || e.phEnd == 0) || e.phEnd > len || e.phoff % 8 != 0) _fail(5);
        e.shoff = _u64(p + 40);
        e.shEnd = e.shoff + 64 * e.shnum;
        if (!(64 <= e.shoff || e.shEnd == 0) || !(e.phEnd <= e.shoff || e.shEnd <= e.phoff)) _fail(6);
        if (e.shEnd > len || e.shoff % 8 != 0) _fail(6);
        if (e.shnum == 0 || _u32(p + e.shoff + 4) != 0) _fail(7); // a primeira seção é SHT_NULL

        // segmentos PT_LOAD em ordem de endereço e dentro do arquivo
        uint256 vaddr;
        for (uint256 i = 0; i < e.phnum; i++) {
            uint256 h = p + e.phoff + 56 * i;
            if (_u32(h) != 1) continue;
            uint256 pv = _u64(h + 16);
            if (pv < vaddr || _u64(h + 8) + _u64(h + 32) > len) _fail(8);
            vaddr = pv;
        }

        // seções (menos NOBITS) em ordem, sem sobrepor cabeçalho nem tabelas
        uint256 offset;
        for (uint256 i = 0; i < e.shnum; i++) {
            uint256 h = p + e.shoff + 64 * i;
            if (_u32(h + 4) == 8) continue;
            uint256 s = _u64(h + 24);
            uint256 end = s + _u64(h + 32);
            if (!(64 <= s || end == 0) || !(end <= e.phoff || e.phEnd <= s) || !(end <= e.shoff || e.shEnd <= s)) _fail(9);
            if (s < offset || end > len) _fail(9);
            offset = end;
        }

        // nomes das seções; .symtab, .strtab e .dynstr não podem repetir
        if (shstrndx == 0) _fail(10);
        e.names = p + e.shoff + 64 * shstrndx;
        bool symtab;
        bool strtab;
        for (uint256 i = 0; i < e.shnum; i++) {
            uint256 h = p + e.shoff + 64 * i;
            (bytes32 w, uint256 l) = _sectionName(e, h);
            if (_is(w, l, ".symtab", 7)) {
                if (symtab) _fail(11);
                symtab = true;
            } else if (_is(w, l, ".strtab", 7)) {
                if (strtab) _fail(11);
                strtab = true;
            } else if (_is(w, l, ".dynstr", 7)) {
                if (e.dynstr != 0) _fail(11);
                e.dynstr = h;
            }
        }
    }

    /// @dev Tabela `.dynamic`: relocações (DT_REL/RELSZ/RELENT) e símbolos dinâmicos (DT_SYMTAB).
    function _dynamic(E memory e) private pure {
        uint256 p = e.p;
        uint256 dyn;
        uint256 dynN;
        bool found;
        for (uint256 i = 0; i < e.phnum; i++) {
            uint256 h = p + e.phoff + 56 * i;
            if (_u32(h) != 2) continue; // o primeiro PT_DYNAMIC
            uint256 off = _u64(h + 8);
            uint256 sz = _u64(h + 32);
            if (_sliceOk(e, off, sz, 16)) {
                (dyn, dynN, found) = (p + off, sz / 16, true);
            }
            break;
        }
        if (!found) {
            for (uint256 i = 0; i < e.shnum; i++) {
                uint256 h = p + e.shoff + 64 * i;
                if (_u32(h + 4) != 6) continue; // a primeira seção SHT_DYNAMIC
                uint256 off = _u64(h + 24);
                uint256 sz = _u64(h + 32);
                if (!_sliceOk(e, off, sz, 16)) _fail(12);
                (dyn, dynN, found) = (p + off, sz / 16, true);
                break;
            }
        }
        if (!found) return;
        uint256 dtRel;
        uint256 dtRelsz;
        uint256 dtRelent;
        uint256 dtSymtab;
        for (uint256 j = 0; j < dynN; j++) {
            uint256 tag = _u64(dyn + 16 * j);
            if (tag == 0) break;
            uint256 val = _u64(dyn + 16 * j + 8);
            if (tag == 6) dtSymtab = val;
            else if (tag == 17) dtRel = val;
            else if (tag == 18) dtRelsz = val;
            else if (tag == 19) dtRelent = val;
        }
        if (dtRel != 0) {
            if (dtRelent != 16 || dtRelsz == 0) _fail(13);
            (bool ok, uint256 off) = _vaddrToOffset(e, dtRel);
            if (!ok || !_sliceOk(e, off, dtRelsz, 16)) _fail(13);
            e.rel = p + off;
            e.relN = dtRelsz / 16;
        }
        if (dtSymtab != 0) {
            uint256 h = _sectionAt(e, dtSymtab);
            if (h == 0) _fail(14);
            uint256 t = _u32(h + 4);
            if (t != 2 && t != 11) _fail(14); // SHT_SYMTAB / SHT_DYNSYM
            uint256 off = _u64(h + 24);
            uint256 sz = _u64(h + 32);
            if (!_sliceOk(e, off, sz, 24)) _fail(14);
            e.sym = p + off;
            e.symN = sz / 24;
        }
    }

    /// @dev O offset no arquivo de um endereço: pelo program header que o contém, senão pela seção
    ///      com esse endereço (`parse_dynamic_relocations`).
    function _vaddrToOffset(E memory e, uint256 vaddr) private pure returns (bool, uint256) {
        for (uint256 i = 0; i < e.phnum; i++) {
            uint256 h = e.p + e.phoff + 56 * i;
            uint256 pv = _u64(h + 16);
            uint256 pend = pv + _u64(h + 40);
            if (pend > U64) _fail(13);
            if (pv <= vaddr && vaddr < pend) {
                uint256 off = vaddr - pv + _u64(h + 8);
                if (off > U64) _fail(13);
                return (true, off);
            }
        }
        uint256 s = _sectionAt(e, vaddr);
        if (s == 0) return (false, 0);
        return (true, _u64(s + 24));
    }

    /// @dev A primeira seção com sh_addr == `addr` (0 se nenhuma).
    function _sectionAt(E memory e, uint256 addr) private pure returns (uint256) {
        for (uint256 i = 0; i < e.shnum; i++) {
            uint256 h = e.p + e.shoff + 64 * i;
            if (_u64(h + 16) == addr) return h;
        }
        return 0;
    }

    /// @dev `get_string_in_section`: string terminada em zero dentro da seção, com no máximo `max`
    ///      bytes contando o zero. Devolve o endereço de memória e o tamanho.
    function _string(E memory e, uint256 strHdr, uint256 off, uint256 max) private pure returns (uint256 start, uint256 l) {
        if (_u32(strHdr + 4) != 3) _fail(15); // SHT_STRTAB
        uint256 so = _u64(strHdr + 24);
        uint256 s = so + off;
        uint256 end = so + _u64(strHdr + 32);
        if (s + max < end) end = s + max;
        if (s > end || end > e.len) _fail(15);
        start = e.p + s;
        uint256 n = end - s;
        for (l = 0; l < n; l++) {
            if (_u8(start + l) == 0) return (start, l);
        }
        _fail(16);
    }

    /// @dev Nome de uma seção (até 15 bytes) como palavra alinhada à esquerda.
    function _sectionName(E memory e, uint256 h) private pure returns (bytes32 w, uint256 l) {
        uint256 start;
        (start, l) = _string(e, e.names, _u32(h), 16);
        assembly {
            w := and(mload(start), not(shr(mul(l, 8), not(0))))
        }
    }

    function _is(bytes32 w, uint256 l, bytes32 name, uint256 nl) private pure returns (bool) {
        return l == nl && w == name;
    }

    function _prefix(bytes32 w, uint256 l, bytes32 pre, uint256 pl) private pure returns (bool) {
        return l >= pl && (w & ~bytes32(type(uint256).max >> (pl * 8))) == pre;
    }

    // ------------------------------------------------------------------ Executable::validate

    function _validate(E memory e) private pure {
        uint256 p = e.p;
        if (_u8(p + 7) != 0) _fail(20); // ELFOSABI_NONE
        uint256 machine = _u16(p + 18);
        if (machine != 247 && machine != 263) _fail(21); // EM_BPF / EM_SBPF
        if (_u16(p + 16) != 3) _fail(22); // ET_DYN
        uint256 texts;
        for (uint256 i = 0; i < e.shnum; i++) {
            uint256 h = p + e.shoff + 64 * i;
            (bytes32 w, uint256 l) = _sectionName(e, h);
            if (_is(w, l, ".text", 5)) {
                texts++;
                e.text = h;
            }
            // seções graváveis não são suportadas (.bss, .data que não seja .data.rel*)
            if (_prefix(w, l, ".bss", 4) || ((_u64(h + 8) & 3) == 3 && _prefix(w, l, ".data", 5) && !_prefix(w, l, ".data.rel", 9))) {
                _fail(23);
            }
            if (_u64(h + 24) + _u64(h + 32) > e.len) _fail(24);
        }
        if (texts != 1) _fail(25);
        uint256 a = _u64(e.text + 16);
        uint256 entryVa = _u64(p + 24);
        uint256 top = a + _u64(e.text + 32);
        if (top > U64) top = U64;
        if (entryVa < a || entryVa >= top) _fail(26);
        // load_with_lenient_parser: o texto fica abaixo da pilha
        if (a + REGION > 2 * REGION) _fail(27);
    }

    // ------------------------------------------------------------------ relocações

    function _relocate(E memory e) private pure {
        uint256 textOff = _u64(e.text + 24);
        uint256 textSize = _u32(e.text + 4) == 8 ? 0 : _u64(e.text + 32);
        uint256 n = textSize / 8;
        e.n = n;
        // bitmap de n + 1 bits (pcs registrados)
        uint256 words = n / 256 + 1;
        uint256 bits;
        assembly ("memory-safe") {
            bits := mload(0x40)
            mstore(0x40, add(bits, shl(5, words)))
            calldatacopy(bits, calldatasize(), shl(5, words))
        }
        e.bits = bits;
        // os remendos crescem no fim da memória (cada um avança o ponteiro livre): nada mais é alocado aqui
        uint256 fp;
        assembly ("memory-safe") {
            fp := mload(0x40)
        }
        e.patches = fp;

        // 1. chamadas relativas (`call imm` com imm != -1): alvo = pc + 1 + imm, imm := hash(alvo)
        uint256 base = e.p + textOff;
        for (uint256 i = 0; i < n; i++) {
            uint256 w;
            assembly {
                w := mload(add(base, shl(3, i)))
            }
            if (w >> 248 != 0x85) continue;
            int256 imm;
            assembly {
                imm := signextend(3, or(or(byte(4, w), shl(8, byte(5, w))), or(shl(16, byte(6, w)), shl(24, byte(7, w)))))
            }
            if (imm == -1) continue;
            int256 t = int256(i) + 1 + imm;
            if (t < 0 || t >= int256(n)) _fail(30);
            _register(e, uint256(t));
            _patch(e, textOff + 8 * i + 4, _hashPc(uint256(t)));
        }

        // 2. tabela de relocações dinâmicas
        for (uint256 j = 0; j < e.relN; j++) {
            uint256 r = e.rel + 16 * j;
            uint256 roff = _u64(r);
            uint256 info = _u64(r + 8);
            uint256 typ = info & 0xffffffff;
            if (typ == 1) _rel64(e, roff, info >> 32);
            else if (typ == 8) _relRelative(e, roff, textOff, textSize);
            else if (typ == 10) _rel32(e, roff, info >> 32);
            else _fail(31);
        }

        // 3. entrada: offset em relação ao .text, múltiplo de 8
        uint256 off = _u64(e.p + 24) - _u64(e.text + 16);
        if (off % 8 != 0) _fail(32);
        e.entry = off / 8;
    }

    /// @dev R_BPF_64_64: lddw com o endereço do símbolo + imm (levado para 0x1_0000_0000 se preciso).
    function _rel64(E memory e, uint256 roff, uint256 symi) private pure {
        uint256 io = roff + 4;
        if (io + 4 > e.len) _fail(33);
        uint256 refd = _u32(e.p + io);
        if (symi >= e.symN) _fail(34);
        uint256 addr = _u64(e.sym + 24 * symi + 8) + refd;
        if (addr > U64) addr = U64;
        if (addr < REGION) addr += REGION;
        if (io + 12 > e.len) _fail(33);
        _patch(e, io, addr & 0xffffffff);
        _patch(e, io + 8, addr >> 32);
    }

    /// @dev R_BPF_64_RELATIVE: no .text, o endereço de 64 bits do lddw; fora, um u64 com 1<<32 + u32.
    function _relRelative(E memory e, uint256 roff, uint256 textOff, uint256 textSize) private pure {
        uint256 io = roff + 4;
        if (roff >= textOff && roff < textOff + textSize) {
            if (roff + 16 > e.len) _fail(35);
            uint256 refd = _u32(e.p + io) | (_u32(e.p + roff + 12) << 32);
            if (refd == 0) _fail(36);
            if (refd < REGION) refd += REGION;
            _patch(e, io, refd & 0xffffffff);
            _patch(e, roff + 12, refd >> 32);
        } else {
            if (io + 4 > e.len) _fail(35);
            uint256 v = _u32(e.p + io);
            if (roff + 8 > e.len) _fail(35);
            _patch(e, roff, v);
            _patch(e, roff + 4, 1);
        }
    }

    /// @dev R_BPF_64_32: chamada a um símbolo. Função definida no .text → hash do pc (registrada);
    ///      senão é uma syscall → hash do nome.
    function _rel32(E memory e, uint256 roff, uint256 symi) private pure {
        if (symi >= e.symN) _fail(37);
        uint256 s = e.sym + 24 * symi;
        if (e.dynstr == 0) _fail(38);
        (uint256 name, uint256 nl) = _string(e, e.dynstr, _u32(s), 64);
        uint256 value = _u64(s + 8);
        uint256 key;
        if ((_u8(s + 4) & 0xf) == 2 && value != 0) {
            uint256 a = _u64(e.text + 16);
            uint256 top = a + _u64(e.text + 32);
            if (top > U64) top = U64;
            if (value < a || value >= top) _fail(39);
            uint256 t = (value - a) / 8;
            if (t > e.n) _fail(39);
            if (nl == 10 && _isEntrypoint(name)) {
                _registerEntry(e, t);
                key = ENTRYPOINT_KEY;
            } else {
                _register(e, t);
                key = _hashPc(t);
            }
        } else {
            key = _murmur(name, nl);
        }
        if (roff + 8 > e.len) _fail(40);
        _patch(e, roff + 4, key);
    }

    function _isEntrypoint(uint256 name) private pure returns (bool r) {
        assembly {
            r := eq(and(mload(name), not(shr(80, not(0)))), shl(176, 0x656e747279706f696e74))
        }
    }

    function _register(E memory e, uint256 ip) private pure {
        uint256 b = e.bits + 32 * (ip / 256);
        assembly {
            mstore(b, or(mload(b), shl(mod(ip, 256), 1)))
        }
    }

    function _registerEntry(E memory e, uint256 pc) private pure {
        if (e.eval != 0 && e.eval != pc + 1) _fail(41); // SymbolHashCollision
        e.eval = pc + 1;
    }

    /// @dev Grava `v` (u32 little-endian) no offset `off` da cópia do ELF e anota o remendo.
    function _patch(E memory e, uint256 off, uint256 v) private pure {
        uint256 a = e.p + off;
        uint256 slot = e.patches + 8 * e.npatch;
        assembly {
            mstore8(a, and(v, 0xff))
            mstore8(add(a, 1), and(shr(8, v), 0xff))
            mstore8(add(a, 2), and(shr(16, v), 0xff))
            mstore8(add(a, 3), and(shr(24, v), 0xff))
            mstore(slot, or(shl(224, off), shl(192, v)))
            mstore(0x40, add(slot, 32))
        }
        e.npatch++;
    }

    // ------------------------------------------------------------------ hashes

    function _hashPc(uint256 pc) private pure returns (uint256 h) {
        h = _mix(0, pc & 0xffffffff);
        h = _mix(h, (pc >> 32) & 0xffffffff);
        h = _fmix(h ^ 8);
    }

    function _mix(uint256 h, uint256 k) private pure returns (uint256) {
        unchecked {
            k = (k * 0xcc9e2d51) & 0xffffffff;
            k = ((k << 15) | (k >> 17)) & 0xffffffff;
            k = (k * 0x1b873593) & 0xffffffff;
            h ^= k;
            h = ((h << 13) | (h >> 19)) & 0xffffffff;
            return (h * 5 + 0xe6546b64) & 0xffffffff;
        }
    }

    function _fmix(uint256 h) private pure returns (uint256) {
        unchecked {
            h ^= h >> 16;
            h = (h * 0x85ebca6b) & 0xffffffff;
            h ^= h >> 13;
            h = (h * 0xc2b2ae35) & 0xffffffff;
            return h ^ (h >> 16);
        }
    }

    function _murmur(uint256 p, uint256 n) private pure returns (uint256 h) {
        unchecked {
            uint256 nb = n & ~uint256(3);
            for (uint256 i = 0; i < nb; i += 4) h = _mix(h, _u32(p + i));
            uint256 t = n & 3;
            if (t != 0) {
                uint256 k = _u32(p + nb) & ((1 << (8 * t)) - 1);
                k = (k * 0xcc9e2d51) & 0xffffffff;
                k = ((k << 15) | (k >> 17)) & 0xffffffff;
                k = (k * 0x1b873593) & 0xffffffff;
                h ^= k;
            }
            h = _fmix(h ^ (n & 0xffffffff));
        }
    }

    function _isSyscall(uint256 key) private pure returns (bool) {
        bytes memory s = SYSCALLS;
        uint256 lo = 0;
        uint256 hi = s.length / 4;
        while (lo < hi) {
            uint256 mid = (lo + hi) / 2;
            uint256 k;
            assembly {
                k := shr(224, mload(add(add(s, 32), shl(2, mid))))
            }
            if (k == key) return true;
            if (k < key) lo = mid + 1;
            else hi = mid;
        }
        return false;
    }

    // ------------------------------------------------------------------ registro de funções e layout

    /// @dev Registro final: hash(pc) → pc de cada pc marcado, e "entrypoint" → entrada (o agave
    ///      remove o que estiver nesse hash e registra a entrada). Ordenado por hash.
    function _functions(E memory e) private pure returns (uint256[] memory f) {
        uint256 count = 1;
        uint256 words = e.n / 256 + 1;
        for (uint256 i = 0; i < words; i++) {
            uint256 w;
            uint256 a = e.bits + 32 * i;
            assembly {
                w := mload(a)
            }
            while (w != 0) {
                w &= w - 1;
                count++;
            }
        }
        f = new uint256[](count);
        uint256 k;
        for (uint256 i = 0; i < words; i++) {
            uint256 w;
            uint256 a = e.bits + 32 * i;
            assembly {
                w := mload(a)
            }
            for (uint256 b = 0; w != 0; b++) {
                if (w & 1 != 0) {
                    uint256 pc = i * 256 + b;
                    uint256 key = _hashPc(pc);
                    if (_isSyscall(key)) _fail(42);
                    if (key == ENTRYPOINT_KEY) {
                        _registerEntry(e, pc); // removido no fim, mas colide com outro valor
                    } else {
                        f[k++] = (key << 32) | pc;
                    }
                }
                w >>= 1;
            }
        }
        f[k++] = (uint256(ENTRYPOINT_KEY) << 32) | e.entry;
        assembly ("memory-safe") {
            mstore(f, k)
        }
        _sort(f);
        for (uint256 i = 1; i < k; i++) {
            if (f[i] >> 32 == f[i - 1] >> 32) _fail(43); // dois pcs com o mesmo hash
        }
    }

    /// @dev heapsort em memória.
    function _sort(uint256[] memory a) private pure {
        uint256 n = a.length;
        if (n < 2) return;
        for (uint256 i = n / 2; i > 0; i--) _sift(a, i - 1, n);
        for (uint256 end = n - 1; end > 0; end--) {
            (a[0], a[end]) = (a[end], a[0]);
            _sift(a, 0, end);
        }
    }

    function _sift(uint256[] memory a, uint256 root, uint256 n) private pure {
        while (2 * root + 1 < n) {
            uint256 c = 2 * root + 1;
            if (c + 1 < n && a[c + 1] > a[c]) c++;
            if (a[root] >= a[c]) return;
            (a[root], a[c]) = (a[c], a[root]);
            root = c;
        }
    }

    function _layout(E memory e) private pure returns (bytes memory out) {
        uint256[] memory f = _functions(e);
        // seções da região só leitura (parse_ro_sections, sem otimização: buffer de 0 até o maior endereço)
        uint256[] memory secs = new uint256[](e.shnum);
        uint256 nsec;
        uint256 highest;
        for (uint256 i = 0; i < e.shnum; i++) {
            uint256 h = e.p + e.shoff + 64 * i;
            (bytes32 w, uint256 l) = _sectionName(e, h);
            if (!(_is(w, l, ".text", 5) || _is(w, l, ".rodata", 7) || _is(w, l, ".data.rel.ro", 12) || _is(w, l, ".eh_frame", 9))) {
                continue;
            }
            uint256 addr = _u64(h + 16);
            if (addr > REGION) _fail(44);
            uint256 dl = _u32(h + 4) == 8 ? 0 : _u64(h + 32);
            if (addr + dl > highest) highest = addr + dl;
            secs[nsec++] = (addr << 64) | (_u64(h + 24) << 32) | dl;
        }
        if (highest > e.len) _fail(45);
        uint256 textLen = _u32(e.text + 4) == 8 ? 0 : _u64(e.text + 32);

        uint256 nf = f.length;
        out = new bytes(20 + 8 * nf + 12 + 12 * nsec + 8 * e.npatch);
        uint256 o;
        assembly ("memory-safe") {
            o := add(out, 32)
        }
        _be(o, uint32(IMAGE_MAGIC), 4);
        _be(o + 4, e.entry, 4);
        _be(o + 8, _u64(e.text + 16), 4);
        _be(o + 12, textLen, 4);
        _be(o + 16, nf, 4);
        o += 20;
        for (uint256 i = 0; i < nf; i++) {
            _be(o, f[i], 8);
            o += 8;
        }
        _be(o, highest, 4);
        _be(o + 4, nsec, 4);
        _be(o + 8, e.npatch, 4);
        o += 12;
        for (uint256 i = 0; i < nsec; i++) {
            uint256 s = secs[i];
            _be(o, s >> 64, 4);
            _be(o + 4, (s >> 32) & 0xffffffff, 4);
            _be(o + 8, s & 0xffffffff, 4);
            o += 12;
        }
        uint256 src = e.patches;
        uint256 bytes_ = 8 * e.npatch;
        assembly ("memory-safe") {
            mcopy(o, src, bytes_)
        }
    }

    /// @dev Grava `v` big-endian com `size` bytes em `a`.
    function _be(uint256 a, uint256 v, uint256 size) private pure {
        assembly {
            let sh := sub(256, mul(size, 8))
            mstore(a, or(shl(sh, v), and(mload(a), shr(mul(size, 8), not(0)))))
        }
    }
}

/// @title SolanaImage — monta a imagem executável de um programa v0 a partir do ELF e do layout
library SolanaImage {
    /// @dev `elf` é modificado (recebe os remendos das relocações).
    function build(bytes memory elf, bytes memory layout) internal pure returns (bytes memory img) {
        uint256 l;
        uint256 e;
        assembly {
            l := add(layout, 32)
            e := add(elf, 32)
        }
        uint256 nf = _r(l + 16, 4);
        uint256 head = 20 + 8 * nf;
        uint256 roLen = _r(l + head, 4);
        uint256 nsec = _r(l + head + 4, 4);
        uint256 npatch = _r(l + head + 8, 4);
        uint256 q = l + head + 12 + 12 * nsec;
        for (uint256 i = 0; i < npatch; i++) {
            uint256 off = _r(q, 4);
            uint256 v = _r(q + 4, 4);
            uint256 a = e + off;
            assembly {
                mstore8(a, and(v, 0xff))
                mstore8(add(a, 1), and(shr(8, v), 0xff))
                mstore8(add(a, 2), and(shr(16, v), 0xff))
                mstore8(add(a, 3), and(shr(24, v), 0xff))
            }
            q += 8;
        }
        img = new bytes(head + roLen);
        uint256 ro;
        assembly ("memory-safe") {
            mcopy(add(img, 32), l, head)
            ro := add(add(img, 32), head)
        }
        q = l + head + 12;
        for (uint256 i = 0; i < nsec; i++) {
            uint256 addr = _r(q, 4);
            uint256 off = _r(q + 4, 4);
            uint256 len = _r(q + 8, 4);
            assembly ("memory-safe") {
                mcopy(add(ro, addr), add(e, off), len)
            }
            q += 12;
        }
    }

    function _r(uint256 a, uint256 size) private pure returns (uint256 v) {
        assembly {
            v := shr(sub(256, mul(size, 8)), mload(a))
        }
    }
}
