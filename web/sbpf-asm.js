// Assembler sBPF v0 em JavaScript: port do assembler do solana-sbpf 0.26.0
// (src/asm_parser.rs + src/assembler.rs), com o mesmo comportamento, inclusive nas esquisitices
// (por exemplo: rótulo que começa com "r" não pode ser usado como operando, e número que não cabe
// em 64 bits vira 0).
//
// Validação: contracts/test/Asm.test.js compara byte a byte com fixtures/asm.json, que o
// reference/ gera com o assembler oficial (programas de teste, sintaxe difícil, casos de erro e
// ~1000 programas aleatórios desmontados pelo disassembler oficial).
//
// Único açúcar, igual ao do reference/: o que vem depois de `;` numa linha é comentário.
// Única restrição a mais: o rótulo `entrypoint` só pode estar no início (o SbpfVM sempre começa
// na instrução 0).
//
// Uso: sbpfAssemble(texto) -> Uint8Array; lança Error com a mensagem do assembler oficial.
(function (root) {
  "use strict";

  const M64 = (1n << 64n) - 1n;
  const toI64 = (x) => BigInt.asIntN(64, x);

  // ------------------------------------------------------------------ parser (asm_parser.rs)

  const isAlnum = (c) => c !== undefined && /[\p{Alphabetic}\p{N}]/u.test(c);
  const isWs = (c) => c !== undefined && /\p{White_Space}/u.test(c);
  const isDigit = (c) => c !== undefined && c >= "0" && c <= "9";
  const isHex = (c) => c !== undefined && /[0-9a-fA-F]/.test(c);
  const FAIL = Symbol("fail"); // falhou sem consumir (o `or` do combine tenta a próxima opção)

  function parse(src) {
    const s = Array.from(src); // por code point, como o combine
    let i = 0;
    const lineCol = (p) => {
      let line = 1, col = 1;
      for (let k = 0; k < p; k++) { if (s[k] === "\n") { line++; col = 1; } else col++; }
      return `line ${line} column ${col}`;
    };
    const err = (msg) => { throw new Error(`Parse error at ${lineCol(i)}: ${msg}`); };
    const skipSpaces = () => { while (s[i] === " ") i++; };

    function many1(pred) {
      const st = i;
      while (pred(s[i])) i++;
      return i > st ? s.slice(st, i).join("") : FAIL;
    }
    const ident = () => many1((c) => isAlnum(c) || c === "_");
    const mnemonic = () => many1(isAlnum);
    const decToI64 = (d) => { const v = BigInt(d); return v > (1n << 63n) - 1n ? 0n : v; }; // parse::<i64>().unwrap_or(0)

    function integer() {
      let sign = 1n, consumed = false;
      if (s[i] === "-" || s[i] === "+") { sign = s[i] === "-" ? -1n : 1n; i++; consumed = true; skipSpaces(); }
      if (s[i] === "0" && s[i + 1] === "x" && isHex(s[i + 2])) { // attempt(string("0x").with(many1(hex_digit)))
        i += 2;
        const h = many1(isHex);
        const v = BigInt("0x" + h);
        return toI64(sign * (v > M64 ? 0n : toI64(v)));
      }
      const d = many1(isDigit);
      if (d === FAIL) { if (consumed) err(`unexpected ${JSON.stringify(s[i] ?? "end of input")}, expected digit`); return FAIL; }
      return toI64(sign * decToI64(d));
    }

    function register() {
      if (s[i] !== "r") return FAIL;
      i++;
      const d = many1(isDigit);
      if (d === FAIL) err(`unexpected ${JSON.stringify(s[i] ?? "end of input")}, expected digit`);
      return decToI64(d);
    }

    function operand() {
      let v = register();
      if (v !== FAIL) return { t: "reg", v };
      v = integer();
      if (v !== FAIL) return { t: "int", v };
      if (s[i] === "[") {
        i++;
        const r = register();
        if (r === FAIL) err(`unexpected ${JSON.stringify(s[i] ?? "end of input")}, expected 'r'`);
        skipSpaces();
        let off = integer();
        if (off === FAIL) off = 0n;
        if (s[i] !== "]") err(`unexpected ${JSON.stringify(s[i] ?? "end of input")}, expected ']'`);
        i++;
        return { t: "mem", r, off };
      }
      v = ident();
      if (v !== FAIL) return { t: "label", v };
      return FAIL;
    }

    function operands() {
      const out = [];
      const first = operand();
      if (first === FAIL) return out;
      out.push(first);
      while (s[i] === ",") {
        i++;
        skipSpaces();
        const o = operand();
        if (o === FAIL) err(`unexpected ${JSON.stringify(s[i] ?? "end of input")}, expected operand`);
        out.push(o);
      }
      return out;
    }

    function statement() {
      const st = i;
      const name = ident(); // attempt((ident, ':'))
      if (name !== FAIL && s[i] === ":") { i++; return { kind: "label", name }; }
      i = st;
      if (s[i] === ".") {
        i++;
        const d = mnemonic();
        if (d === FAIL) err(`unexpected ${JSON.stringify(s[i] ?? "end of input")}, expected letter or digit`);
        skipSpaces();
        return { kind: "directive", name: d, ops: operands() };
      }
      const m = mnemonic();
      if (m === FAIL) return FAIL;
      skipSpaces();
      return { kind: "insn", name: m, ops: operands() };
    }

    const out = [];
    while (isWs(s[i])) i++;
    for (;;) {
      const st = statement();
      if (st === FAIL) break;
      out.push(st);
      while (isWs(s[i])) i++;
    }
    if (i < s.length) err(`unexpected ${JSON.stringify(s[i])}, expected end of input`);
    return out;
  }

  // ------------------------------------------------------------------ assembler (assembler.rs, sBPF v0)

  const MAP = (() => {
    const m = new Map();
    const alu = [["add", 0x00], ["sub", 0x10], ["mul", 0x20], ["div", 0x30], ["or", 0x40], ["and", 0x50], ["lsh", 0x60],
      ["rsh", 0x70], ["mod", 0x90], ["xor", 0xa0], ["mov", 0xb0], ["arsh", 0xc0], ["hor", 0xf0]];
    m.set("lddw", ["lddw", 0x18]); m.set("ja", ["ja", 0x05]); m.set("syscall", ["syscall", 0x85]);
    m.set("call", ["call", 0x85]); m.set("callx", ["callx", 0x8d]); m.set("exit", ["none", 0x95]);
    m.set("neg", ["unary", 0x87]); m.set("neg32", ["unary", 0x84]); m.set("neg64", ["unary", 0x87]);
    for (const [n, op] of alu) { m.set(n, ["alu", 0x07 | op]); m.set(n + "32", ["alu", 0x04 | op]); m.set(n + "64", ["alu", 0x07 | op]); }
    const pqr = [["lmul", 0x80], ["uhmul", 0x20], ["shmul", 0xa0], ["udiv", 0x40], ["urem", 0x60], ["sdiv", 0xc0], ["srem", 0xe0]];
    for (const [n, op] of pqr) {
      m.set(n, ["alu", 0x06 | 0x10 | op]); m.set(n + "64", ["alu", 0x06 | 0x10 | op]);
      if (n !== "uhmul" && n !== "shmul") m.set(n + "32", ["alu", 0x06 | op]);
    }
    const sizes = [["b", 0x10], ["h", 0x08], ["w", 0x00], ["dw", 0x18]];
    for (const [suf, sz] of sizes) {
      m.set("ldx" + suf, ["ldx", 0x60 | 0x01 | sz]);
      m.set("st" + suf, ["st", 0x60 | 0x02 | sz]);
      m.set("stx" + suf, ["stx", 0x60 | 0x03 | sz]);
    }
    const jc = [["jeq", 0x10], ["jgt", 0x20], ["jge", 0x30], ["jlt", 0xa0], ["jle", 0xb0], ["jset", 0x40], ["jne", 0x50],
      ["jsgt", 0x60], ["jsge", 0x70], ["jslt", 0xc0], ["jsle", 0xd0]];
    for (const [n, c] of jc) { m.set(n, ["jcond", 0x05 | c]); m.set(n + "32", ["jcond", 0x06 | c]); m.set(n + "64", ["jcond", 0x05 | c]); }
    for (const sz of [16, 32, 64]) { m.set("be" + sz, ["endian", 0xdc, sz]); m.set("le" + sz, ["endian", 0xd4, sz]); }
    return m;
  })();

  // murmur3 32 bits, seed 0 (ebpf::hash_symbol_name)
  function murmur3(bytes) {
    let h = 0;
    const c1 = 0xcc9e2d51, c2 = 0x1b873593;
    const nb = bytes.length & ~3;
    for (let k = 0; k < nb; k += 4) {
      let x = bytes[k] | (bytes[k + 1] << 8) | (bytes[k + 2] << 16) | (bytes[k + 3] << 24);
      x = Math.imul(x, c1); x = (x << 15) | (x >>> 17); x = Math.imul(x, c2);
      h ^= x; h = (h << 13) | (h >>> 19); h = (Math.imul(h, 5) + 0xe6546b64) | 0;
    }
    let x = 0;
    switch (bytes.length & 3) {
      case 3: x ^= bytes[nb + 2] << 16; // fallthrough
      case 2: x ^= bytes[nb + 1] << 8; // fallthrough
      case 1: x ^= bytes[nb]; x = Math.imul(x, c1); x = (x << 15) | (x >>> 17); x = Math.imul(x, c2); h ^= x;
    }
    h ^= bytes.length;
    h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16;
    return h | 0; // as i32
  }

  function insn(opc, dst, src, off, imm) {
    if (dst < 0n || dst >= 16n) throw new Error(`Invalid destination register ${dst}`);
    if (src < 0n || src >= 16n) throw new Error(`Invalid source register ${src}`);
    if (off < -32768n || off > 32767n) throw new Error(`Invalid offset ${off}`);
    if (imm < -2147483648n || imm > 2147483647n) throw new Error(`Invalid immediate ${imm}`);
    return { opc, dst: Number(dst), src: Number(src), off: Number(off), imm };
  }

  function encode(x) {
    const b = new Uint8Array(8);
    b[0] = x.opc & 0xff;
    b[1] = ((x.src << 4) | x.dst) & 0xff;
    b[2] = x.off & 0xff; b[3] = (x.off >> 8) & 0xff;
    const imm = Number(BigInt.asUintN(32, x.imm));
    b[4] = imm & 0xff; b[5] = (imm >>> 8) & 0xff; b[6] = (imm >>> 16) & 0xff; b[7] = (imm >>> 24) & 0xff;
    return b;
  }

  const show = (ops) => "[" + ops.map((o) => o.t === "reg" ? `Register(${o.v})` : o.t === "int" ? `Integer(${o.v})`
    : o.t === "mem" ? `Memory(${o.r}, ${o.off})` : `Label(${JSON.stringify(o.v)})`).join(", ") + "]";

  function sbpfAssemble(text) {
    // comentários (`;`) e linhas vazias saem antes, como no reference/
    const clean = text.split(/\r\n|\n|\r/).map((l) => l.split(";")[0].replace(/\s+$/u, "")).filter((l) => l.trim() !== "").join("\n");
    const stmts = parse(clean);

    const labels = new Map([["entrypoint", 0n]]);
    let ptr = 0n;
    for (const st of stmts) {
      if (st.kind === "label") {
        if (st.name === "entrypoint" && ptr !== 0n) throw new Error("o rótulo entrypoint precisa estar no início do programa");
        labels.set(st.name, ptr);
      } else if (st.kind === "directive") {
        if (st.name === "fill" && st.ops.length === 2 && st.ops[0].t === "int" && st.ops[1].t === "int") {
          if (st.ops[0].v < 0n || st.ops[0].v > 100000n) throw new Error("repetição inválida em .fill");
          ptr += st.ops[0].v;
        }
      } else ptr += st.name === "lddw" ? 2n : 1n;
    }
    const resolve = (p, l) => {
      if (!labels.has(l)) throw new Error(`Label not found ${l}`);
      return labels.get(l) - p - 1n;
    };

    const out = [];
    ptr = 0n;
    for (const st of stmts) {
      if (st.kind === "label") continue;
      if (st.kind === "directive") {
        const o = st.ops;
        if (st.name === "fill" && o.length === 2 && o[0].t === "int" && o[1].t === "int") {
          const v = o[1].v;
          for (let k = 0n; k < o[0].v; k++) {
            out.push({ opc: Number(v & 0xffn), dst: Number((v >> 8n) & 0xfn), src: Number((v >> 12n) & 0xfn),
              off: Number(BigInt.asIntN(16, v >> 16n)), imm: BigInt.asUintN(32, v >> 32n) });
            ptr++;
          }
          continue;
        }
        throw new Error(`Invalid directive ${JSON.stringify(st.name)}`);
      }
      const ent = MAP.get(st.name);
      if (!ent) throw new Error(`Invalid instruction ${JSON.stringify(st.name)}`);
      const [type, opc, size] = ent;
      const o = st.ops;
      const sig = o.map((x) => x.t).join(",");
      let x = null;
      switch (type) {
        case "alu":
          if (sig === "reg,reg") x = insn(opc | 0x08, o[0].v, o[1].v, 0n, 0n);
          else if (sig === "reg,int" && o[0].v === 10n && opc === 0x07) x = insn(0x47, 0n, 0n, 0n, 0n); // v0: add r10 vira no-op
          else if (sig === "reg,int") x = insn(opc, o[0].v, 0n, 0n, o[1].v);
          break;
        case "unary": if (sig === "reg") x = insn(opc, o[0].v, 0n, 0n, 0n); break;
        case "ldx": if (sig === "reg,mem") x = insn(opc, o[0].v, o[1].r, o[1].off, 0n); break;
        case "stx": if (sig === "mem,reg") x = insn(opc, o[0].r, o[1].v, o[0].off, 0n); break;
        case "st": if (sig === "mem,int") x = insn(opc, o[0].r, 0n, o[0].off, o[1].v); break;
        case "none": if (sig === "") x = insn(opc, 0n, 0n, 0n, 0n); break;
        case "ja":
          if (sig === "int") x = insn(opc, 0n, 0n, o[0].v, 0n);
          else if (sig === "label") x = insn(opc, 0n, 0n, resolve(ptr, o[0].v), 0n);
          break;
        case "jcond":
          if (sig === "reg,reg,int") x = insn(opc | 0x08, o[0].v, o[1].v, o[2].v, 0n);
          else if (sig === "reg,int,int") x = insn(opc, o[0].v, 0n, o[2].v, o[1].v);
          else if (sig === "reg,reg,label") x = insn(opc | 0x08, o[0].v, o[1].v, resolve(ptr, o[2].v), 0n);
          else if (sig === "reg,int,label") x = insn(opc, o[0].v, 0n, resolve(ptr, o[2].v), o[1].v);
          break;
        case "call":
          if (sig === "int") x = insn(opc, 0n, 0n, 0n, o[0].v + ptr + 1n);
          else if (sig === "label") {
            if (!labels.has(o[0].v)) throw new Error(`Label not found ${o[0].v}`);
            x = insn(opc, 0n, 0n, 0n, labels.get(o[0].v));
          }
          break;
        case "syscall":
          if (sig === "label") x = insn(opc, 0n, 0n, 0n, BigInt(murmur3(new TextEncoder().encode(o[0].v))));
          else if (sig === "int") x = insn(opc, 0n, 0n, 0n, o[0].v);
          break;
        case "callx": if (sig === "reg") x = insn(opc, 0n, 0n, 0n, o[0].v); break; // v0: registrador no imm
        case "endian": if (sig === "reg") x = insn(opc, o[0].v, 0n, 0n, BigInt(size)); break;
        case "lddw":
          if (sig === "reg,int") {
            x = insn(opc, o[0].v, 0n, 0n, BigInt.asIntN(32, o[1].v));
            out.push(x); ptr++;
            out.push({ opc: 0, dst: 0, src: 0, off: 0, imm: o[1].v >> 32n });
            ptr++;
            continue;
          }
          break;
      }
      if (!x) throw new Error(`Unexpected operands: ${show(o)}`);
      out.push(x);
      ptr++;
    }
    const bytes = new Uint8Array(out.length * 8);
    out.forEach((x, k) => bytes.set(encode(x), k * 8));
    return bytes;
  }

  const api = { sbpfAssemble, parse };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else Object.assign(root, api);
})(typeof globalThis !== "undefined" ? globalThis : this);
