// Montador sBPF mínimo: texto -> bytecode (8 bytes por instrução, lddw = 16)
const { SYSCALLS } = require("./syscalls");

const MM_PROGRAM = 0x100000000n;
const ALU = { add: 0x00, sub: 0x10, mul: 0x20, div: 0x30, or: 0x40, and: 0x50, lsh: 0x60, rsh: 0x70,
  neg: 0x80, mod: 0x90, xor: 0xa0, mov: 0xb0, arsh: 0xc0 };
const JMP = { jeq: 0x10, jgt: 0x20, jge: 0x30, jset: 0x40, jne: 0x50, jsgt: 0x60, jsge: 0x70,
  jlt: 0xa0, jle: 0xb0, jslt: 0xc0, jsle: 0xd0 };
const SIZE = { w: 0x00, h: 0x08, b: 0x10, dw: 0x18 };

function reg(s) {
  const m = /^r(\d+)$/.exec(s.trim());
  if (!m || +m[1] > 10) throw new Error(`registrador inválido: ${s}`);
  return +m[1];
}
function isReg(s) { return /^r\d+$/.test(s.trim()); }
function num(s) {
  s = s.trim();
  const neg = s.startsWith("-");
  const v = BigInt(neg ? s.slice(1) : s);
  return neg ? -v : v;
}
function mem(s) {
  const m = /^\[\s*(r\d+)\s*(?:([+-])\s*(\w+))?\s*\]$/.exec(s.trim());
  if (!m) throw new Error(`operando de memória inválido: ${s}`);
  let off = m[3] ? Number(num(m[3])) : 0;
  if (m[2] === "-") off = -off;
  return { r: reg(m[1]), off };
}
function splitOps(rest) {
  const out = []; let cur = ""; let depth = 0;
  for (const ch of rest) {
    if (ch === "[") depth++;
    if (ch === "]") depth--;
    if (ch === "," && depth === 0) { out.push(cur.trim()); cur = ""; } else cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}
function enc(opc, dst, src, off, imm) {
  const b = Buffer.alloc(8);
  b[0] = opc; b[1] = (src << 4) | dst;
  b.writeInt16LE(off, 2);
  b.writeUInt32LE(Number(BigInt.asUintN(32, BigInt(imm))), 4);
  return b;
}

function parse(src) {
  const items = [];
  for (let raw of src.split("\n")) {
    let line = raw.replace(/(;|\/\/|#).*$/, "").trim();
    while (true) {
      const lm = /^([A-Za-z_.$][\w.$]*):\s*(.*)$/.exec(line);
      if (!lm) break;
      items.push({ label: lm[1] });
      line = lm[2].trim();
    }
    if (!line) continue;
    const sp = line.search(/\s/);
    const mn = (sp < 0 ? line : line.slice(0, sp)).toLowerCase();
    const rest = sp < 0 ? "" : line.slice(sp + 1).trim();
    items.push({ mn, rest, line: raw });
  }
  return items;
}

function dataBytes(mn, rest) {
  let b;
  if (mn === ".ascii" || mn === ".asciz") {
    b = Buffer.from(JSON.parse(rest), "utf8");
    if (mn === ".asciz") b = Buffer.concat([b, Buffer.from([0])]);
  } else if (mn === ".bytes") {
    b = Buffer.from(rest.replace(/^0x/, ""), "hex");
  } else if (mn === ".u64") {
    b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt.asUintN(64, num(rest)));
  } else return null;
  const pad = (8 - (b.length % 8)) % 8;
  return Buffer.concat([b, Buffer.alloc(pad)]);
}

function sizeOf(it) {
  if (it.label) return 0;
  const d = dataBytes(it.mn, it.rest);
  if (d) return d.length;
  return it.mn === "lddw" ? 16 : 8;
}

function assemble(src) {
  const items = parse(src);
  const labels = {};
  let pos = 0;
  for (const it of items) {
    if (it.label) { labels[it.label] = pos; continue; }
    pos += sizeOf(it);
  }
  const out = [];
  pos = 0;
  const target = (s, pc) => {
    s = s.trim();
    if (s in labels) return labels[s] / 8 - (pc + 1);
    return Number(num(s));
  };
  for (const it of items) {
    if (it.label) continue;
    const pc = pos / 8;
    const d = dataBytes(it.mn, it.rest);
    try {
      if (d) { out.push(d); }
      else out.push(encodeInsn(it.mn, splitOps(it.rest), pc, labels, target));
    } catch (e) {
      throw new Error(`${e.message} em: ${it.line.trim()}`);
    }
    pos += sizeOf(it);
  }
  return Buffer.concat(out);
}

function encodeInsn(mn, ops, pc, labels, target) {
  let m;
  if ((m = /^(add|sub|mul|div|or|and|lsh|rsh|neg|mod|xor|mov|arsh)(64|32)?$/.exec(mn))) {
    const cls = m[2] === "32" ? 0x04 : 0x07;
    const op = ALU[m[1]];
    const dst = reg(ops[0]);
    if (m[1] === "neg") return enc(op | cls, dst, 0, 0, 0);
    if (isReg(ops[1])) return enc(op | 0x08 | cls, dst, reg(ops[1]), 0, 0);
    return enc(op | cls, dst, 0, 0, num(ops[1]));
  }
  if ((m = /^(le|be)(16|32|64)$/.exec(mn))) {
    return enc(m[1] === "le" ? 0xd4 : 0xdc, reg(ops[0]), 0, 0, +m[2]);
  }
  if (mn === "lddw") {
    const dst = reg(ops[0]);
    const v = ops[1] in labels ? MM_PROGRAM + BigInt(labels[ops[1]]) : BigInt.asUintN(64, num(ops[1]));
    return Buffer.concat([enc(0x18, dst, 0, 0, v & 0xffffffffn), enc(0x00, 0, 0, 0, v >> 32n)]);
  }
  if ((m = /^ldx(dw|w|h|b)$/.exec(mn))) {
    const a = mem(ops[1]);
    return enc(0x61 | SIZE[m[1]], reg(ops[0]), a.r, a.off, 0);
  }
  if ((m = /^stx(dw|w|h|b)$/.exec(mn))) {
    const a = mem(ops[0]);
    return enc(0x63 | SIZE[m[1]], a.r, reg(ops[1]), a.off, 0);
  }
  if ((m = /^st(dw|w|h|b)$/.exec(mn))) {
    const a = mem(ops[0]);
    return enc(0x62 | SIZE[m[1]], a.r, 0, a.off, num(ops[1]));
  }
  if (mn === "ja") return enc(0x05, 0, 0, target(ops[0], pc), 0);
  if (mn in JMP) {
    const dst = reg(ops[0]);
    const off = target(ops[2], pc);
    if (isReg(ops[1])) return enc(JMP[mn] | 0x08 | 0x05, dst, reg(ops[1]), off, 0);
    return enc(JMP[mn] | 0x05, dst, 0, off, num(ops[1]));
  }
  if (mn === "call") {
    const name = ops[0];
    if (name in SYSCALLS) return enc(0x85, 0, 0, 0, SYSCALLS[name]);
    if (name in labels) return enc(0x85, 0, 1, 0, labels[name] / 8 - (pc + 1));
    throw new Error(`call para destino desconhecido: ${name}`);
  }
  if (mn === "callx") return enc(0x8d, 0, reg(ops[0]), 0, 0);
  if (mn === "exit") return enc(0x95, 0, 0, 0, 0);
  throw new Error(`mnemônico desconhecido: ${mn}`);
}

module.exports = { assemble, MM_PROGRAM };
