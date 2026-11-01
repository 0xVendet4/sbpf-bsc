// Interpretador sBPF de referência em JS (BigInt). Mesma semântica do contracts/SbpfVM.sol.
// Usado pelo minerador (off-chain) e como oráculo nos testes diferenciais.
const { keccak256 } = require("ethers");
const { BY_HASH } = require("./syscalls");

const MM_PROGRAM = 0x100000000n, MM_STACK = 0x200000000n, MM_HEAP = 0x300000000n, MM_INPUT = 0x400000000n;
const FRAME_SIZE = 4096n, MAX_DEPTH = 4, HEAP_SIZE = 4096, MAX_LOGS = 32, SYSCALL_COST = 100;
const U64 = (1n << 64n) - 1n, U32 = 0xffffffffn;

class VmError extends Error {
  constructor(kind, pc) { super(`${kind} @pc=${pc}`); this.kind = kind; this.pc = pc; }
}
const sext32 = (x) => (x & 0x80000000n ? x | 0xffffffff00000000n : x);
const s64 = (x) => BigInt.asIntN(64, x);
const s32 = (x) => BigInt.asIntN(32, x);

function run(prog, input, budget) {
  prog = Buffer.from(prog); input = Buffer.from(input);
  const stack = Buffer.alloc(Number(FRAME_SIZE) * MAX_DEPTH), heap = Buffer.alloc(HEAP_SIZE);
  const r = new Array(11).fill(0n);
  r[1] = MM_INPUT; r[10] = MM_STACK + FRAME_SIZE;
  const n = Math.floor(prog.length / 8);
  const frames = [];
  const logs = [];
  let pc = 0, steps = 0;

  const region = (cpc, vaddr, len, write) => {
    const reg = vaddr >> 32n, o = Number(vaddr & U32);
    let m;
    if (reg === 1n && !write) m = prog;
    else if (reg === 2n) m = stack;
    else if (reg === 3n) m = heap;
    else if (reg === 4n) m = input;
    else throw new VmError("AccessViolation", cpc);
    if (BigInt(len) > U32 || o + Number(len) > m.length) throw new VmError("AccessViolation", cpc);
    return [m, o];
  };
  const load = (m, o, sz) => { let v = 0n; for (let i = 0; i < sz; i++) v |= BigInt(m[o + i]) << BigInt(8 * i); return v; };
  const store = (m, o, sz, v) => { for (let i = 0; i < sz; i++) m[o + i] = Number((v >> BigInt(8 * i)) & 0xffn); };
  const size = (cpc, opc, base) => {
    if (opc === base) return 4; if (opc === base + 0x08) return 2;
    if (opc === base + 0x10) return 1; if (opc === base + 0x18) return 8;
    throw new VmError("InvalidInstruction", cpc);
  };
  const charge = (cu) => { steps += cu; if (steps > budget) throw new VmError("ComputeBudgetExceeded", pc); };
  const readBytes = (cpc, a, len) => { const [m, o] = region(cpc, a, len, false); return Buffer.from(m.subarray(o, o + Number(len))); };
  const pushLog = (l) => { if (logs.length < MAX_LOGS) logs.push(l); };
  const pushFrame = (cpc, target) => {
    if (frames.length + 1 >= MAX_DEPTH) throw new VmError("CallDepthExceeded", cpc);
    if (target >= BigInt(n)) throw new VmError("InvalidCallTarget", cpc);
    frames.push([r[6], r[7], r[8], r[9], pc]);
    r[10] += FRAME_SIZE; pc = Number(target);
  };

  const syscall = (cpc, h) => {
    charge(SYSCALL_COST);
    const name = BY_HASH[Number(h)];
    switch (name) {
      case "sol_log_": pushLog({ kind: 0, data: readBytes(cpc, r[1], r[2]) }); break;
      case "sol_log_64_": pushLog({ kind: 1, values: [r[1], r[2], r[3], r[4], r[5]] }); break;
      case "sol_log_compute_units_": pushLog({ kind: 2, values: [BigInt(budget - steps), 0n, 0n, 0n, 0n] }); break;
      case "sol_keccak256": {
        const [sm, so] = region(cpc, r[1], r[2] * 16n, false);
        const parts = [];
        for (let i = 0; i < Number(r[2]); i++) {
          const p = load(sm, so + i * 16, 8), len = load(sm, so + i * 16 + 8, 8);
          charge(Number(len / 2n));
          parts.push(readBytes(cpc, p, len));
        }
        const [om, oo] = region(cpc, r[3], 32, true);
        Buffer.from(keccak256(Buffer.concat(parts)).slice(2), "hex").copy(om, oo);
        break;
      }
      case "sol_memcpy_": case "sol_memmove_": {
        charge(Number(r[3] / 250n));
        const [sm, so] = region(cpc, r[2], r[3], false);
        const [dm, dOff] = region(cpc, r[1], r[3], true);
        Buffer.from(sm.subarray(so, so + Number(r[3]))).copy(dm, dOff);
        break;
      }
      case "sol_memset_": {
        charge(Number(r[3] / 250n));
        const [dm, dOff] = region(cpc, r[1], r[3], true);
        dm.fill(Number(r[2] & 0xffn), dOff, dOff + Number(r[3]));
        break;
      }
      case "sol_memcmp_": {
        charge(Number(r[3] / 250n));
        const [am, ao] = region(cpc, r[1], r[3], false);
        const [bm, bo] = region(cpc, r[2], r[3], false);
        let res = 0n;
        for (let i = 0; i < Number(r[3]); i++) {
          if (am[ao + i] !== bm[bo + i]) { res = BigInt.asUintN(32, BigInt(am[ao + i] - bm[bo + i])); break; }
        }
        const [rm, ro] = region(cpc, r[4], 4, true);
        store(rm, ro, 4, res);
        break;
      }
      case "abort": throw new VmError("ProgramAborted", cpc);
      case "sol_panic_": throw new VmError("ProgramPanicked", cpc);
      default: throw new VmError("UnknownSyscall", cpc);
    }
    r[0] = 0n;
  };

  const alu = (cpc, opc, a, b, isReg, imm) => {
    const op = opc & 0xf0;
    if ((opc & 7) === 7) {
      if (!isReg) b = sext32(b);
      switch (op) {
        case 0x00: return (a + b) & U64;
        case 0x10: return (a - b) & U64;
        case 0x20: return (a * b) & U64;
        case 0x30: if (b === 0n) throw new VmError("DivisionByZero", cpc); return a / b;
        case 0x40: return a | b;
        case 0x50: return a & b;
        case 0x60: return (a << (b & 63n)) & U64;
        case 0x70: return a >> (b & 63n);
        case 0x80: if (isReg) throw new VmError("InvalidInstruction", cpc); return (-a) & U64;
        case 0x90: if (b === 0n) throw new VmError("DivisionByZero", cpc); return a % b;
        case 0xa0: return a ^ b;
        case 0xb0: return b;
        case 0xc0: return BigInt.asUintN(64, s64(a) >> (b & 63n));
      }
      throw new VmError("InvalidInstruction", cpc);
    }
    const a32 = a & U32, b32 = b & U32;
    switch (op) {
      case 0x00: return sext32((a32 + b32) & U32);
      case 0x10: return sext32((a32 - b32) & U32);
      case 0x20: return sext32((a32 * b32) & U32);
      case 0x30: if (b32 === 0n) throw new VmError("DivisionByZero", cpc); return a32 / b32;
      case 0x40: return a32 | b32;
      case 0x50: return a32 & b32;
      case 0x60: return (a32 << (b32 & 31n)) & U32;
      case 0x70: return a32 >> (b32 & 31n);
      case 0x80: if (isReg) throw new VmError("InvalidInstruction", cpc); return (-a32) & U32;
      case 0x90: if (b32 === 0n) throw new VmError("DivisionByZero", cpc); return a32 % b32;
      case 0xa0: return a32 ^ b32;
      case 0xb0: return b32;
      case 0xc0: return BigInt.asUintN(32, s32(a32) >> (b32 & 31n));
      case 0xd0: {
        if (imm !== 16n && imm !== 32n && imm !== 64n) throw new VmError("InvalidInstruction", cpc);
        const nb = Number(imm) / 8;
        if (!isReg) return a & ((1n << imm) - 1n);
        let out = 0n; for (let i = 0; i < nb; i++) out = (out << 8n) | ((a >> BigInt(8 * i)) & 0xffn);
        return out;
      }
    }
    throw new VmError("InvalidInstruction", cpc);
  };

  for (;;) {
    if (steps >= budget) throw new VmError("ComputeBudgetExceeded", pc);
    steps++;
    if (pc < 0 || pc >= n) throw new VmError("PcOutOfBounds", pc);
    const cpc = pc, base = pc * 8;
    const opc = prog[base], dst = prog[base + 1] & 0xf, src = prog[base + 1] >> 4;
    const off = BigInt(prog.readInt16LE(base + 2)), imm = BigInt(prog.readUInt32LE(base + 4));
    if (dst > 10 || src > 10) throw new VmError("InvalidRegister", cpc);
    pc = cpc + 1;
    const cls = opc & 7;
    const isRegOp = (opc & 8) !== 0;
    const jumpTo = () => { const t = (BigInt(cpc) + 1n + off) & U64; pc = t > BigInt(n) ? n : Number(t); };
    if (cls === 7 || cls === 4) {
      if (dst === 10) throw new VmError("InvalidRegister", cpc);
      r[dst] = alu(cpc, opc, r[dst], isRegOp ? r[src] : imm, isRegOp, imm);
    } else if (cls === 5) {
      if (opc === 0x05) { jumpTo(); continue; }
      if (opc === 0x95) {
        if (frames.length === 0) break;
        const f = frames.pop();
        [r[6], r[7], r[8], r[9]] = f; pc = f[4]; r[10] -= FRAME_SIZE; continue;
      }
      if (opc === 0x85) {
        if (src === 0) { syscall(cpc, imm); continue; }
        if (src !== 1) throw new VmError("InvalidInstruction", cpc);
        pushFrame(cpc, (BigInt(cpc) + 1n + sext32(imm)) & U64); continue;
      }
      if (opc === 0x8d) {
        const t = r[src];
        if (t < MM_PROGRAM || (t - MM_PROGRAM) % 8n !== 0n) throw new VmError("InvalidCallTarget", cpc);
        pushFrame(cpc, (t - MM_PROGRAM) / 8n); continue;
      }
      const a = r[dst], b = isRegOp ? r[src] : sext32(imm), op = opc & 0xf0;
      let taken;
      switch (op) {
        case 0x10: taken = a === b; break;
        case 0x20: taken = a > b; break;
        case 0x30: taken = a >= b; break;
        case 0x40: taken = (a & b) !== 0n; break;
        case 0x50: taken = a !== b; break;
        case 0x60: taken = s64(a) > s64(b); break;
        case 0x70: taken = s64(a) >= s64(b); break;
        case 0xa0: taken = a < b; break;
        case 0xb0: taken = a <= b; break;
        case 0xc0: taken = s64(a) < s64(b); break;
        case 0xd0: taken = s64(a) <= s64(b); break;
        default: throw new VmError("InvalidInstruction", cpc);
      }
      if (taken) jumpTo();
    } else if (cls === 1) {
      if (dst === 10) throw new VmError("InvalidRegister", cpc);
      const sz = size(cpc, opc, 0x61);
      const [m, o] = region(cpc, (r[src] + off) & U64, sz, false);
      r[dst] = load(m, o, sz);
    } else if (cls === 2) {
      const sz = size(cpc, opc, 0x62);
      const [m, o] = region(cpc, (r[dst] + off) & U64, sz, true);
      store(m, o, sz, sext32(imm));
    } else if (cls === 3) {
      const sz = size(cpc, opc, 0x63);
      const [m, o] = region(cpc, (r[dst] + off) & U64, sz, true);
      store(m, o, sz, r[src]);
    } else if (opc === 0x18) {
      if (dst === 10) throw new VmError("InvalidRegister", cpc);
      if (cpc + 1 >= n) throw new VmError("PcOutOfBounds", cpc + 1);
      r[dst] = imm | (BigInt(prog.readUInt32LE(base + 12)) << 32n);
      pc = cpc + 2;
    } else throw new VmError("InvalidInstruction", cpc);
  }
  return { r0: r[0], steps, input, logs };
}

module.exports = { run, VmError, MM_PROGRAM, MM_STACK, MM_HEAP, MM_INPUT };
