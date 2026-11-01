// Fuzz diferencial: programas aleatórios executados na VM Solidity e na VM JS de referência.
const { expect } = require("chai");
const jsvm = require("../js/vm");
const { execSol, deployRuntime, assemble } = require("./helpers");

let seed = 0xC0FFEEn;
function rnd() { seed = (seed * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n); return seed >> 11n; }
const pick = (a) => a[Number(rnd() % BigInt(a.length))];
const IMMS = ["0", "1", "-1", "2", "7", "31", "32", "63", "64", "0x7fffffff", "-2147483648", "255", "-256"];
const ALU = ["add", "sub", "mul", "div", "or", "and", "lsh", "rsh", "mod", "xor", "mov", "arsh"];
const JMP = ["jeq", "jgt", "jge", "jset", "jne", "jsgt", "jsge", "jlt", "jle", "jslt", "jsle"];

function genProgram(len) {
  const lines = [];
  for (let i = 0; i <= 9; i++) lines.push(`lddw r${i}, ${BigInt.asIntN(64, rnd() * 2654435761n)}`);
  let lbl = 0;
  const pending = [];
  for (let i = 0; i < len; i++) {
    const r = () => `r${Number(rnd() % 10n)}`;
    const imm = () => (rnd() % 3n === 0n ? String(BigInt.asIntN(32, rnd())) : pick(IMMS));
    const k = Number(rnd() % 10n);
    if (pending.length && rnd() % 4n === 0n) lines.push(`${pending.shift()}:`);
    if (k < 5) {
      const op = pick(ALU), w = pick(["64", "32"]);
      lines.push(`${op}${w} ${r()}, ${rnd() % 2n ? r() : imm()}`);
    } else if (k === 5) {
      lines.push(`${pick(["neg64", "neg32", "be16", "be32", "be64", "le16", "le32", "le64"])} ${r()}`);
    } else if (k === 6) {
      const name = `L${lbl++}`; pending.push(name);
      lines.push(`${pick(JMP)} ${r()}, ${rnd() % 2n ? r() : imm()}, ${name}`);
    } else if (k === 7) {
      const sz = pick(["b", "h", "w", "dw"]);
      lines.push(`stx${sz} [r10-${8 * (1 + Number(rnd() % 8n))}], ${r()}`);
    } else if (k === 8) {
      const sz = pick(["b", "h", "w", "dw"]);
      lines.push(`ldx${sz} ${r()}, [r10-${8 * (1 + Number(rnd() % 8n))}]`);
    } else {
      lines.push(`st${pick(["b", "h", "w", "dw"])} [r10-${8 * (1 + Number(rnd() % 8n))}], ${imm()}`);
    }
  }
  for (const p of pending) lines.push(`${p}:`);
  for (let i = 1; i <= 9; i++) { lines.push(`xor64 r0, r${i}`); lines.push(`lsh64 r0, 3`); lines.push(`add64 r0, r${i}`); }
  lines.push("exit");
  return lines.join("\n");
}

describe("Fuzz diferencial Solidity x JS", function () {
  this.timeout(600000);
  let rt;
  before(async () => { rt = await deployRuntime(); });

  it("300 programas aleatórios dão o mesmo resultado", async () => {
    let ok = 0, err = 0;
    for (let t = 0; t < 300; t++) {
      const asm = genProgram(20 + (t % 40));
      const code = assemble(asm);
      let js;
      try { const r = jsvm.run(code, Buffer.alloc(0), 100000); js = { ok: true, r0: r.r0, steps: r.steps }; }
      catch (e) { if (!e.kind) throw e; js = { ok: false, kind: e.kind }; }
      const sol = await execSol(rt, code, Buffer.alloc(0), 100000);
      const ctx = `programa #${t}:\n${asm}`;
      expect(sol.ok, ctx).to.equal(js.ok);
      if (js.ok) { expect(sol.r0, ctx).to.equal(js.r0); expect(sol.steps, ctx).to.equal(js.steps); ok++; }
      else { expect(sol.kind, ctx).to.equal(js.kind); err++; }
    }
    console.log(`      ${ok} sucesso, ${err} com erro (ex.: divisão por zero), todos idênticos`);
  });
});
