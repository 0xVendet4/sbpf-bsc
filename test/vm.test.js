const { expect } = require("chai");
const { ethers } = require("hardhat");
const jsvm = require("../js/vm");
const { prog, u64le, execSol, deployRuntime, assemble } = require("./helpers");

const M64 = (1n << 64n) - 1n;

describe("SbpfVM (Solidity)", function () {
  let rt;
  before(async () => { rt = await deployRuntime(); });

  it("hello world: sol_log_ lendo rodata", async () => {
    const r = await execSol(rt, prog("hello"), Buffer.alloc(0));
    expect(r.ok).to.equal(true);
    expect(r.r0).to.equal(0n);
    expect(r.logs.length).to.equal(1);
    expect(Buffer.from(r.logs[0].data.slice(2), "hex").toString()).to.equal("Hello from sBPF/BSC");
  });

  it("fib com chamadas internas (frames)", async () => {
    for (const [n, f] of [[0, 0n], [1, 1n], [2, 1n], [10, 55n], [50, 12586269025n], [90, 2880067194370816120n]]) {
      const r = await execSol(rt, prog("fib"), u64le(n));
      expect(r.r0, `fib(${n})`).to.equal(f);
    }
  });

  it("sol_keccak256 usa o keccak nativo da EVM", async () => {
    const msg = Buffer.from("Solana dentro da BSC");
    const input = Buffer.concat([u64le(msg.length), msg, Buffer.alloc(32)]);
    const r = await execSol(rt, prog("keccak"), input);
    expect(r.ok).to.equal(true);
    expect("0x" + r.input.subarray(8 + msg.length).toString("hex")).to.equal(ethers.keccak256(msg));
  });

  const cases = [
    // [asm, r0 esperado]
    ["mov64 r0, -1\nexit", M64],
    ["mov32 r0, -1\nexit", 0xffffffffn],
    ["lddw r0, 0x7fffffff\nadd32 r0, 1\nexit", 0xffffffff80000000n], // sBPF v1: add32 com sinal
    ["mov64 r0, 0\nsub64 r0, 1\nexit", M64],
    ["lddw r0, 0xffffffffffffffff\nmul64 r0, 3\nexit", M64 - 2n],
    ["mov64 r0, 100\ndiv64 r0, 7\nexit", 14n],
    ["mov64 r0, 100\nmod64 r0, 7\nexit", 2n],
    ["mov64 r0, -8\narsh64 r0, 1\nexit", BigInt.asUintN(64, -4n)],
    ["mov64 r0, -8\nrsh64 r0, 60\nexit", 0xfn],
    ["mov64 r0, 1\nlsh64 r0, 63\nexit", 1n << 63n],
    ["mov64 r0, 1\nmov64 r1, 65\nlsh64 r0, r1\nexit", 2n], // shift mascarado
    ["mov64 r0, 5\nneg64 r0\nexit", BigInt.asUintN(64, -5n)],
    ["mov64 r0, 5\nneg32 r0\nexit", 0xfffffffbn],
    ["mov32 r0, -8\narsh32 r0, 1\nexit", 0xfffffffcn],
    ["lddw r0, 0x1122334455667788\nbe64 r0\nexit", 0x8877665544332211n],
    ["lddw r0, 0x1122334455667788\nbe16 r0\nexit", 0x8877n],
    ["lddw r0, 0x1122334455667788\nle32 r0\nexit", 0x55667788n],
    ["mov64 r1, -1\nmov64 r0, 0\njsgt r1, 0, x\nmov64 r0, 7\nx:\nexit", 7n],
    ["mov64 r1, -1\nmov64 r0, 0\njgt r1, 0, x\nmov64 r0, 7\nx:\nexit", 0n],
    ["mov64 r0, 6\njset r0, 4, x\nmov64 r0, 0\nx:\nexit", 6n],
    ["stdw [r10-8], -2\nldxw r0, [r10-8]\nexit", 0xfffffffen],
    ["mov64 r1, 0x1234\nstxh [r10-2], r1\nldxb r0, [r10-1]\nexit", 0x12n],
  ];
  for (const [asm, want] of cases) {
    it(`opcode: ${asm.split("\n").slice(0, -1).join("; ")}`, async () => {
      const code = assemble(asm);
      const r = await execSol(rt, code, Buffer.alloc(0));
      expect(r.ok, r.kind).to.equal(true);
      expect(r.r0).to.equal(want);
      expect(jsvm.run(code, Buffer.alloc(0), 1000).r0).to.equal(want);
    });
  }

  const errors = [
    ["mov64 r0, 1\ndiv64 r0, 0\nexit", "DivisionByZero"],
    ["lddw r1, 0x500000000\nldxdw r0, [r1+0]\nexit", "AccessViolation"],
    ["lddw r1, 0x100000000\nstdw [r1+0], 1\nexit", "AccessViolation"], // programa é somente leitura
    ["lddw r1, 0x200004000\nldxb r0, [r1+0]\nexit", "AccessViolation"], // 1 byte além do fim da pilha (4 frames x 4 KiB)
    ["x:\nja x", "ComputeBudgetExceeded"],
    ["mov64 r10, 0\nexit", "InvalidRegister"],
    ["call abort", "ProgramAborted"],
    ["f:\ncall f", "CallDepthExceeded"],
    ["mov64 r0, 0", "PcOutOfBounds"],
  ];
  for (const [asm, kind] of errors) {
    it(`erro ${kind}: ${asm.replace(/\n/g, "; ")}`, async () => {
      const code = assemble(asm);
      const r = await execSol(rt, code, Buffer.alloc(0), 5000);
      let jsKind;
      try { jsvm.run(code, Buffer.alloc(0), 5000); } catch (e) { jsKind = e.kind; }
      expect(r.ok).to.equal(false);
      expect(r.kind).to.equal(kind);
      expect(jsKind).to.equal(kind);
    });
  }

  it("instrução inválida", async () => {
    const r = await execSol(rt, Buffer.from("ff00000000000000", "hex"), Buffer.alloc(0));
    expect(r.kind).to.equal("InvalidInstruction");
  });
});
