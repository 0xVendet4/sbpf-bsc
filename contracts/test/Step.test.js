const { expect } = require("chai");
const { ethers } = require("hardhat");
const { deployVM, loadFixtures } = require("./helpers");

// Equivalência passo a passo: aplicar `step`/`trace` a partir do estado inicial até parar dá o
// mesmo (status, r0, cu) que `execute`, para todos os fixtures que passam no verificador.
describe("Passo único (prova de fraude)", function () {
  let vm, ZERO_STACK, s0;
  const SETS = ["opcodes", "memory", "invalid", "programs", "random"];

  before(async () => {
    vm = await deployVM();
    ZERO_STACK = "0x" + "00".repeat(4096);
    s0 = await vm.initialState();
    expect(s0.stackHash).to.equal(ethers.keccak256(ZERO_STACK));
  });

  const asStruct = (t) => ({ pc: t.pc, cu: t.cu, halted: t.halted, status: t.status, regs: [...t.regs], stackHash: t.stackHash });

  async function runSteps(fx, chunk) {
    let s = asStruct(s0), stack = ZERO_STACK, steps = 0;
    while (!s.halted) {
      const budget = chunk(steps);
      const [t, out] = await vm.trace(s, stack, fx.program, fx.input, fx.maxCu, budget);
      s = asStruct(t); stack = out; steps += Number(budget);
      if (steps > 20_000) throw new Error("não parou");
    }
    return s;
  }

  for (const set of SETS) {
    it(`fixtures/${set}.json`, async function () {
      const fixtures = loadFixtures(set);
      let stepped = 0, rejected = 0, totalSteps = 0;
      let seed = 7;
      const rnd = (n) => { seed = (seed * 48271) % 2147483647; return 1 + (seed % n); };
      for (const fx of fixtures) {
        if (!(await vm.verify(fx.program))) {
          expect(fx.expect.status).to.equal("Invalid");
          rejected++;
          continue;
        }
        const cu = Number(fx.expect.cu);
        // até 100 instruções: uma por chamada; acima disso, 20 de uma em uma e depois blocos aleatórios
        const s = await runSteps(fx, (k) => (cu <= 100 || k < 20 ? 1n : BigInt(rnd(97))));
        const status = ["Ok", "Invalid", "DivideByZero", "AccessViolation", "CuExceeded"][Number(s.status)];
        const r0 = status === "Ok" ? s.regs[0] : 0n;
        expect({ status, r0: "0x" + r0.toString(16), cu: Number(s.cu) }, fx.name).to.deep.equal({ status: fx.expect.status, r0: fx.expect.r0, cu: cu });
        stepped++;
        totalSteps += cu;
      }
      console.log(`      ${stepped} programas executados passo a passo (${totalSteps} instruções), ${rejected} recusados pelo verificador`);
    });
  }

  it("step == trace com orçamento 1, e o hash do estado é determinístico", async () => {
    const fx = loadFixtures("programs").find((f) => f.name === "isqrt_8"); // u64::MAX: caminho longo
    let s = asStruct(s0), stack = ZERO_STACK;
    const hashes = [await vm.stateHash(s)];
    for (let i = 0; i < 40 && !s.halted; i++) {
      const t1 = asStruct(await vm.step(s, stack, fx.program, fx.input, fx.maxCu));
      const [t2, out] = await vm.trace(s, stack, fx.program, fx.input, fx.maxCu, 1);
      expect(await vm.stateHash(t1)).to.equal(await vm.stateHash(asStruct(t2)));
      s = t1; stack = out;
      hashes.push(await vm.stateHash(s));
    }
    // o estado após k passos, pedido de uma vez, bate com o encadeado
    for (const k of [1, 7, 23, 40]) {
      const [tk] = await vm.trace(asStruct(s0), ZERO_STACK, fx.program, fx.input, fx.maxCu, k);
      expect(await vm.stateHash(asStruct(tk))).to.equal(hashes[k]);
    }
    expect(new Set(hashes).size).to.equal(hashes.length);
  });

  it("recusa pilha errada e estado parado", async () => {
    const fx = loadFixtures("programs")[0];
    const bad = "0x01" + "00".repeat(4095);
    await expect(vm.step(asStruct(s0), bad, fx.program, fx.input, fx.maxCu)).to.be.revertedWithCustomError(vm, "BadStack");
    const halted = { ...asStruct(s0), halted: true };
    await expect(vm.step(halted, ZERO_STACK, fx.program, fx.input, fx.maxCu)).to.be.revertedWithCustomError(vm, "StateHalted");
  });

  it("gas de um passo on-chain", async () => {
    const fx = loadFixtures("programs").find((f) => f.name === "max8_0");
    const [s1, stack1] = await vm.trace(asStruct(s0), ZERO_STACK, fx.program, fx.input, fx.maxCu, 3);
    const gas = await vm.step.estimateGas(asStruct(s1), stack1, fx.program, fx.input, fx.maxCu);
    console.log(`      step: ${gas} gas (pilha de 4 KiB em calldata)`);
    expect(gas).to.be.lt(200_000n);
  });
});
