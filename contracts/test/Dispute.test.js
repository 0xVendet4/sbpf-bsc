const { expect } = require("chai");
const { ethers } = require("hardhat");
const { deployVM, loadFixtures } = require("./helpers");
const { mine } = require("./golfHelpers");

const BOND = ethers.parseEther("0.01");
const CHALLENGE = 20n, MOVE = 10n;
const ZERO_STACK = "0x" + "00".repeat(4096);
const asStruct = (t) => ({ pc: t.pc, cu: t.cu, halted: t.halted, status: t.status, regs: [...t.regs], stackHash: t.stackHash });

// Provador fora da cadeia: a cadeia de estados honesta de um programa, via `trace`.
async function honestTrace(vm, fx) {
  let s = asStruct(await vm.initialState()), stack = ZERO_STACK;
  const states = [{ s, stack, hash: await vm.stateHash(s) }];
  while (!s.halted) {
    const [t, out] = await vm.trace(s, stack, fx.program, fx.input, fx.maxCu, 1);
    s = asStruct(t); stack = out;
    states.push({ s, stack, hash: await vm.stateHash(s) });
  }
  return states; // states[k] = estado após k instruções; último está parado
}

describe("SbpfDispute (prova de fraude por bisseção)", function () {
  let vm, dispute, A, B, fx, chain, steps;

  before(async () => {
    [A, B] = await ethers.getSigners();
    vm = await deployVM();
    dispute = await (await ethers.getContractFactory("SbpfDispute")).deploy(vm, BOND, CHALLENGE, MOVE);
    fx = loadFixtures("programs").find((f) => f.name === "isqrt_8"); // u64::MAX
    chain = await honestTrace(vm, fx);
    steps = chain.length - 1;
    console.log(`      ${fx.name}: ${steps} instruções, resultado r0 = 0x${chain[steps].s.regs[0].toString(16)}`);
    expect(chain[steps].s.halted).to.equal(true);
  });

  const inputHash = () => ethers.keccak256(fx.input);

  async function assertAs(who, endHash, n = steps) {
    const tx = await dispute.connect(who).assertRun(fx.program, inputHash(), fx.maxCu, n, endHash, { value: BOND });
    const rc = await tx.wait();
    const ev = rc.logs.map((l) => { try { return dispute.interface.parseLog(l); } catch { return null; } }).find((e) => e?.name === "Asserted");
    return ev.args.id;
  }

  // joga a bisseção: `asserterHash(k)` é o que quem afirmou posta; o contestador honesto compara com a cadeia
  async function play(id, asserter, challenger, asserterHash) {
    for (;;) {
      const c = await dispute.claim(id);
      if (c.phase === 3n) return c; // Proving
      const mid = (c.lo + c.hi) / 2n;
      await dispute.connect(asserter).bisect(id, asserterHash(Number(mid)));
      const honest = chain[Number(mid)]?.hash; // além do fim: não existe estado honesto, discorda
      await dispute.connect(challenger).choose(id, asserterHash(Number(mid)) !== honest);
    }
  }

  it("afirmação sem contestação é confirmada depois da janela", async () => {
    const id = await assertAs(A, chain[steps].hash);
    await expect(dispute.timeout(id)).to.be.revertedWithCustomError(dispute, "NotExpired");
    await mine(Number(CHALLENGE) + 1);
    await expect(dispute.connect(B).challenge(id, { value: BOND })).to.be.revertedWithCustomError(dispute, "Expired");
    const bal = await ethers.provider.getBalance(A.address);
    await expect(dispute.connect(B).timeout(id)).to.emit(dispute, "Resolved").withArgs(id, true, A.address);
    expect(await ethers.provider.getBalance(A.address)).to.equal(bal + BOND);
    const r = await dispute.result(id);
    expect(r.endHash).to.equal(chain[steps].hash);
  });

  it("afirmação honesta: contestador perde no passo final", async () => {
    const id = await assertAs(A, chain[steps].hash);
    await dispute.connect(B).challenge(id, { value: BOND });
    // contestador desonesto: sempre discorda do lado esquerdo (não tem como ganhar)
    let c;
    for (;;) {
      c = await dispute.claim(id);
      if (c.phase === 3n) break;
      const mid = Number((c.lo + c.hi) / 2n);
      await dispute.connect(A).bisect(id, chain[mid].hash);
      await dispute.connect(B).choose(id, true);
    }
    expect(c.hi - c.lo).to.equal(1n);
    const k = Number(c.lo);
    const bal = await ethers.provider.getBalance(A.address);
    const tx = await dispute.connect(B).prove(id, chain[k].s, chain[k].stack, fx.program, fx.input); // qualquer um pode chamar
    await expect(tx).to.emit(dispute, "Resolved").withArgs(id, true, A.address);
    expect(await ethers.provider.getBalance(A.address)).to.equal(bal + 2n * BOND);
    console.log(`      prova de um passo: ${(await tx.wait()).gasUsed} gas`);
  });

  it("afirmação falsa (r0 errado no fim): contestador honesto ganha", async () => {
    // estados honestos até o penúltimo; o último tem r0 + 1
    const fake = { ...chain[steps].s, regs: chain[steps].s.regs.map((v, i) => (i === 0 ? v + 1n : v)) };
    const fakeHash = await vm.stateHash(fake);
    const id = await assertAs(A, fakeHash);
    await dispute.connect(B).challenge(id, { value: BOND });
    const c = await play(id, A, B, (k) => (k === steps ? fakeHash : chain[k].hash));
    expect(Number(c.lo)).to.equal(steps - 1);
    const k = Number(c.lo);
    const bal = await ethers.provider.getBalance(B.address);
    // quem afirmou tenta provar: o passo honesto não bate com o hash falso
    const tx = await dispute.connect(A).prove(id, chain[k].s, chain[k].stack, fx.program, fx.input);
    await expect(tx).to.emit(dispute, "Resolved").withArgs(id, false, B.address);
    expect(await ethers.provider.getBalance(B.address)).to.equal(bal + 2n * BOND);
  });

  it("afirmação falsa no meio: a bisseção encontra a instrução errada", async () => {
    const bad = 5; // a partir da instrução 5 os hashes são inventados
    const fakeAt = (k) => (k < bad ? chain[k].hash : ethers.keccak256(ethers.toBeHex(k, 32)));
    const id = await assertAs(A, fakeAt(steps));
    await dispute.connect(B).challenge(id, { value: BOND });
    const c = await play(id, A, B, fakeAt);
    expect(Number(c.lo)).to.equal(bad - 1);
    expect(c.loHash).to.equal(chain[bad - 1].hash);
    // ninguém consegue provar o hash inventado; quem afirmou perde por prazo
    await expect(dispute.connect(A).prove(id, chain[bad - 1].s, chain[bad - 1].stack, fx.program, fx.input))
      .to.emit(dispute, "Resolved").withArgs(id, false, B.address);
  });

  it("número de instruções errado (programa para antes): quem afirmou não consegue provar e perde por prazo", async () => {
    const id = await assertAs(A, chain[steps].hash, steps + 3);
    await dispute.connect(B).challenge(id, { value: BOND });
    // contestador honesto: para k > steps não existe estado; discorda
    const c = await play(id, A, B, (k) => (k <= steps ? chain[k].hash : ethers.keccak256(ethers.toBeHex(k, 32))));
    expect(Number(c.lo)).to.equal(steps);
    // o estado após `steps` está parado: step reverte
    await expect(dispute.connect(A).prove(id, chain[steps].s, chain[steps].stack, fx.program, fx.input)).to.be.revertedWithCustomError(vm, "StateHalted");
    await mine(Number(MOVE) + 1);
    await expect(dispute.timeout(id)).to.emit(dispute, "Resolved").withArgs(id, false, B.address);
  });

  it("quem afirmou some depois da contestação: perde por prazo", async () => {
    const id = await assertAs(A, chain[steps].hash);
    await dispute.connect(B).challenge(id, { value: BOND });
    await expect(dispute.connect(B).bisect(id, chain[1].hash)).to.be.revertedWithCustomError(dispute, "NotYourMove");
    await mine(Number(MOVE) + 1);
    await expect(dispute.connect(A).bisect(id, chain[1].hash)).to.be.revertedWithCustomError(dispute, "Expired");
    await expect(dispute.timeout(id)).to.emit(dispute, "Resolved").withArgs(id, false, B.address);
  });

  it("quem contestou some: afirmação confirmada", async () => {
    const id = await assertAs(A, chain[steps].hash);
    await dispute.connect(B).challenge(id, { value: BOND });
    await dispute.connect(A).bisect(id, chain[Math.floor(steps / 2)].hash);
    await mine(Number(MOVE) + 1);
    await expect(dispute.timeout(id)).to.emit(dispute, "Resolved").withArgs(id, true, A.address);
  });

  it("recusa programa inválido, caução errada e prova com programa/input trocados", async () => {
    await expect(dispute.assertRun("0x", inputHash(), fx.maxCu, 1, chain[steps].hash, { value: BOND })).to.be.revertedWithCustomError(dispute, "BadClaim");
    await expect(dispute.assertRun(fx.program, inputHash(), fx.maxCu, steps, chain[steps].hash, { value: 1n })).to.be.revertedWithCustomError(dispute, "BadBond");
    const id = await assertAs(A, chain[steps].hash, 1);
    await dispute.connect(B).challenge(id, { value: BOND }); // steps == 1: vai direto para a prova
    expect((await dispute.claim(id)).phase).to.equal(3n);
    await expect(dispute.prove(id, chain[0].s, chain[0].stack, fx.program, "0x1234")).to.be.revertedWithCustomError(dispute, "BadProof");
    await expect(dispute.prove(id, chain[1].s, chain[1].stack, fx.program, fx.input)).to.be.revertedWithCustomError(dispute, "BadProof");
  });
});
