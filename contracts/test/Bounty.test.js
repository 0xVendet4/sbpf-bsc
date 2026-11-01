const { expect } = require("chai");
const { ethers } = require("hardhat");
const { deployVM } = require("./helpers");
const { program, slower, WRONG, mineTo, salt, hashOf } = require("./golfHelpers");

describe("BountyBoard", function () {
  let vm, token, board, usd, P, A, B, C;
  const REWARD = ethers.parseEther("500");
  const FEE = ethers.parseEther("5");

  before(async () => {
    [P, A, B, C] = await ethers.getSigners();
    vm = await deployVM();
    token = await (await ethers.getContractFactory("GolfToken")).deploy();
    await token.setMinter(P.address); // só no teste: P emite GOLF para pagar a taxa
    await token.mint(P.address, ethers.parseEther("100"));
    board = await (await ethers.getContractFactory("BountyBoard")).deploy(vm, token, FEE);
    usd = await (await ethers.getContractFactory("MockUSD")).deploy();
    await usd.mint(P.address, ethers.parseEther("10000"));
    await usd.connect(P).approve(board, ethers.MaxUint256);
    await token.connect(P).approve(board, ethers.MaxUint256);
  });

  const le64 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return "0x" + b.toString("hex"); };

  function postParams(over = {}) {
    return {
      rewardToken: usd, reward: REWARD, refProgram: program("isqrt"), maxCu: 5000, inputLen: 8,
      edgeInputs: [le64(0), le64(1), le64(2n ** 64n - 1n)], spec: "floor(sqrt(x)) para u64",
      commitBlocks: 10, revealBlocks: 20, ...over,
    };
  }

  it("postar queima a taxa em GOLF e deposita o prêmio em qualquer ERC-20", async () => {
    await expect(board.connect(P).post(postParams({ refProgram: WRONG.slice(0, 10) }))).to.be.revertedWithCustomError(board, "ReferenceRejected");
    await expect(board.connect(P).post(postParams({ revealBlocks: 8001 }))).to.be.revertedWithCustomError(board, "BadParams");
    const supply = await token.totalSupply();
    await expect(board.connect(P).post(postParams())).to.emit(board, "Posted").withArgs(0, P.address, await usd.getAddress(), REWARD, "floor(sqrt(x)) para u64");
    expect(await token.totalSupply()).to.equal(supply - FEE);
    expect(await usd.balanceOf(board)).to.equal(REWARD);
    const [active, ref, maxCu, inputLen] = await board.referenceSpec(0);
    expect(active).to.equal(true);
    expect(ref).to.equal(program("isqrt"));
    expect(maxCu).to.equal(5000n);
    expect(inputLen).to.equal(8n);
  });

  it("disputa: menor CU com todas as respostas iguais à referência ganha o prêmio", async () => {
    const b = await board.bounty(0);
    await board.connect(A).commit(0, hashOf(A.address, 0, program("isqrt"), salt("a")));
    await board.connect(B).commit(0, hashOf(B.address, 0, slower(program("isqrt"), 2), salt("b")));
    await board.connect(C).commit(0, hashOf(C.address, 0, WRONG, salt("c")));
    await mineTo(b.commitEnd + 1n);

    const txB = await board.connect(B).reveal(0, slower(program("isqrt"), 2), salt("b"));
    const evB = (await txB.wait()).logs.map((l) => { try { return board.interface.parseLog(l); } catch { return null; } }).find((e) => e && e.name === "Revealed");
    expect(evB.args.isBest).to.equal(true);
    const txA = await board.connect(A).reveal(0, program("isqrt"), salt("a"));
    const evA = (await txA.wait()).logs.map((l) => { try { return board.interface.parseLog(l); } catch { return null; } }).find((e) => e && e.name === "Revealed");
    expect(evA.args.isBest).to.equal(true);
    expect(evB.args.totalCu - evA.args.totalCu).to.equal(2n * 7n); // 2 nops x (4 aleatórios + 3 bordas)
    console.log(`      isqrt: ${evA.args.totalCu} CU em 7 inputs`);
    await expect(board.connect(C).reveal(0, WRONG, salt("c"))).to.be.revertedWithCustomError(board, "ProgramRejected");

    await expect(board.finalize(0)).to.be.revertedWithCustomError(board, "NotOver");
    await mineTo(b.revealEnd + 1n);
    await expect(board.finalize(0)).to.emit(board, "Finalized").withArgs(0, A.address, evA.args.totalCu, REWARD);
    expect(await usd.balanceOf(A.address)).to.equal(REWARD);
    const [active] = await board.referenceSpec(0);
    expect(active).to.equal(false);
    await expect(board.finalize(0)).to.be.revertedWithCustomError(board, "AlreadyFinalized");
  });

  it("sem vencedor, o prêmio volta para quem postou", async () => {
    await board.connect(P).post(postParams({ refProgram: program("gcd"), inputLen: 16, edgeInputs: [], spec: "gcd" }));
    const b = await board.bounty(1);
    await board.connect(A).commit(1, hashOf(A.address, 1, WRONG, salt("a")));
    await mineTo(b.commitEnd + 1n);
    await expect(board.connect(A).reveal(1, WRONG, salt("a"))).to.be.revertedWithCustomError(board, "ProgramRejected");
    await mineTo(b.revealEnd + 1n);
    const bal = await usd.balanceOf(P.address);
    await board.finalize(1);
    expect(await usd.balanceOf(P.address)).to.equal(bal + REWARD);
  });

  it("inputs em que a referência falha são descartados", async () => {
    // referência que só aceita inputs de 16 bytes: com inputLen 8 todos os aleatórios dão AccessViolation
    // e só sobram os casos de borda (um de 16 bytes)
    await board.connect(P).post(postParams({ refProgram: program("gcd"), inputLen: 8, edgeInputs: [le64(12) + le64(18).slice(2)], spec: "gcd" }));
    const b = await board.bounty(2);
    await board.connect(A).commit(2, hashOf(A.address, 2, program("gcd"), salt("a")));
    await mineTo(b.commitEnd + 1n);
    const tx = await board.connect(A).reveal(2, program("gcd"), salt("a"));
    const ev = (await tx.wait()).logs.map((l) => { try { return board.interface.parseLog(l); } catch { return null; } }).find((e) => e && e.name === "Revealed");
    expect(ev.args.totalCu).to.equal(22n); // gcd(12, 18): 22 CU (ver fixtures/programs.json gcd_3)
  });
});
