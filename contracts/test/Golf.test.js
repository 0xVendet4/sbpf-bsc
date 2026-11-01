const { expect } = require("chai");
const { ethers } = require("hardhat");
const { deployVM } = require("./helpers");
const { program, slower, WRONG, mine, mineTo, salt, hashOf } = require("./golfHelpers");

const FEE = ethers.parseEther("10");
const REWARD = ethers.parseEther("100");
const COMMIT = 10n, REVEAL = 20n;

describe("SbpfGolf (CU Golf)", function () {
  let vm, token, golf, board, usd, A, B, C, D;

  before(async () => {
    [A, B, C, D] = await ethers.getSigners();
    vm = await deployVM();
    token = await (await ethers.getContractFactory("GolfToken")).deploy();
    // taxa 10 GOLF (50% queimada), 1 rodada grátis, commit 10 blocos, reveal 20 blocos
    golf = await (await ethers.getContractFactory("SbpfGolf")).deploy(vm, token, FEE, 5000, 1, COMMIT, REVEAL);
    await token.setMinter(golf);
    board = await (await ethers.getContractFactory("BountyBoard")).deploy(vm, token, ethers.parseEther("5"));
    await golf.setBountyBoard(board);
    usd = await (await ethers.getContractFactory("MockUSD")).deploy();
  });

  async function commitAs(signer, prog, s) {
    const r = await golf.round();
    await golf.connect(signer).commit(hashOf(signer.address, r, prog, salt(s)));
  }

  it("rodada 1: tarefa 1 (popcount), sem taxa", async () => {
    const r = await golf.currentRound();
    expect(r.task).to.equal(1n);
    expect(await golf.taskName(1)).to.equal("popcount");
    expect(await golf.entryFee()).to.equal(0n);
  });

  it("commit, reveal e vencedor por menor CU", async () => {
    const r = await golf.currentRound();
    await commitAs(A, program("popcount"), "a");
    await commitAs(B, slower(program("popcount")), "b");
    await commitAs(C, WRONG, "c");
    await commitAs(D, program("popcount"), "d"); // D nunca revela
    await expect(commitAs(A, program("popcount"), "a2")).to.be.revertedWithCustomError(golf, "AlreadyCommitted");

    // ainda na janela de commit: reveal não pode
    await expect(golf.connect(A).reveal(program("popcount"), salt("a"))).to.be.revertedWithCustomError(golf, "NotRevealWindow");
    await mineTo(r.commitEnd + 1n);
    await expect(commitAs(B, program("popcount"), "x")).to.be.revertedWithCustomError(golf, "NotCommitWindow");

    // salt errado
    await expect(golf.connect(A).reveal(program("popcount"), salt("zzz"))).to.be.revertedWithCustomError(golf, "BadReveal");

    const tx = await golf.connect(A).reveal(program("popcount"), salt("a"));
    const rc = await tx.wait();
    const ev = rc.logs.map((l) => { try { return golf.interface.parseLog(l); } catch { return null; } }).find((e) => e && e.name === "Revealed");
    const cuA = ev.args.totalCu;
    console.log(`      popcount: ${cuA} CU em 4 inputs, gas do reveal: ${rc.gasUsed}`);
    expect(ev.args.isBest).to.equal(true);

    // seed = blockhash do último bloco de commit
    const r2 = await golf.currentRound();
    expect(r2.seed).to.equal((await ethers.provider.getBlock(Number(r.commitEnd))).hash);

    const txB = await golf.connect(B).reveal(slower(program("popcount")), salt("b"));
    const evB = (await txB.wait()).logs.map((l) => { try { return golf.interface.parseLog(l); } catch { return null; } }).find((e) => e && e.name === "Revealed");
    expect(evB.args.totalCu).to.equal(cuA + 4n); // 1 nop x 4 inputs
    expect(evB.args.isBest).to.equal(false);

    await expect(golf.connect(C).reveal(WRONG, salt("c"))).to.be.revertedWithCustomError(golf, "ProgramRejected");
    await expect(golf.connect(A).reveal(program("popcount"), salt("a"))).to.be.revertedWithCustomError(golf, "AlreadyRevealed");

    await expect(golf.finalize()).to.be.revertedWithCustomError(golf, "RoundNotOver");
    await mineTo(r.revealEnd + 1n);
    await expect(golf.connect(D).reveal(program("popcount"), salt("d"))).to.be.revertedWithCustomError(golf, "NotRevealWindow");

    await expect(golf.finalize()).to.emit(golf, "Finalized").withArgs(1n, A.address, cuA, REWARD, 0n);
    expect(await token.balanceOf(A.address)).to.equal(REWARD);
    expect(await golf.round()).to.equal(2n);
    expect((await golf.currentRound()).task).to.equal(2n); // 2 % 5 = isqrt
  });

  it("rodada 2: taxa de entrada (queima + prêmio) e leilão da próxima tarefa", async () => {
    expect(await golf.entryFee()).to.equal(FEE);
    // B não tem GOLF: não pode entrar
    await expect(commitAs(B, program("isqrt"), "b")).to.be.reverted;

    await token.connect(A).approve(golf, ethers.MaxUint256);
    const supply0 = await token.totalSupply();
    await commitAs(A, program("isqrt"), "a");
    expect(await token.totalSupply()).to.equal(supply0 - FEE / 2n); // 50% queimado
    expect((await golf.currentRound()).prize).to.equal(FEE / 2n);

    // A oferece 20 GOLF para a próxima tarefa ser fib (0)
    await golf.connect(A).bid(0, ethers.parseEther("20"));
    await expect(golf.connect(A).bid(0, ethers.parseEther("1"))).to.emit(golf, "BidPlaced"); // acumula: 21
    await expect(golf.connect(A).bid(3, 1n)).to.be.revertedWithCustomError(golf, "InvalidChoice"); // não pode trocar a escolha
    await expect(golf.connect(A).bid(1000, 1n)).to.be.revertedWithCustomError(golf, "InvalidChoice"); // bounty inexistente

    const r = await golf.currentRound();
    await mineTo(r.commitEnd + 1n);
    await golf.connect(A).reveal(program("isqrt"), salt("a"));
    await mineTo(r.revealEnd + 1n);

    const balBefore = await token.balanceOf(A.address);
    const supplyBefore = await token.totalSupply();
    await golf.finalize();
    // prêmio: 100 (mint) + 5 (taxa) ; oferta de 21 queimada
    expect(await token.balanceOf(A.address)).to.equal(balBefore + REWARD + FEE / 2n);
    expect(await token.totalSupply()).to.equal(supplyBefore + REWARD - ethers.parseEther("21"));
    expect((await golf.currentRound()).task).to.equal(0n); // fib, escolhido no leilão
    await expect(golf.connect(A).claimRefund(2)).to.be.revertedWithCustomError(golf, "NothingToRefund");
  });

  it("rodada 3: ofertas perdedoras são devolvidas; sem vencedor o prêmio acumula", async () => {
    await token.connect(A).transfer(B.address, ethers.parseEther("50"));
    await token.connect(B).approve(golf, ethers.MaxUint256);
    await golf.connect(A).bid(1, ethers.parseEther("10"));
    await expect(golf.connect(B).bid(3, ethers.parseEther("10"))).to.be.revertedWithCustomError(golf, "BidTooLow");
    await golf.connect(B).bid(3, ethers.parseEther("15"));

    await commitAs(A, program("fib"), "a"); // paga taxa, mas não revela
    const r = await golf.currentRound();
    await mineTo(r.revealEnd + 1n);
    await golf.finalize();

    expect(await golf.carry()).to.equal(FEE / 2n); // metade da taxa de A acumula
    expect((await golf.currentRound()).task).to.equal(3n); // max8, escolhido por B
    const bal = await token.balanceOf(A.address);
    await golf.connect(A).claimRefund(3);
    expect(await token.balanceOf(A.address)).to.equal(bal + ethers.parseEther("10"));
    await expect(golf.connect(B).claimRefund(3)).to.be.revertedWithCustomError(golf, "NothingToRefund"); // vencedor: queimada
  });

  it("rodada 4: empate em CU, vence o commit mais antigo; prêmio acumulado é pago", async () => {
    await commitAs(B, program("max8"), "b"); // B comita primeiro
    await commitAs(A, program("max8"), "a");
    const r = await golf.currentRound();
    await mineTo(r.commitEnd + 1n);
    await golf.connect(A).reveal(program("max8"), salt("a"));
    await golf.connect(B).reveal(program("max8"), salt("b"));
    expect((await golf.currentRound()).best).to.equal(B.address);
    await mineTo(r.revealEnd + 1n);
    const bal = await token.balanceOf(B.address);
    await golf.finalize();
    // 100 de mint + 2 taxas/2 desta rodada + 5 acumulados da rodada 3
    expect(await token.balanceOf(B.address)).to.equal(bal + REWARD + FEE + FEE / 2n);
    expect(await golf.carry()).to.equal(0n);
  });

  it("tarefa vinda de um bounty: correção pelo programa de referência do BountyBoard", async () => {
    // A posta um bounty (queima 5 GOLF, deposita 100 mUSD) com isqrt como referência
    await usd.mint(A.address, ethers.parseEther("100"));
    await usd.connect(A).approve(board, ethers.MaxUint256);
    await token.connect(A).approve(board, ethers.MaxUint256);
    await board.connect(A).post({
      rewardToken: usd, reward: ethers.parseEther("100"), refProgram: program("isqrt"), maxCu: 5000, inputLen: 8,
      edgeInputs: [], spec: "isqrt(u64)", commitBlocks: 100, revealBlocks: 200,
    });
    // leilão: rodada 6 usa o bounty 0
    await golf.connect(A).bid(1000, ethers.parseEther("1"));
    const r = await golf.currentRound();
    await mineTo(r.revealEnd + 1n);
    await golf.finalize();
    expect((await golf.currentRound()).task).to.equal(1000n);
    expect(await golf.taskName(1000)).to.equal("bounty");

    await commitAs(A, program("isqrt"), "a");
    await commitAs(B, WRONG, "b");
    const r6 = await golf.currentRound();
    await mineTo(r6.commitEnd + 1n);
    await expect(golf.connect(B).reveal(WRONG, salt("b"))).to.be.revertedWithCustomError(golf, "ProgramRejected");
    await expect(golf.connect(A).reveal(program("isqrt"), salt("a"))).to.emit(golf, "Revealed");
    const inputs = await golf.inputsFor(6);
    expect(inputs.length).to.equal(4);
    expect(ethers.dataLength(inputs[0])).to.equal(8);
  });
});
