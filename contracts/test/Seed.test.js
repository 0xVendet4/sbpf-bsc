const { expect } = require("chai");
const { ethers, network } = require("hardhat");
const { deployVM } = require("./helpers");
const { program, mineTo, salt, hashOf } = require("./golfHelpers");

const HISTORY = "0x0000F90827F1C53a10cb7A02335B175320002935";

// Janela de reveal maior que 256 blocos: a seed vem do contrato de histórico da EIP-2935.
describe("Seed além de 256 blocos (EIP-2935)", function () {
  let vm, token, history, A;

  before(async () => {
    [A] = await ethers.getSigners();
    vm = await deployVM();
    token = await (await ethers.getContractFactory("GolfToken")).deploy();
    const mock = await (await ethers.getContractFactory("MockBlockHistory")).deploy();
    await network.provider.send("hardhat_setCode", [HISTORY, await ethers.provider.getCode(mock)]);
    history = await ethers.getContractAt("MockBlockHistory", HISTORY);
  });

  async function newGolf(revealBlocks) {
    const g = await (await ethers.getContractFactory("SbpfGolf")).deploy(vm, token, 0, 5000, 1000, 10, revealBlocks);
    return g;
  }

  it("janela de reveal: até 8000 blocos", async () => {
    await expect(newGolf(8001)).to.be.reverted;
    await newGolf(8000);
  });

  it("reveal 300 blocos depois do commit usa o hash do histórico", async () => {
    const golf = await newGolf(1000);
    await token.setMinter(golf);
    const r = await golf.currentRound();
    const prog = program("popcount");
    await golf.commit(hashOf(A.address, 1n, prog, salt("a")));
    await mineTo(r.commitEnd + 300n);

    // histórico sem o hash: o reveal não pode usar seed zero
    await expect(golf.reveal(prog, salt("a"))).to.be.revertedWithCustomError(golf, "SeedUnavailable");

    const real = (await ethers.provider.getBlock(Number(r.commitEnd))).hash;
    await history.set(r.commitEnd, real);
    await expect(golf.reveal(prog, salt("a"))).to.emit(golf, "Revealed");
    expect((await golf.currentRound()).seed).to.equal(real);

    await mineTo(r.revealEnd + 1n);
    await expect(golf.finalize()).to.emit(golf, "Finalized");
    expect(await token.balanceOf(A.address)).to.equal(ethers.parseEther("100"));
  });

  it("dentro de 256 blocos continua usando blockhash direto", async () => {
    const golf = await newGolf(1000);
    const r = await golf.currentRound();
    const prog = program("popcount");
    await golf.commit(hashOf(A.address, 1n, prog, salt("b")));
    await mineTo(r.commitEnd + 5n);
    await golf.reveal(prog, salt("b"));
    expect((await golf.currentRound()).seed).to.equal((await ethers.provider.getBlock(Number(r.commitEnd))).hash);
  });
});
