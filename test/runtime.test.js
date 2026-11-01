const { expect } = require("chai");
const { ethers } = require("hardhat");
const { prog, u64le, hex, deployRuntime } = require("./helpers");

describe("SolanaRuntime (deploy/invoke de programas sBPF)", function () {
  let rt, owner, id;
  before(async () => {
    [owner] = await ethers.getSigners();
    rt = await deployRuntime();
    const salt = ethers.id("counter");
    id = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["address", "bytes32"], [owner.address, salt]));
    await expect(rt.deploy(hex(prog("counter")), 8, salt)).to.emit(rt, "ProgramDeployed");
  });

  it("guarda o bytecode (SSTORE2) e devolve igual", async () => {
    expect(await rt.programCode(id)).to.equal(hex(prog("counter")));
  });

  it("invoke persiste a conta de dados e emite logs", async () => {
    const tx = await rt.invoke(id, "0x", 10000);
    const rc = await tx.wait();
    console.log(`      gas do invoke (contador): ${rc.gasUsed}`);
    await expect(tx).to.emit(rt, "ProgramData").withArgs(id, [1n, 1n, 0n, 0n, 0n]);
    expect(await rt.accountData(id)).to.equal(hex(u64le(1)));

    await rt.invoke(id, hex(u64le(41)), 10000);
    expect(await rt.accountData(id)).to.equal(hex(u64le(42)));
  });

  it("programa que retorna erro reverte a tx e não altera o estado", async () => {
    await expect(rt.invoke(id, hex(u64le(2_000_000)), 10000))
      .to.be.revertedWithCustomError(rt, "ProgramFailed").withArgs(id, 42);
    expect(await rt.accountData(id)).to.equal(hex(u64le(42)));
  });

  it("simulate não grava nada", async () => {
    const res = await rt.simulate(id, hex(u64le(8)), owner.address, 10000);
    expect(res.r0).to.equal(0n);
    expect(await rt.accountData(id)).to.equal(hex(u64le(42)));
  });

  it("estouro do compute budget reverte", async () => {
    await expect(rt.invoke(id, "0x", 5)).to.be.revertedWithCustomError(rt, "ComputeBudgetExceeded");
  });
});
